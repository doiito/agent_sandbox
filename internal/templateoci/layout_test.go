package templateoci

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type fixture struct {
	root     string
	options  VerifyOptions
	private  ed25519.PrivateKey
	metadata sandbox.SignedArtifactManifest
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Malicious-registry fixtures intentionally rewrite our exported read-only
	// blobs; this must also work when CI runs without root.
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "external.public")
	mustWrite(t, key, []byte(base64.StdEncoding.EncodeToString(public)))
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableSHA := fileDigest(t, binary)
	kernel, image, sbom := []byte("kernel bytes"), bytes.Repeat([]byte("guest bytes\x00"), 4096), []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)
	mustWrite(t, filepath.Join(source, "boot/kernel"), kernel)
	mustWrite(t, filepath.Join(source, "disk/rootfs.raw"), image)
	mustWrite(t, filepath.Join(source, "sbom.cdx.json"), sbom)
	m := sandbox.SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v1", CreatedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Kernel: sandbox.Artifact{Path: "boot/kernel", SHA256: digest(kernel)[7:]}, Image: sandbox.Artifact{Path: "disk/rootfs.raw", SHA256: digest(image)[7:], Format: "raw"},
		KernelSize: int64(len(kernel)), ImageSize: int64(len(image)), SBOMSize: int64(len(sbom)), SBOMSHA256: digest(sbom)[7:], FirecrackerSHA256: executableSHA, JailerSHA256: executableSHA}
	f := fixture{source, VerifyOptions{Architecture: runtime.GOARCH, Backend: "firecracker-linux", PublicKeyPath: key, FirecrackerPath: binary, JailerPath: binary}, private, m}
	f.sign(t)
	return f
}
func (f fixture) sign(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.metadata)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(f.root, "manifest.json"), data)
	mustWrite(t, filepath.Join(f.root, "manifest.json.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, data))))
}
func exportFixture(t *testing.T, f fixture) (string, Descriptor) {
	t.Helper()
	layout := filepath.Join(t.TempDir(), "layout")
	d, err := Export(context.Background(), f.root, layout, f.options)
	if err != nil {
		t.Fatal(err)
	}
	return layout, d
}
func assertNotPublished(t *testing.T, destination string) {
	t.Helper()
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("unexpected published path: %v", err)
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+"-incoming-*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("leaked staging directories: %v %v", stages, err)
	}
}
func rewriteEnvelope(t *testing.T, layout string, current Descriptor, mutate func(*manifest)) Descriptor {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(mustRead(t, filepath.Join(layout, blobName(current))), &m); err != nil {
		t.Fatal(err)
	}
	mutate(&m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	d := Descriptor{MediaType: ManifestMediaType, Digest: digest(data), Size: int64(len(data))}
	mustWrite(t, filepath.Join(layout, blobName(d)), data)
	idx, _ := json.Marshal(index{2, IndexMediaType, []Descriptor{d}})
	mustWrite(t, filepath.Join(layout, "index.json"), idx)
	return d
}
func replaceBlob(t *testing.T, layout string, d *Descriptor, data []byte) {
	t.Helper()
	d.Digest, d.Size = digest(data), int64(len(data))
	mustWrite(t, filepath.Join(layout, blobName(*d)), data)
}
func mutateSigned(t *testing.T, layout string, d Descriptor, f fixture, change func(*sandbox.SignedArtifactManifest), resign bool) Descriptor {
	t.Helper()
	return rewriteEnvelope(t, layout, d, func(envelope *manifest) {
		var position int
		for i, layer := range envelope.Layers {
			if layer.Annotations[roleKey] == "manifest" {
				position = i
			}
		}
		var m sandbox.SignedArtifactManifest
		if err := json.Unmarshal(mustRead(t, filepath.Join(layout, blobName(envelope.Layers[position]))), &m); err != nil {
			t.Fatal(err)
		}
		change(&m)
		data, _ := json.Marshal(m)
		replaceBlob(t, layout, &envelope.Layers[position], data)
		if resign {
			for i := range envelope.Layers {
				if envelope.Layers[i].Annotations[roleKey] == "signature" {
					replaceBlob(t, layout, &envelope.Layers[i], []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, data))))
				}
			}
		}
		var config configuration
		if err := json.Unmarshal(mustRead(t, filepath.Join(layout, blobName(envelope.Config))), &config); err != nil {
			t.Fatal(err)
		}
		config.ManifestSHA256 = digest(data)[7:]
		raw, _ := json.Marshal(config)
		replaceBlob(t, layout, &envelope.Config, raw)
	})
}

func TestRoundTripPreservesSignedArtifactBytes(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	second, again := exportFixture(t, f)
	if d.Digest != again.Digest || !bytes.Equal(mustRead(t, filepath.Join(layout, "index.json")), mustRead(t, filepath.Join(second, "index.json"))) {
		t.Fatal("same signed bytes must produce the same OCI digest")
	}
	destination := filepath.Join(t.TempDir(), "imported")
	got, err := Import(context.Background(), layout, d.Digest, destination, f.options)
	if err != nil || got.Digest != d.Digest {
		t.Fatalf("import: %+v %v", got, err)
	}
	for _, name := range []string{"manifest.json", "manifest.json.sig", "sbom.cdx.json", f.metadata.Kernel.Path, f.metadata.Image.Path} {
		if !bytes.Equal(mustRead(t, filepath.Join(f.root, name)), mustRead(t, filepath.Join(destination, name))) {
			t.Fatalf("changed signed artifact %s", name)
		}
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil || info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("imported artifact must be read-only: %s %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(layout, ".verification")); !os.IsNotExist(err) {
		t.Fatal("private verification view retained")
	}
}

func TestImportRejectsUntrustedLayoutsWithoutPublishing(t *testing.T) {
	tests := []struct {
		name     string
		change   func(*testing.T, string, *Descriptor, *fixture)
		contains string
	}{
		{"unpinned-digest", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			d.Digest = "sha256:" + strings.Repeat("a", 64)
		}, "external digest"},
		{"wrong-key", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			other := newFixture(t)
			f.options.PublicKeyPath = other.options.PublicKeyPath
		}, "signature"},
		{"wrong-binary", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			p := filepath.Join(t.TempDir(), "binary")
			mustWrite(t, p, []byte("other executable"))
			os.Chmod(p, 0o700)
			f.options.FirecrackerPath = p
		}, "hash"},
		{"wrong-architecture", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			other := "arm64"
			if runtime.GOARCH == other {
				other = "amd64"
			}
			f.options.Architecture = other
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) {
				var c configuration
				json.Unmarshal(mustRead(t, filepath.Join(l, blobName(m.Config))), &c)
				c.Architecture = other
				raw, _ := json.Marshal(c)
				replaceBlob(t, l, &m.Config, raw)
			})
		}, "ELF architecture"},
		{"traversal", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers[4].Annotations[titleKey] = "../escape" })
		}, "layer"},
		{"duplicate-role", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers[4] = m.Layers[3] })
		}, "layer"},
		{"extra-layer", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers = append(m.Layers, m.Layers[0]) })
		}, "manifest"},
		{"wrong-artifact-type", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.ArtifactType = "application/example" })
		}, "manifest"},
		{"descriptor-size", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers[4].Size++ })
		}, "authenticated"},
		{"descriptor-digest", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers[4].Digest = "sha256:" + strings.Repeat("b", 64) })
		}, "authenticated"},
		{"external-url", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Layers[4].URLs = []string{"https://untrusted.example/blob"} })
		}, "layer"},
		{"inline-data", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = rewriteEnvelope(t, l, *d, func(m *manifest) { m.Config.Data = "e30=" })
		}, "descriptor"},
		{"expired", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) { m.ExpiresAt = time.Now().Add(-time.Second) }, true)
		}, "expired"},
		{"future", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) {
				m.CreatedAt = time.Now().Add(time.Hour)
				m.ExpiresAt = time.Now().Add(2 * time.Hour)
			}, true)
		}, "validity"},
		{"invalid-signature", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) { m.ExpiresAt = m.ExpiresAt.Add(time.Hour) }, false)
		}, "signature"},
		{"signed-traversal", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) { m.Image.Path = "../outside" }, true)
		}, "path"},
		{"signed-path-collision", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) { m.Image.Path = "boot/kernel/child" }, true)
		}, "paths"},
		{"signed-oversized-image", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			*d = mutateSigned(t, l, *d, *f, func(m *sandbox.SignedArtifactManifest) { m.ImageSize = 17 << 30 }, true)
		}, "size"},
		{"missing-image", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			if err := os.Remove(filepath.Join(l, "blobs/sha256/"+f.metadata.Image.SHA256)); err != nil {
				t.Fatal(err)
			}
		}, "no such file"},
		{"tampered-image", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			p := filepath.Join(l, "blobs/sha256/"+f.metadata.Image.SHA256)
			data := mustRead(t, p)
			data[0] ^= 1
			mustWrite(t, p, data)
		}, "digest"},
		{"oversized-image-bytes", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			p := filepath.Join(l, "blobs/sha256/"+f.metadata.Image.SHA256)
			mustWrite(t, p, append(mustRead(t, p), 0))
		}, "size"},
		{"truncated-image", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			p := filepath.Join(l, "blobs/sha256/"+f.metadata.Image.SHA256)
			data := mustRead(t, p)
			mustWrite(t, p, data[:len(data)-1])
		}, "size"},
		{"symlink-image", func(t *testing.T, l string, d *Descriptor, f *fixture) {
			p := filepath.Join(l, "blobs/sha256/"+f.metadata.Image.SHA256)
			os.Remove(p)
			if err := os.Symlink(filepath.Join(f.root, f.metadata.Image.Path), p); err != nil {
				t.Fatal(err)
			}
		}, "regular file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			layout, d := exportFixture(t, f)
			test.change(t, layout, &d, &f)
			destination := filepath.Join(t.TempDir(), "imported")
			_, err := Import(context.Background(), layout, d.Digest, destination, f.options)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("expected %q rejection, got %v", test.contains, err)
			}
			assertNotPublished(t, destination)
		})
	}
}

func TestImportNeverOverwritesExistingDestination(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	destination := filepath.Join(t.TempDir(), "existing")
	sentinel := []byte("existing operator data")
	mustWrite(t, filepath.Join(destination, "sentinel"), sentinel)
	if _, err := Import(context.Background(), layout, d.Digest, destination, f.options); err == nil {
		t.Fatal("existing destination replaced")
	}
	if !bytes.Equal(mustRead(t, filepath.Join(destination, "sentinel")), sentinel) {
		t.Fatal("existing data changed")
	}
}

func TestConcurrentImportsPublishExactlyOnce(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	destination := filepath.Join(t.TempDir(), "shared")
	var group sync.WaitGroup
	results := make(chan error, 4)
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := Import(context.Background(), layout, d.Digest, destination, f.options)
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !strings.Contains(err.Error(), "busy") && !strings.Contains(err.Error(), "already exists") {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("published %d times", success)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(destination, f.metadata.Image.Path)), mustRead(t, filepath.Join(f.root, f.metadata.Image.Path))) {
		t.Fatal("wrong winning image")
	}
}

func TestExportRejectsChangedSourceAndCleansStage(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.root, f.metadata.Image.Path), []byte("changed source"))
	destination := filepath.Join(t.TempDir(), "layout")
	if _, err := Export(context.Background(), f.root, destination, f.options); err == nil {
		t.Fatal("changed source accepted")
	}
	assertNotPublished(t, destination)
}

func TestImportCancellationDuringImageCopy(t *testing.T) {
	f := newFixture(t)
	image := filepath.Join(f.root, f.metadata.Image.Path)
	handle, err := os.OpenFile(image, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(128 << 20); err != nil {
		handle.Close()
		t.Fatal(err)
	}
	handle.Close()
	f.metadata.ImageSize = 128 << 20
	f.metadata.Image.SHA256 = fileDigest(t, image)
	f.sign(t)
	layout, d := exportFixture(t, f)
	parent := t.TempDir()
	destination := filepath.Join(parent, "cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan bool, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				cancel()
				observed <- false
				return
			case <-ticker.C:
				paths, _ := filepath.Glob(filepath.Join(parent, ".cancelled-incoming-*", "disk", "rootfs.raw"))
				if len(paths) > 0 {
					cancel()
					observed <- true
					return
				}
			}
		}
	}()
	_, err = Import(ctx, layout, d.Digest, destination, f.options)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation during copy, got %v", err)
	}
	if !<-observed {
		t.Fatal("did not observe image-copy phase")
	}
	assertNotPublished(t, destination)
}

func TestImportRejectsInvalidSignatureBeforeOpeningImage(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	d = mutateSigned(t, layout, d, f, func(m *sandbox.SignedArtifactManifest) { m.ExpiresAt = m.ExpiresAt.Add(time.Hour) }, false)
	if err := os.Remove(filepath.Join(layout, "blobs/sha256/"+f.metadata.Image.SHA256)); err != nil {
		t.Fatal(err)
	}
	_, err := Import(context.Background(), layout, d.Digest, filepath.Join(t.TempDir(), "imported"), f.options)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("image accessed before signature rejection: %v", err)
	}
}
