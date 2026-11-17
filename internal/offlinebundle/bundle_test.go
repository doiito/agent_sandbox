package offlinebundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(t.TempDir(), "fixture-static")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", exe, "./cmd/osv-offline-release")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build static fixture: %v: %s", err, output)
	}
	for _, name := range required {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(name, "bin/") {
			if err := os.Link(exe, p); err != nil {
				input, readErr := os.ReadFile(exe)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err := os.WriteFile(p, input, 0o755); err != nil {
					t.Fatal(err)
				}
			}
		} else if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return root, pub, priv
}

func TestPackVerifyInstallAndTamper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux install")
	}
	source, pub, priv := fixture(t)
	if err := os.Link(filepath.Join(source, "bin/osv-sandboxd"), filepath.Join(source, "bin/osv-sandbox-mcp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(source, "bin/osv-sandboxd"), filepath.Join(source, "bin/osv-sandbox-egress")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(source, "bin/osv-sandboxd"), filepath.Join(source, "bin/osv-template-oci")); err != nil {
		t.Fatal(err)
	}
	contracts := []string{"docs/contracts/openapi.json", "docs/API-CONTRACTS.zh-CN.md",
		"docs/contracts/api/control/v1/control.proto", "docs/contracts/control.descriptor.pb",
		"docs/GRPC.zh-CN.md", "docs/GO-MODULE-LICENSES.txt"}
	for _, name := range append(contracts, "examples/auth.production.json", "examples/config.production.json",
		"templates/python-science/template.json", "templates/python-science/artifacts/kernel.elf",
		"templates/python-science/artifacts/rootfs.raw", "templates/python-science/artifacts/manifest.json",
		"templates/python-science/artifacts/manifest.json.sig", "templates/python-science/artifacts/sbom.cdx.json",
		"templates/python-science/docs/runtime-licenses.tar.gz",
		"templates/python-science/docs/readonly-input-profile.json",
		"templates/linux-code/template.json", "templates/linux-code/artifacts/kernel", "templates/linux-code/artifacts/rootfs.ext4",
		"templates/linux-code/artifacts/manifest.json", "templates/linux-code/artifacts/manifest.json.sig", "templates/linux-code/artifacts/sbom.cdx.json",
		"templates/linux-code/docs/runtime-inventory.json", "templates/linux-code/docs/image-inventory.json", "templates/linux-code/docs/code-runtime.json",
		"templates/linux-code/docs/source-lock.json", "templates/linux-code/docs/runtime-license-paths.json",
		"examples/mcp.production.json", "docs/MCP.zh-CN.md", "docs/PREVIEW.zh-CN.md", "docs/OCI-TEMPLATES.zh-CN.md", "docs/OTLP.zh-CN.md",
		"examples/egress.production.json", "docs/EGRESS.zh-CN.md", "systemd/osv-sandbox-egress.service",
		"examples/egress-public-roots.crt", "docs/egress-roots-LICENSE.txt", "docs/egress-roots-source-lock.json",
		"docs/bash-LICENSE.txt", "docs/bash-source-lock.json", "docs/bash-build-provenance.json", "docs/bash-5.3.tar.gz",
		"docs/security-profile.json", "docs/vulnerability-report.json",
		"docs/mimalloc-policy.json", "docs/musl-guest-build-provenance.json", "docs/mimalloc-compiler-transcript.txt",
		"docs/mimalloc-rust-LICENSE.txt", "docs/mimalloc-sys-LICENSE.txt", "docs/mimalloc-c-LICENSE.txt") {
		p := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if allowedName("examples/token.production.json") || allowedName("examples/private.key") {
		t.Fatal("unreviewed example entered the release allowlist")
	}
	for _, name := range []string{"templates/../private.key", "templates/python-science/bin/hook", "templates/python-science/artifacts/private.key", "templates/python-science/artifacts/token.pem"} {
		if allowedName(name) {
			t.Fatal("credential or host hook admitted as template data", name)
		}
	}
	for _, name := range []string{"docs/contracts/private.key", "docs/contracts/other.json", "docs/contracts/openapi.json/private.key",
		"docs/contracts/api/control/v1/private.key", "docs/contracts/api/control/v1/control.proto/private.key", "docs/contracts/../private.key"} {
		if allowedName(name) {
			t.Fatal("contract document exception broadened the release allowlist", name)
		}
	}
	sdkPath := filepath.Join(source, "sdk", "python", "osv_sandbox_client.py")
	if err := os.MkdirAll(filepath.Dir(sdkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sdkPath, []byte("# offline Python client fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(source, "sdk", "node", "index.js")
	if err := os.MkdirAll(filepath.Dir(nodePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodePath, []byte("// offline Node client fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	validUntil := time.Now().Add(24 * time.Hour)
	for _, out := range []*bytes.Buffer{&first, &second} {
		if err := Pack(source, out, "v1", runtime.GOARCH, "abc123", validUntil, priv); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("nondeterministic archive")
	}
	if _, err := Verify(bytes.NewReader(first.Bytes()), pub, runtime.GOARCH, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bytes.NewReader(append(first.Bytes(), 'x')), pub, runtime.GOARCH, ""); err == nil {
		t.Fatal("nonzero trailing data accepted")
	}
	if err := Pack(source, &bytes.Buffer{}, "v2", runtime.GOARCH, "abc123", time.Now().Add(-time.Hour), priv); err == nil {
		t.Fatal("expired release accepted")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bytes.NewReader(first.Bytes()), other, runtime.GOARCH, ""); err == nil {
		t.Fatal("wrong key accepted")
	}
	wrongArch := "arm64"
	if runtime.GOARCH == "arm64" {
		wrongArch = "amd64"
	}
	if _, err := Verify(bytes.NewReader(first.Bytes()), pub, wrongArch, ""); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	archive := filepath.Join(t.TempDir(), "release.tar")
	if err := os.WriteFile(archive, first.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "versions")
	oldUmask := syscall.Umask(0o077)
	installed, err := Install(archive, pub, root)
	syscall.Umask(oldUmask)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(installed, "docs/PREVIEW.zh-CN.md")); err != nil || string(data) != "{}\n" {
		t.Fatal("signed preview manual changed at install", err)
	}
	for _, name := range contracts {
		data, err := os.ReadFile(filepath.Join(installed, name))
		if err != nil || string(data) != "{}\n" {
			t.Fatal("signed API contract changed at install", name, err)
		}
		if info, err := os.Stat(filepath.Join(installed, name)); err != nil || info.Mode().Perm() != 0o444 {
			t.Fatal("installed API contract is not immutable", name, err)
		}
		// Mutate only this document's payload, leaving the signed manifest and
		// all other members intact. Every contract byte must be hash-bound.
		mutated := append([]byte(nil), first.Bytes()...)
		input := bytes.NewReader(mutated)
		reader := tar.NewReader(input)
		found := false
		for {
			header, err := reader.Next()
			if err != nil {
				break
			}
			if header.Name == name {
				if header.Size == 0 {
					t.Fatal("empty document fixture")
				}
				mutated[len(mutated)-input.Len()] ^= 1
				found = true
				break
			}
		}
		if !found {
			t.Fatal("document absent from signed archive", name)
		}
		if _, err := Verify(bytes.NewReader(mutated), pub, runtime.GOARCH, ""); err == nil {
			t.Fatal("mutated API document accepted", name)
		}
	}
	for _, name := range []string{"templates/python-science/template.json", "templates/python-science/artifacts/rootfs.raw", "templates/python-science/docs/runtime-licenses.tar.gz", "templates/python-science/docs/readonly-input-profile.json",
		"templates/linux-code/template.json", "templates/linux-code/artifacts/rootfs.ext4", "templates/linux-code/docs/image-inventory.json", "templates/linux-code/docs/code-runtime.json"} {
		data, err := os.ReadFile(filepath.Join(installed, name))
		if err != nil || string(data) != "{}\n" {
			t.Fatal("signed template payload changed at install", name, err)
		}
		info, err := os.Stat(filepath.Join(installed, name))
		if err != nil || info.Mode().Perm() != 0o444 {
			t.Fatal("template data not immutable", name, err)
		}
	}
	if info, err := os.Stat(installed); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed release must be traversable by the unprivileged API: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(installed, "bin/osv-sandboxd")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bin", "artifacts", "config", "systemd", "sdk", "sdk/python", "sdk/node", "docs", "docs/contracts"} {
		info, err := os.Stat(filepath.Join(installed, name))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("installed %s not traversable after restrictive umask: %v %v", name, info, err)
		}
	}
	// Every authenticated nested parent must be traversable, including template
	// paths which were previously absent from the installer's fixed list.
	manifest, err := Verify(bytes.NewReader(first.Bytes()), pub, runtime.GOARCH, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Files {
		for parent := filepath.Dir(item.Path); parent != "."; parent = filepath.Dir(parent) {
			info, err := os.Stat(filepath.Join(installed, parent))
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
				t.Fatal("verified payload parent is not traversable after restrictive umask", parent, err)
			}
		}
	}
	if info, err := os.Stat(filepath.Join(installed, "bin/osv-sandboxd")); err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("installed executable mode mismatch: %v %v", info, err)
	}
	installedSDK := filepath.Join(installed, "sdk", "python", "osv_sandbox_client.py")
	if data, err := os.ReadFile(installedSDK); err != nil || string(data) != "# offline Python client fixture\n" {
		t.Fatalf("signed SDK payload was not installed intact: %v %q", err, data)
	}
	if data, err := os.ReadFile(filepath.Join(installed, "sdk/node/index.js")); err != nil || string(data) != "// offline Node client fixture\n" {
		t.Fatalf("signed Node SDK payload was not installed intact: %v %q", err, data)
	}
	if _, err := Install(archive, pub, root); err == nil {
		t.Fatal("existing version overwritten")
	}

	mutated := append([]byte(nil), first.Bytes()...)
	needle := []byte("artifacts/rootfs.ext4")
	index := bytes.LastIndex(mutated, needle)
	if index < 0 {
		t.Fatal("fixture payload absent")
	}
	mutated[index] ^= 1
	if _, err := Verify(bytes.NewReader(mutated), pub, runtime.GOARCH, ""); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if err := os.WriteFile(archive, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(archive, pub, root); err == nil {
		t.Fatal("tampered install accepted")
	}
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("failed install left version data")
	}
}

func TestVerifyRejectsSignedTraversal(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	m := Manifest{Format: 1, Version: "v1", Arch: runtime.GOARCH, Commit: "abc123", ValidUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	for _, name := range required {
		m.Files = append(m.Files, File{Path: name, Size: 0, Mode: 0o444, SHA256: hex.EncodeToString(empty[:])})
	}
	m.Files[0].Path = "../escape"
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, manifest))
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"manifest.sig", []byte(sig)}} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bytes.NewReader(archive.Bytes()), pub, runtime.GOARCH, ""); err == nil {
		t.Fatal("signed traversal accepted")
	}
}

func TestPackRejectsSymlinkAndSecretPath(t *testing.T) {
	source, _, priv := fixture(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(source, "docs", "link")); err != nil {
		if err := os.MkdirAll(filepath.Join(source, "docs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", filepath.Join(source, "docs", "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := Pack(source, &bytes.Buffer{}, "v1", runtime.GOARCH, "abc123", time.Now().Add(24*time.Hour), priv); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(filepath.Join(source, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config", "private.key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Pack(source, &bytes.Buffer{}, "v1", runtime.GOARCH, "abc123", time.Now().Add(24*time.Hour), priv); err == nil {
		t.Fatal("secret path accepted")
	}
}
