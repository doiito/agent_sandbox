// Package templateoci transports signed guest artifacts without changing the
// root launcher's trust model. Registry transport is separate from admission.
package templateoci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

const (
	ManifestMediaType       = "application/vnd.oci.image.manifest.v1+json"
	IndexMediaType          = "application/vnd.oci.image.index.v1+json"
	ArtifactMediaType       = "application/vnd.osv-sandbox.template.v1"
	ConfigMediaType         = "application/vnd.osv-sandbox.template.config.v1+json"
	roleKey                 = "io.osv-sandbox.role"
	titleKey                = "org.opencontainers.image.title"
	metadataLimit     int64 = 1 << 20
)

var roles = []string{"manifest", "signature", "sbom", "kernel", "image"}
var mediaTypes = map[string]string{
	"manifest":  "application/vnd.osv-sandbox.artifact-manifest.v1+json",
	"signature": "application/vnd.osv-sandbox.artifact-signature.v1",
	"sbom":      "application/vnd.cyclonedx+json",
	"kernel":    "application/vnd.osv-sandbox.kernel.v1",
	"image":     "application/vnd.osv-sandbox.rootfs.v1",
}
var limits = map[string]int64{"manifest": metadataLimit, "signature": 4096, "sbom": 64 << 20, "kernel": 512 << 20, "image": 16 << 30}

type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	URLs        []string          `json:"urls,omitempty"`
	Data        string            `json:"data,omitempty"`
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}
type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}
type configuration struct {
	Protocol       string `json:"protocol"`
	Architecture   string `json:"architecture"`
	Backend        string `json:"backend"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// VerifyOptions are trusted operator inputs. No trust key or executable is
// selected from OCI content, and importing never switches a running service.
type VerifyOptions struct {
	Architecture    string
	Backend         string
	PublicKeyPath   string
	FirecrackerPath string
	JailerPath      string
	Entrypoints     []string
}

type artifactSet struct {
	metadata *sandbox.SignedArtifactManifest
	files    map[string]Descriptor
}

func digest(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }
func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
func canonical(name string) bool {
	return len(name) <= 256 && fs.ValidPath(name) && name != "." && !strings.ContainsAny(name, "\\\x00\r\n")
}
func descriptorOK(d Descriptor, media string, limit int64) bool {
	return d.MediaType == media && validDigest(d.Digest) && d.Size > 0 && d.Size <= limit && len(d.URLs) == 0 && d.Data == ""
}
func decode(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("expected exactly one JSON object")
	}
	return nil
}

// openRegular rejects links within the selected root, including leaf links.
// The operator-owned root itself may be addressed through a resolved alias.
func openRegular(root, name string) (*os.File, error) {
	if !canonical(name) {
		return nil, errors.New("non-canonical artifact path")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	current := realRoot
	parts := strings.Split(name, "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) || (i == len(parts)-1 && !info.Mode().IsRegular()) {
			return nil, errors.New("artifact path must contain only directories and a regular file")
		}
	}
	f, err := os.OpenFile(current, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("artifact is not a regular file")
	}
	return f, nil
}
func readBounded(root, name string, limit int64) ([]byte, error) {
	f, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > limit {
		return nil, errors.New("artifact exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("artifact exceeds size limit")
	}
	return data, nil
}
func blobName(d Descriptor) string { return "blobs/sha256/" + d.Digest[7:] }
func readBlob(root string, d Descriptor, media string, limit int64) ([]byte, error) {
	if !descriptorOK(d, media, limit) {
		return nil, errors.New("invalid OCI descriptor")
	}
	data, err := readBounded(root, blobName(d), d.Size)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != d.Size || digest(data) != d.Digest {
		return nil, errors.New("OCI blob size or digest mismatch")
	}
	return data, nil
}

func (o VerifyOptions) validate() error {
	if (o.Architecture != "amd64" && o.Architecture != "arm64") || (o.Backend != "firecracker-linux" && o.Backend != "firecracker-osv") || o.PublicKeyPath == "" || o.FirecrackerPath == "" || o.JailerPath == "" {
		return errors.New("explicit architecture, backend, external public key and trusted hypervisor/jailer paths are required")
	}
	return nil
}
func (o VerifyOptions) authenticate(data, signature []byte) (*sandbox.SignedArtifactManifest, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	key, err := os.Stat(o.PublicKeyPath)
	if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("trust key must be a regular file not writable by group or others")
	}
	public, err := readBounded(filepath.Dir(o.PublicKeyPath), filepath.Base(o.PublicKeyPath), 4096)
	if err != nil {
		return nil, err
	}
	m, err := sandbox.VerifySignedArtifactMetadata(data, signature, public, o.Backend, o.Entrypoints)
	if err != nil {
		return nil, err
	}
	if m.CodeRuntime != nil && m.CodeRuntime.Architecture != o.Architecture || m.GuestInference != nil && m.GuestInference.Architecture != o.Architecture {
		return nil, errors.New("signed runtime architecture mismatch")
	}
	if err := verifyBinaries(m, o); err != nil {
		return nil, err
	}
	return m, nil
}
func expectedFiles(m *sandbox.SignedArtifactManifest, data, signature []byte) (map[string]Descriptor, error) {
	names := map[string]string{"manifest": "manifest.json", "signature": "manifest.json.sig", "sbom": "sbom.cdx.json", "kernel": m.Kernel.Path, "image": m.Image.Path}
	digests := map[string]string{"manifest": digest(data), "signature": digest(signature), "sbom": "sha256:" + strings.ToLower(m.SBOMSHA256), "kernel": "sha256:" + strings.ToLower(m.Kernel.SHA256), "image": "sha256:" + strings.ToLower(m.Image.SHA256)}
	sizes := map[string]int64{"manifest": int64(len(data)), "signature": int64(len(signature)), "sbom": m.SBOMSize, "kernel": m.KernelSize, "image": m.ImageSize}
	seen := map[string]bool{}
	files := map[string]Descriptor{}
	for _, role := range roles {
		name := names[role]
		if !canonical(name) || seen[name] {
			return nil, errors.New("duplicate or non-canonical signed artifact path")
		}
		for previous := range seen {
			if strings.HasPrefix(name, previous+"/") || strings.HasPrefix(previous, name+"/") {
				return nil, errors.New("conflicting artifact paths")
			}
		}
		seen[name] = true
		d := Descriptor{MediaType: mediaTypes[role], Digest: digests[role], Size: sizes[role], Annotations: map[string]string{roleKey: role, titleKey: name}}
		if !descriptorOK(d, mediaTypes[role], limits[role]) {
			return nil, errors.New("signed artifact size or digest is unsupported")
		}
		files[role] = d
	}
	return files, nil
}

func loadSource(root string, o VerifyOptions) (artifactSet, error) {
	data, err := readBounded(root, "manifest.json", metadataLimit)
	if err != nil {
		return artifactSet{}, err
	}
	signature, err := readBounded(root, "manifest.json.sig", 4096)
	if err != nil {
		return artifactSet{}, err
	}
	m, err := o.authenticate(data, signature)
	if err != nil {
		return artifactSet{}, err
	}
	files, err := expectedFiles(m, data, signature)
	return artifactSet{m, files}, err
}

func loadLayout(root, expectedDigest string, o VerifyOptions) (artifactSet, Descriptor, error) {
	if !validDigest(expectedDigest) {
		return artifactSet{}, Descriptor{}, errors.New("explicit sha256 OCI manifest digest is required")
	}
	marker, err := readBounded(root, "oci-layout", 1024)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	var version struct {
		Version string `json:"imageLayoutVersion"`
	}
	if decode(marker, &version) != nil || version.Version != "1.0.0" {
		return artifactSet{}, Descriptor{}, errors.New("unsupported OCI layout version")
	}
	data, err := readBounded(root, "index.json", metadataLimit)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	var idx index
	if decode(data, &idx) != nil || idx.SchemaVersion != 2 || idx.MediaType != IndexMediaType || len(idx.Manifests) != 1 || idx.Manifests[0].Digest != expectedDigest {
		return artifactSet{}, Descriptor{}, errors.New("expected a single-template OCI index matching the external digest")
	}
	d := idx.Manifests[0]
	data, err = readBlob(root, d, ManifestMediaType, metadataLimit)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	envelope, files, err := parseEnvelope(data)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	configBytes, err := readBlob(root, envelope.Config, ConfigMediaType, 16<<10)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	var config configuration
	if decode(configBytes, &config) != nil || config.Protocol != "osv-sandbox-template-config/v1" || config.Architecture != o.Architecture || config.Backend != o.Backend {
		return artifactSet{}, Descriptor{}, errors.New("OCI template configuration does not match trusted selection")
	}
	data, err = readBlob(root, files["manifest"], mediaTypes["manifest"], metadataLimit)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	signature, err := readBlob(root, files["signature"], mediaTypes["signature"], 4096)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	m, err := o.authenticate(data, signature)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	expected, err := expectedFiles(m, data, signature)
	if err != nil {
		return artifactSet{}, Descriptor{}, err
	}
	if config.ManifestSHA256 != digest(data)[7:] {
		return artifactSet{}, Descriptor{}, errors.New("OCI configuration differs from signed manifest")
	}
	for _, role := range roles {
		got, want := files[role], expected[role]
		if got.Digest != want.Digest || got.Size != want.Size || got.Annotations[titleKey] != want.Annotations[titleKey] {
			return artifactSet{}, Descriptor{}, errors.New("OCI layer differs from authenticated artifact metadata")
		}
	}
	return artifactSet{m, files}, d, nil
}

// parseEnvelope applies the same bounded profile to disk and registry inputs.
func parseEnvelope(data []byte) (manifest, map[string]Descriptor, error) {
	var envelope manifest
	if int64(len(data)) > metadataLimit || decode(data, &envelope) != nil || envelope.SchemaVersion != 2 || envelope.MediaType != ManifestMediaType || envelope.ArtifactType != ArtifactMediaType || len(envelope.Layers) != len(roles) {
		return manifest{}, nil, errors.New("unsupported signed-template OCI manifest")
	}
	if !descriptorOK(envelope.Config, ConfigMediaType, 16<<10) {
		return manifest{}, nil, errors.New("invalid OCI config descriptor")
	}
	files := map[string]Descriptor{}
	for _, layer := range envelope.Layers {
		role := layer.Annotations[roleKey]
		if _, exists := files[role]; exists || mediaTypes[role] == "" || !descriptorOK(layer, mediaTypes[role], limits[role]) || !canonical(layer.Annotations[titleKey]) {
			return manifest{}, nil, errors.New("invalid, duplicate or oversized template layer")
		}
		files[role] = layer
	}
	return envelope, files, nil
}

func verifyBinaries(m *sandbox.SignedArtifactManifest, o VerifyOptions) error {
	for _, binary := range []struct{ path, sha string }{{o.FirecrackerPath, m.FirecrackerSHA256}, {o.JailerPath, m.JailerSHA256}} {
		f, err := openRegular(filepath.Dir(binary.path), filepath.Base(binary.path))
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil || info.Size() > 512<<20 || info.Mode().Perm()&0o111 == 0 {
			f.Close()
			return errors.New("invalid trusted executable")
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		if err != nil || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), binary.sha) {
			f.Close()
			return errors.New("signed hypervisor/jailer hash mismatch")
		}
		file, err := elf.NewFile(f)
		if err != nil {
			f.Close()
			return errors.New("trusted hypervisor/jailer must be an ELF executable")
		}
		machine, class, order, kind := file.Machine, file.Class, file.Data, file.Type
		file.Close()
		f.Close()
		if class != elf.ELFCLASS64 || order != elf.ELFDATA2LSB || (kind != elf.ET_EXEC && kind != elf.ET_DYN) || (o.Architecture == "amd64" && machine != elf.EM_X86_64) || (o.Architecture == "arm64" && machine != elf.EM_AARCH64) {
			return errors.New("trusted hypervisor/jailer ELF architecture mismatch")
		}
	}
	return nil
}

func verifyDirectory(root string, set artifactSet, o VerifyOptions) error {
	m := set.metadata
	config := sandbox.Config{ArtifactRoot: root, Backend: o.Backend, HypervisorPath: o.FirecrackerPath, Jailer: &sandbox.JailerConfig{Path: o.JailerPath}, Kernel: m.Kernel, Image: m.Image, AllowedEntrypoints: o.Entrypoints,
		ArtifactManifest: &sandbox.ArtifactManifestConfig{Path: "manifest.json", SignaturePath: "manifest.json.sig", SBOMPath: "sbom.cdx.json", PublicKeyPath: o.PublicKeyPath}}
	resolved, err := sandbox.ResolveArtifacts(root, config.Kernel, config.Image)
	if err != nil {
		return err
	}
	return sandbox.VerifyArtifactManifest(config, resolved)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func copyFile(ctx context.Context, sourceRoot, sourceName, destinationRoot, destinationName string, d Descriptor) error {
	input, err := openRegular(sourceRoot, sourceName)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || info.Size() != d.Size {
		return errors.New("artifact size mismatch before copy")
	}
	path := filepath.Join(destinationRoot, destinationName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	defer output.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, h), io.LimitReader(contextReader{ctx, input}, d.Size+1))
	if err != nil {
		return err
	}
	if n != d.Size || fmt.Sprintf("sha256:%x", h.Sum(nil)) != d.Digest {
		return errors.New("artifact copy size or digest mismatch")
	}
	return output.Sync()
}
func writeFile(root, name string, data []byte) (Descriptor, error) {
	d := Descriptor{Digest: digest(data), Size: int64(len(data))}
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return d, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return d, err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return d, err
}
func writeJSONBlob(root string, value any, media string) (Descriptor, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return Descriptor{}, err
	}
	d, err := writeFile(root, "blobs/sha256/"+digest(data)[7:], data)
	d.MediaType = media
	return d, err
}

func publish(ctx context.Context, destination string, operation func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, base := filepath.Dir(abs), filepath.Base(abs)
	if base == "." || base == string(filepath.Separator) {
		return errors.New("invalid publication destination")
	}
	lock, err := os.OpenFile(abs+".oci.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("unsafe template publication lock")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("template destination is busy")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	absent := func() error {
		_, err := os.Lstat(abs)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("template destination already exists")
	}
	if err := absent(); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, "."+base+"-incoming-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := operation(stage); err != nil {
		return err
	}
	// Data files have already been synced. Persist all new directory entries.
	err = filepath.WalkDir(stage, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
	if err != nil {
		return err
	}
	if err := absent(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := os.Rename(stage, abs); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("template published but parent open failed: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("template published but parent sync failed: %w", err)
	}
	return nil
}

// Export writes one reproducible OCI image layout from authenticated artifacts.
func Export(ctx context.Context, source, destination string, o VerifyOptions) (Descriptor, error) {
	set, err := loadSource(source, o)
	if err != nil {
		return Descriptor{}, err
	}
	var result Descriptor
	err = publish(ctx, destination, func(stage string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		view := filepath.Join(stage, ".verification")
		if err := os.Mkdir(view, 0o700); err != nil {
			return err
		}
		envelope := manifest{SchemaVersion: 2, MediaType: ManifestMediaType, ArtifactType: ArtifactMediaType}
		for _, role := range roles {
			d := set.files[role]
			// Distinct roles may legitimately contain identical bytes.
			name := blobName(d)
			if _, err := os.Lstat(filepath.Join(stage, name)); os.IsNotExist(err) {
				if err := copyFile(ctx, source, d.Annotations[titleKey], stage, name, d); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			target := filepath.Join(view, d.Annotations[titleKey])
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Links refer only to our copied private blobs, never source assets.
			if err := os.Link(filepath.Join(stage, name), target); err != nil {
				return err
			}
			envelope.Layers = append(envelope.Layers, d)
		}
		if err := verifyDirectory(view, set, o); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.RemoveAll(view); err != nil {
			return err
		}
		envelope.Config, err = writeJSONBlob(stage, configuration{"osv-sandbox-template-config/v1", o.Architecture, o.Backend, set.files["manifest"].Digest[7:]}, ConfigMediaType)
		if err != nil {
			return err
		}
		result, err = writeJSONBlob(stage, envelope, ManifestMediaType)
		if err != nil {
			return err
		}
		marker, _ := json.Marshal(map[string]string{"imageLayoutVersion": "1.0.0"})
		if _, err := writeFile(stage, "oci-layout", marker); err != nil {
			return err
		}
		data, err := json.Marshal(index{2, IndexMediaType, []Descriptor{result}})
		if err != nil {
			return err
		}
		_, err = writeFile(stage, "index.json", data)
		return err
	})
	if err != nil {
		return Descriptor{}, err
	}
	return result, nil
}

// Import authenticates the pinned layout and atomically publishes guest data.
// An existing destination is never updated, including during concurrent import.
func Import(ctx context.Context, source, expectedDigest, destination string, o VerifyOptions) (Descriptor, error) {
	set, result, err := loadLayout(source, expectedDigest, o)
	if err != nil {
		return Descriptor{}, err
	}
	err = publish(ctx, destination, func(stage string) error {
		for _, role := range roles {
			d := set.files[role]
			if err := copyFile(ctx, source, blobName(d), stage, d.Annotations[titleKey], d); err != nil {
				return err
			}
		}
		if err := verifyDirectory(stage, set, o); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return Descriptor{}, err
	}
	return result, nil
}
