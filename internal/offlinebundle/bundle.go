package offlinebundle

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

const maxFileSize int64 = 2 << 30
const maxBundleSize int64 = 4 << 30
const maxFiles = 128

var required = []string{
	"bin/osv-sandboxd", "bin/osv-sandbox-launcher", "bin/firecracker", "bin/jailer",
	"bin/osv-offline-release",
	"bin/mkfs.ext4", "artifacts/kernel", "artifacts/rootfs.ext4",
	"systemd/osv-sandboxd.service", "systemd/osv-sandbox-launcher.service",
	"config/config.production.json.template", "artifacts/manifest.json",
	"artifacts/manifest.json.sig", "artifacts/sbom.cdx.json",
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format     int    `json:"format"`
	Version    string `json:"version"`
	Arch       string `json:"arch"`
	Commit     string `json:"commit"`
	ValidUntil string `json:"valid_until"`
	Files      []File `json:"files"`
}

func validArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

func validVersion(version string) bool {
	if version == "" || len(version) > 80 {
		return false
	}
	for i, ch := range version {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		if i > 0 && (ch == '.' || ch == '_' || ch == '-') {
			continue
		}
		return false
	}
	return true
}

func validName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name ||
		strings.HasPrefix(name, "../") || strings.Contains(name, "//") || strings.Contains(name, ":") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	return true
}

func allowedName(name string) bool {
	if !validName(name) {
		return false
	}
	if allowedTemplateFile(name) {
		return true
	}
	for _, item := range required {
		if name == item {
			return true
		}
	}
	if name == "docs/PRODUCTION.zh-CN.md" || name == "docs/PREVIEW.zh-CN.md" || name == "docs/OTLP.zh-CN.md" {
		return true
	}
	switch name {
	case "docs/contracts/openapi.json", "docs/API-CONTRACTS.zh-CN.md":
		return true
	case "docs/contracts/api/control/v1/control.proto", "docs/contracts/control.descriptor.pb",
		"docs/GRPC.zh-CN.md", "docs/GO-MODULE-LICENSES.txt":
		return true
	case "bin/osv-template-oci", "docs/OCI-TEMPLATES.zh-CN.md":
		return true
	case "examples/egress-public-roots.crt", "docs/egress-roots-LICENSE.txt", "docs/egress-roots-source-lock.json":
		return true
	case "bin/osv-sandbox-egress", "systemd/osv-sandbox-egress.service", "docs/EGRESS.zh-CN.md", "examples/egress.production.json":
		return true
	case "bin/osv-sandbox-mcp", "docs/MCP.zh-CN.md", "examples/mcp.production.json":
		return true
	case "docs/bash-LICENSE.txt", "docs/bash-source-lock.json", "docs/bash-build-provenance.json", "docs/bash-5.3.tar.gz":
		return true
	case "docs/security-profile.json", "docs/vulnerability-report.json":
		return true
	case "docs/mimalloc-policy.json", "docs/musl-guest-build-provenance.json", "docs/mimalloc-compiler-transcript.txt",
		"docs/mimalloc-rust-LICENSE.txt", "docs/mimalloc-sys-LICENSE.txt", "docs/mimalloc-c-LICENSE.txt":
		return true
	}
	if name == "examples/auth.production.json" || name == "examples/config.production.json" {
		return true
	}
	if name == "docs/PYTHON-SDK.md" || name == "sdk/python/osv_sandbox_client.py" {
		return true
	}
	if name == "docs/NODE-SDK.md" || name == "sdk/node/index.js" ||
		name == "sdk/node/index.d.ts" || name == "sdk/node/package.json" {
		return true
	}
	if strings.HasPrefix(name, "lib/") {
		base := strings.ToLower(path.Base(name))
		return !strings.Contains(base, "secret") && !strings.Contains(base, "private") && !strings.Contains(base, "token") && !strings.HasSuffix(base, ".key") && !strings.HasSuffix(base, ".pem")
	}
	return false
}

func validateManifest(m Manifest) error {
	if m.Format != 1 || !validArch(m.Arch) || !validVersion(m.Version) ||
		len(m.Commit) == 0 || len(m.Commit) > 128 || len(m.Files) < len(required) || len(m.Files) > maxFiles {
		return errors.New("invalid release manifest metadata")
	}
	expires, err := time.Parse(time.RFC3339, m.ValidUntil)
	if err != nil || !expires.After(time.Now().UTC()) {
		return errors.New("release signature has expired")
	}
	seen := make(map[string]bool)
	var total int64
	last := ""
	for _, f := range m.Files {
		if !allowedName(f.Path) || f.Path <= last || f.Size < 0 || f.Size > maxFileSize ||
			(f.Mode != 0o444 && f.Mode != 0o555) || len(f.SHA256) != 64 {
			return fmt.Errorf("invalid release file: %q", f.Path)
		}
		if _, err := hex.DecodeString(f.SHA256); err != nil {
			return fmt.Errorf("invalid hash for %s: %w", f.Path, err)
		}
		last = f.Path
		seen[f.Path] = true
		total += f.Size
		if total > maxBundleSize {
			return errors.New("release payload exceeds size limit")
		}
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("missing required release file %s", name)
		}
	}
	return nil
}

// Pack writes a deterministic, uncompressed tar. The signing key is never copied into the bundle.
func Pack(source string, out io.Writer, version, arch, commit string, validUntil time.Time, key ed25519.PrivateKey) error {
	return pack(source, out, version, arch, commit, validUntil, key, nil)
}

// PackWithReference compares the computed payload with reference before writing
// an archive header or signature. The existing write-time hash checks also apply.
// The caller must authenticate reference.
// Outer version, commit, expiry, and signing key may change; payload bytes may not.
func PackWithReference(source string, out io.Writer, version, arch, commit string, validUntil time.Time, key ed25519.PrivateKey, reference Manifest) error {
	if err := validateManifest(reference); err != nil {
		return fmt.Errorf("invalid reference manifest: %w", err)
	}
	if reference.Arch != arch {
		return errors.New("reference manifest architecture differs")
	}
	return pack(source, out, version, arch, commit, validUntil, key, &reference)
}

func pack(source string, out io.Writer, version, arch, commit string, validUntil time.Time, key ed25519.PrivateKey, reference *Manifest) error {
	if len(key) != ed25519.PrivateKeySize || !validArch(arch) {
		return errors.New("invalid signing key or architecture")
	}
	m := Manifest{Format: 1, Version: version, Arch: arch, Commit: commit, ValidUntil: validUntil.UTC().Format(time.RFC3339)}
	paths := make([]string, 0)
	err := filepath.WalkDir(source, func(p string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == source {
			return nil
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || !allowedName(filepath.ToSlash(rel)) {
			return fmt.Errorf("unsupported release entry %q", rel)
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	for _, name := range paths {
		p := filepath.Join(source, filepath.FromSlash(name))
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return fmt.Errorf("invalid file %s", name)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(f, maxFileSize+1))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return fmt.Errorf("file changed while packing: %s", name)
		}
		mode := int64(0o444)
		if info.Mode()&0o111 != 0 {
			mode = 0o555
		}
		m.Files = append(m.Files, File{Path: name, Size: n, Mode: mode, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	if reference != nil && !slices.Equal(m.Files, reference.Files) {
		return errors.New("release payload differs from the validated candidate")
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	if err := checkELF(source, arch); err != nil {
		return err
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, manifest)
	w := tar.NewWriter(out)
	write := func(name string, data io.Reader, size, mode int64) error {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, Typeflag: tar.TypeReg, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)}); err != nil {
			return err
		}
		_, err := io.CopyN(w, data, size)
		return err
	}
	if err := write("manifest.json", strings.NewReader(string(manifest)), int64(len(manifest)), 0o444); err != nil {
		return err
	}
	if err := write("manifest.sig", strings.NewReader(hex.EncodeToString(sig)), int64(hex.EncodedLen(len(sig))), 0o444); err != nil {
		return err
	}
	for _, item := range m.Files {
		f, err := os.Open(filepath.Join(source, filepath.FromSlash(item.Path)))
		if err != nil {
			return err
		}
		hash := sha256.New()
		err = write(item.Path, io.TeeReader(f, hash), item.Size, item.Mode)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return fmt.Errorf("file changed while packing: %s", item.Path)
		}
	}
	return w.Close()
}

// Verify reads the entire archive and rejects unknown, duplicate or mismatched entries.
// If stage is nonempty, verified files are written there for a subsequent atomic install.
func Verify(r io.Reader, public ed25519.PublicKey, expectedArch, stage string) (Manifest, error) {
	var m Manifest
	if len(public) != ed25519.PublicKeySize || !validArch(expectedArch) {
		return m, errors.New("invalid trust anchor or architecture")
	}
	limited := &io.LimitedReader{R: r, N: maxBundleSize + 2<<20}
	tr := tar.NewReader(limited)
	readMeta := func(expected string, limit int64) ([]byte, error) {
		h, err := tr.Next()
		if err != nil {
			return nil, err
		}
		if h.Name != expected || h.Typeflag != tar.TypeReg || h.Size > limit || h.Size < 0 {
			return nil, fmt.Errorf("invalid %s entry", expected)
		}
		return io.ReadAll(io.LimitReader(tr, limit+1))
	}
	manifest, err := readMeta("manifest.json", 1<<20)
	if err != nil {
		return m, err
	}
	sigHex, err := readMeta("manifest.sig", 2*ed25519.SignatureSize)
	if err != nil {
		return m, err
	}
	sig, err := hex.DecodeString(string(sigHex))
	if err != nil || !ed25519.Verify(public, manifest, sig) {
		return m, errors.New("release signature verification failed")
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return m, err
	}
	canonical, _ := json.Marshal(m)
	if string(canonical) != string(manifest) {
		return m, errors.New("noncanonical release manifest")
	}
	if err := validateManifest(m); err != nil {
		return m, err
	}
	if m.Arch != expectedArch {
		return m, fmt.Errorf("release architecture %s does not match %s", m.Arch, expectedArch)
	}
	for _, item := range m.Files {
		h, err := tr.Next()
		if err != nil {
			return m, err
		}
		if h.Name != item.Path || h.Typeflag != tar.TypeReg || h.Size != item.Size || h.Mode != item.Mode {
			return m, fmt.Errorf("unexpected release entry %q", h.Name)
		}
		var output io.Writer = io.Discard
		var f *os.File
		if stage != "" {
			target := filepath.Join(stage, filepath.FromSlash(item.Path))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return m, err
			}
			f, err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(item.Mode))
			if err != nil {
				return m, err
			}
			output = f
		}
		hash := sha256.New()
		_, err = io.CopyN(io.MultiWriter(output, hash), tr, item.Size)
		if f != nil {
			if err == nil {
				err = f.Chmod(os.FileMode(item.Mode))
			}
			if err == nil {
				err = f.Sync()
			}
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			return m, err
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return m, fmt.Errorf("hash mismatch: %s", item.Path)
		}
	}
	if h, err := tr.Next(); err != io.EOF {
		if err != nil {
			return m, err
		}
		return m, fmt.Errorf("unexpected extra entry %q", h.Name)
	}
	if _, err := io.Copy(zeroTail{}, limited); err != nil {
		return m, err
	}
	var extra [1]byte
	if n, err := r.Read(extra[:]); n != 0 || err != io.EOF {
		return m, errors.New("release archive exceeds limit or has trailing bytes")
	}
	return m, nil
}

type zeroTail struct{}

func (zeroTail) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, errors.New("nonzero trailing data in release archive")
		}
	}
	return len(p), nil
}

// Install verifies before committing an immutable version directory. It never activates services.
func Install(archive string, public ed25519.PublicKey, root string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("offline install requires Linux")
	}
	preflight, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	verified, verifyErr := Verify(preflight, public, runtime.GOARCH, "")
	closeErr := preflight.Close()
	if verifyErr != nil {
		return "", verifyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	target := filepath.Join(root, verified.Version+"-linux-"+verified.Arch)
	if _, err := os.Lstat(target); err == nil {
		return "", fmt.Errorf("release version already exists: %s", target)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	if err := ownedDirectory(root); err != nil {
		return "", err
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(root, ".incoming-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	m, verifyErr := Verify(f, public, runtime.GOARCH, stage)
	closeErr = f.Close()
	if verifyErr != nil {
		return "", verifyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := checkELF(stage, m.Arch); err != nil {
		return "", err
	}
	// MkdirAll respects the caller's umask. Derive every directory from the
	// verified payload so nested documentation/templates remain traversable to
	// the unprivileged API even under umask 0077. Only our private stage is touched.
	parents := map[string]bool{".": true}
	for _, item := range m.Files {
		for parent := path.Dir(item.Path); parent != "."; parent = path.Dir(parent) {
			parents[parent] = true
		}
	}
	directories := make([]string, 0, len(parents))
	for parent := range parents {
		directories = append(directories, parent)
	}
	// A child sorts after its prefix parent; reverse order syncs children first
	// and keeps the incoming stage private until its final "." entry.
	sort.Sort(sort.Reverse(sort.StringSlice(directories)))
	for _, dir := range directories {
		d, err := os.Open(filepath.Join(stage, dir))
		if err != nil {
			return "", err
		}
		if err := d.Chmod(0o755); err != nil {
			d.Close()
			return "", err
		}
		if err := d.Sync(); err != nil {
			d.Close()
			return "", err
		}
		if err := d.Close(); err != nil {
			return "", err
		}
	}
	if m.Version != verified.Version || m.Arch != verified.Arch {
		return "", errors.New("release changed between verification passes")
	}
	if err := os.Rename(stage, target); err != nil {
		return "", err
	}
	d, err := os.Open(root)
	if err != nil {
		return "", err
	}
	err = d.Sync()
	_ = d.Close()
	return target, err
}

func checkELF(stage, arch string) error {
	want := elf.EM_X86_64
	if arch == "arm64" {
		want = elf.EM_AARCH64
	}
	libNames := make(map[string]bool)
	libDir := filepath.Join(stage, "lib")
	entries, err := os.ReadDir(libDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("nested library directories are unsupported")
		}
		libNames[entry.Name()] = true
	}
	checkNeeded := func(f *elf.File, name string) error {
		needed, err := f.ImportedLibraries()
		if err != nil {
			return fmt.Errorf("read %s dependencies: %w", name, err)
		}
		for _, dependency := range needed {
			if !libNames[dependency] {
				return fmt.Errorf("%s needs missing bundled library %s", name, dependency)
			}
		}
		return nil
	}
	binaries := []string{"osv-sandboxd", "osv-sandbox-launcher", "osv-offline-release", "firecracker", "jailer", "mkfs.ext4"}
	for _, optional := range []string{"osv-sandbox-mcp", "osv-sandbox-egress"} {
		if _, err := os.Stat(filepath.Join(stage, "bin", optional)); err == nil {
			binaries = append(binaries, optional)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, name := range binaries {
		f, err := elf.Open(filepath.Join(stage, "bin", name))
		if err != nil {
			return fmt.Errorf("%s must be ELF: %w", name, err)
		}
		if f.Machine != want {
			f.Close()
			return fmt.Errorf("%s has wrong ELF architecture", name)
		}
		for _, program := range f.Progs {
			if program.Type != elf.PT_INTERP {
				continue
			}
			if name != "mkfs.ext4" {
				f.Close()
				return fmt.Errorf("%s must be static", name)
			}
			data, err := io.ReadAll(program.Open())
			if err != nil {
				f.Close()
				return err
			}
			loader := filepath.Base(strings.TrimRight(string(data), "\x00"))
			if !libNames[loader] {
				f.Close()
				return fmt.Errorf("mkfs loader %s missing from bundle", loader)
			}
		}
		if err := checkNeeded(f, name); err != nil {
			f.Close()
			return err
		}
		_ = f.Close()
	}
	for _, entry := range entries {
		f, err := elf.Open(filepath.Join(libDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("bundled library %s is not ELF: %w", entry.Name(), err)
		}
		if f.Machine != want {
			f.Close()
			return fmt.Errorf("bundled library %s has wrong architecture", entry.Name())
		}
		if err := checkNeeded(f, entry.Name()); err != nil {
			f.Close()
			return err
		}
		_ = f.Close()
	}
	return nil
}
