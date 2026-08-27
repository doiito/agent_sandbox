package sandbox

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type ResolvedArtifacts struct {
	KernelPath          string
	ImagePath           string
	ScratchTemplatePath string
	Format              string
}

func ResolveArtifacts(root string, kernel, image Artifact) (ResolvedArtifacts, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ResolvedArtifacts{}, fmt.Errorf("resolve artifact root: %w", err)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return ResolvedArtifacts{}, err
	}
	resolve := func(a Artifact, name string) (string, error) {
		if len(a.SHA256) != 64 {
			return "", fmt.Errorf("%s sha256 must contain 64 hex characters", name)
		}
		if _, err := hex.DecodeString(a.SHA256); err != nil {
			return "", fmt.Errorf("%s sha256 is invalid: %w", name, err)
		}
		candidate := a.Path
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(realRoot, candidate)
		}
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", name, err)
		}
		real, err = filepath.Abs(real)
		if err != nil {
			return "", err
		}
		rel, err := filepath.Rel(realRoot, real)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%s escapes artifact_root", name)
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() {
			return "", fmt.Errorf("%s must be a regular file", name)
		}
		got, err := fileSHA256(real)
		if err != nil {
			return "", fmt.Errorf("hash %s: %w", name, err)
		}
		if !strings.EqualFold(got, a.SHA256) {
			return "", fmt.Errorf("%s sha256 mismatch: got %s", name, got)
		}
		return real, nil
	}
	kernelPath, err := resolve(kernel, "kernel")
	if err != nil {
		return ResolvedArtifacts{}, err
	}
	imagePath, err := resolve(image, "image")
	if err != nil {
		return ResolvedArtifacts{}, err
	}
	format := image.Format
	if format == "" {
		format = "raw"
	}
	if format != "raw" && format != "qcow2" {
		return ResolvedArtifacts{}, fmt.Errorf("image format must be raw or qcow2")
	}
	return ResolvedArtifacts{KernelPath: kernelPath, ImagePath: imagePath, Format: format}, nil
}

type SignedArtifactManifest struct {
	Protocol          string    `json:"protocol"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Kernel            Artifact  `json:"kernel"`
	Image             Artifact  `json:"image"`
	KernelSize        int64     `json:"kernel_size"`
	ImageSize         int64     `json:"image_size"`
	FirecrackerSHA256 string    `json:"firecracker_sha256"`
	JailerSHA256      string    `json:"jailer_sha256"`
	SBOMSHA256        string    `json:"sbom_sha256"`
	SBOMSize          int64     `json:"sbom_size"`
}

func VerifyArtifactManifest(config Config, resolved ResolvedArtifacts) error {
	manifestConfig := config.ArtifactManifest
	if manifestConfig == nil {
		return nil
	}
	manifestPath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.Path, "artifact manifest")
	if err != nil {
		return err
	}
	signaturePath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.SignaturePath, "artifact signature")
	if err != nil {
		return err
	}
	publicKeyInfo, err := os.Stat(manifestConfig.PublicKeyPath)
	if err != nil || !publicKeyInfo.Mode().IsRegular() || publicKeyInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("artifact public key must be a regular file not writable by group or other")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	encodedSignature, err := os.ReadFile(signaturePath)
	if err != nil {
		return err
	}
	encodedPublicKey, err := os.ReadFile(manifestConfig.PublicKeyPath)
	if err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedPublicKey)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("artifact manifest public key is not a base64 Ed25519 key")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), manifestBytes, signature) {
		return errors.New("artifact manifest Ed25519 signature verification failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	var manifest SignedArtifactManifest
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode artifact manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("artifact manifest must contain exactly one JSON object")
	}
	if manifest.Protocol != "osv-sandbox-artifacts/v1" {
		return errors.New("unsupported artifact manifest protocol")
	}
	now := time.Now().UTC()
	if manifest.CreatedAt.After(now.Add(5*time.Minute)) || !manifest.ExpiresAt.After(now) || !manifest.ExpiresAt.After(manifest.CreatedAt) {
		return errors.New("artifact manifest validity window is invalid or expired")
	}
	manifestResolved, err := ResolveArtifacts(config.ArtifactRoot, manifest.Kernel, manifest.Image)
	if err != nil {
		return fmt.Errorf("resolve signed artifacts: %w", err)
	}
	if manifestResolved.KernelPath != resolved.KernelPath || manifestResolved.ImagePath != resolved.ImagePath ||
		!strings.EqualFold(manifest.Kernel.SHA256, config.Kernel.SHA256) || !strings.EqualFold(manifest.Image.SHA256, config.Image.SHA256) {
		return errors.New("runtime artifact configuration does not match signed manifest")
	}
	kernelInfo, _ := os.Stat(resolved.KernelPath)
	imageInfo, _ := os.Stat(resolved.ImagePath)
	if kernelInfo.Size() != manifest.KernelSize || imageInfo.Size() != manifest.ImageSize {
		return errors.New("signed artifact size mismatch")
	}
	if err := verifyExecutableHash(config.HypervisorPath, manifest.FirecrackerSHA256, "firecracker"); err != nil {
		return err
	}
	if err := verifyExecutableHash(config.Jailer.Path, manifest.JailerSHA256, "jailer"); err != nil {
		return err
	}
	sbomPath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.SBOMPath, "SBOM")
	if err != nil {
		return err
	}
	sbomInfo, _ := os.Stat(sbomPath)
	sbomHash, err := fileSHA256(sbomPath)
	if err != nil || sbomInfo.Size() != manifest.SBOMSize || !strings.EqualFold(sbomHash, manifest.SBOMSHA256) {
		return errors.New("signed SBOM hash or size mismatch")
	}
	return nil
}

func confinedRegularFile(root, path, name string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return "", err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(realRoot, candidate)
	}
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(realRoot, real)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s escapes artifact_root", name)
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", name)
	}
	return real, nil
}

func verifyExecutableHash(path, expected, name string) error {
	if len(expected) != 64 {
		return fmt.Errorf("signed %s hash is invalid", name)
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return err
	}
	got, err := fileSHA256(resolved)
	if err != nil || !strings.EqualFold(got, expected) {
		return fmt.Errorf("signed %s hash mismatch", name)
	}
	return nil
}

func ValidateProductionHostPaths(config Config, resolved ResolvedArtifacts) error {
	paths := []struct {
		name string
		path string
	}{
		{"artifact root", config.ArtifactRoot},
		{"kernel", resolved.KernelPath},
		{"image", resolved.ImagePath},
		{"run root", config.RunRoot},
		{"launcher socket parent", filepath.Dir(config.LauncherSocket)},
		{"manifest", filepath.Join(config.ArtifactRoot, config.ArtifactManifest.Path)},
		{"manifest signature", filepath.Join(config.ArtifactRoot, config.ArtifactManifest.SignaturePath)},
		{"manifest public key", config.ArtifactManifest.PublicKeyPath},
		{"SBOM", filepath.Join(config.ArtifactRoot, config.ArtifactManifest.SBOMPath)},
		{"auth policy", config.AuthPolicyPath},
		{"TLS certificate", config.TLS.CertFile},
		{"TLS private key", config.TLS.KeyFile},
		{"TLS client CA", config.TLS.ClientCAFile},
		{"audit log", config.AuditLogPath},
	}
	for _, item := range paths {
		if err := trustedRootOwnedPath(item.path); err != nil {
			return fmt.Errorf("untrusted %s: %w", item.name, err)
		}
	}
	for _, item := range []struct{ name, path string }{{"firecracker", config.HypervisorPath}, {"jailer", config.Jailer.Path}} {
		resolvedExecutable, err := exec.LookPath(item.path)
		if err != nil {
			return err
		}
		if err := trustedRootOwnedPath(resolvedExecutable); err != nil {
			return fmt.Errorf("untrusted %s: %w", item.name, err)
		}
	}
	return nil
}

func trustedRootOwnedPath(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return err
	}
	for current := real; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("%s is not owned by root", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or other", current)
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func ValidateAuditLogTarget(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("audit log path must be absolute")
	}
	if err := trustedRootOwnedPath(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log target must be a regular non-symlink file")
	}
	return trustedRootOwnedPath(path)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
