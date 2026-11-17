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
	"slices"
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
	Protocol          string                `json:"protocol"`
	Backend           string                `json:"backend,omitempty"`
	Entrypoints       []string              `json:"entrypoints,omitempty"`
	AgentFeatures     []string              `json:"agent_features,omitempty"`
	CodeRuntime       *SignedCodeRuntime    `json:"code_runtime,omitempty"`
	GuestInference    *SignedGuestInference `json:"guest_inference,omitempty"`
	OSvUpstreamCommit string                `json:"osv_upstream_commit,omitempty"`
	OSvROFSCache      string                `json:"osv_rofs_cache,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
	Kernel            Artifact              `json:"kernel"`
	Image             Artifact              `json:"image"`
	KernelSize        int64                 `json:"kernel_size"`
	ImageSize         int64                 `json:"image_size"`
	FirecrackerSHA256 string                `json:"firecracker_sha256"`
	JailerSHA256      string                `json:"jailer_sha256"`
	SBOMSHA256        string                `json:"sbom_sha256"`
	SBOMSize          int64                 `json:"sbom_size"`
	digestSHA256      string
}

// ValidateProfile binds the signed artifact set to the runtime backend and
// the module paths an OSv tenant policy may subsequently allow.
func (m SignedArtifactManifest) ValidateProfile(backend string, allowedEntrypoints []string) error {
	if m.Protocol == "osv-sandbox-artifacts/v8" {
		return m.validateWorkspaceArtifactProfile(backend, allowedEntrypoints)
	}
	if m.Protocol != "osv-sandbox-artifacts/v7" && m.GuestInference != nil {
		return errors.New("guest inference requires a signed v7 profile")
	}
	if m.Protocol != "osv-sandbox-artifacts/v5" && m.Protocol != "osv-sandbox-artifacts/v6" && (m.Protocol != "osv-sandbox-artifacts/v7" || backend != "firecracker-linux") && m.CodeRuntime != nil {
		return errors.New("code runtime requires a signed Linux code profile")
	}
	switch m.Protocol {
	case "osv-sandbox-artifacts/v7":
		if m.Backend != backend || m.GuestInference.validate(backend) != nil {
			return errors.New("invalid signed v7 guest inference profile")
		}
		if backend == "firecracker-linux" {
			if len(m.Entrypoints) != 0 || m.OSvUpstreamCommit != "" || m.OSvROFSCache != "" || m.CodeRuntime.validate() != nil || m.CodeRuntime.Architecture != m.GuestInference.Architecture {
				return errors.New("invalid signed v7 Linux runtime")
			}
			if err := validateV7Features(m.AgentFeatures, []string{"code-contexts-v1", "remote-infer-v1", "vsock-proxy-v1"}, []string{"workspace-watch-v1", "port-forward-v1"}); err != nil {
				return err
			}
			return nil
		}
		if err := validateV7Features(m.AgentFeatures, []string{"remote-infer-v1", "vsock-proxy-v1"}, []string{"environment", "input-files-v1", "stdin", "pristine-v1"}); err != nil {
			return err
		}
		python := false
		for _, path := range m.Entrypoints {
			python = python || path == "/python3.12.so"
		}
		if !python {
			return errors.New("OSv v7 requires its signed Python module")
		}
	case "osv-sandbox-artifacts/v5", "osv-sandbox-artifacts/v6":
		ports := m.Protocol == "osv-sandbox-artifacts/v6"
		maximum := 3
		if ports {
			maximum = 4
		}
		if backend != "firecracker-linux" || m.Backend != backend || len(m.Entrypoints) != 0 || m.OSvUpstreamCommit != "" || m.OSvROFSCache != "" || len(m.AgentFeatures) < 1 || len(m.AgentFeatures) > maximum {
			return errors.New("invalid signed Linux code/port profile")
		}
		code, port, previous := false, false, ""
		for _, feature := range m.AgentFeatures {
			if feature != "code-contexts-v1" && feature != "workspace-watch-v1" && feature != "vsock-proxy-v1" && !(ports && feature == "port-forward-v1") || feature <= previous {
				return errors.New("unsupported, unsorted or duplicate signed code feature")
			}
			code = code || feature == "code-contexts-v1"
			port = port || feature == "port-forward-v1"
			previous = feature
		}
		if !ports && !code {
			return errors.New("v5 Linux profile requires code-contexts-v1")
		}
		if ports && !port {
			return errors.New("v6 Linux profile requires port-forward-v1")
		}
		if code {
			return m.CodeRuntime.validate()
		}
		if m.CodeRuntime != nil {
			return errors.New("code runtime without code-contexts-v1")
		}
		return nil
	case "osv-sandbox-artifacts/v1":
		if backend != "firecracker-linux" || m.Backend != "" || len(m.Entrypoints) != 0 || len(m.AgentFeatures) != 0 || m.OSvUpstreamCommit != "" || m.OSvROFSCache != "" {
			return errors.New("v1 artifact manifest is only valid for the Linux backend")
		}
		return nil
	case "osv-sandbox-artifacts/v2":
		if backend != "firecracker-osv" || m.Backend != backend {
			return errors.New("signed OSv backend does not match runtime backend")
		}
	case "osv-sandbox-artifacts/v3":
		if backend != "firecracker-linux" || m.Backend != backend || len(m.Entrypoints) != 0 || m.OSvUpstreamCommit != "" || m.OSvROFSCache != "" || len(m.AgentFeatures) != 1 || m.AgentFeatures[0] != "vsock-proxy-v1" {
			return errors.New("v3 Linux profile requires exactly the supported signed guest proxy feature")
		}
		return nil
	case "osv-sandbox-artifacts/v4":
		if backend != "firecracker-linux" || m.Backend != backend || len(m.Entrypoints) != 0 || m.OSvUpstreamCommit != "" || m.OSvROFSCache != "" || len(m.AgentFeatures) < 1 || len(m.AgentFeatures) > 2 {
			return errors.New("v4 Linux profile requires the supported signed workspace watch feature")
		}
		watch, previous := false, ""
		for _, feature := range m.AgentFeatures {
			if feature != "workspace-watch-v1" && feature != "vsock-proxy-v1" || feature <= previous {
				return errors.New("unsupported, unsorted or duplicate signed Linux agent feature")
			}
			watch = watch || feature == "workspace-watch-v1"
			previous = feature
		}
		if !watch {
			return errors.New("v4 Linux profile requires workspace-watch-v1")
		}
		return nil
	default:
		return errors.New("unsupported artifact manifest protocol")
	}
	if m.OSvROFSCache != "" && m.OSvROFSCache != "disabled" {
		return errors.New("unsupported signed OSv ROFS cache policy")
	}
	if len(m.OSvUpstreamCommit) != 40 {
		return errors.New("signed OSv upstream commit must be 40 lowercase hex characters")
	}
	for _, char := range m.OSvUpstreamCommit {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return errors.New("signed OSv upstream commit must be 40 lowercase hex characters")
		}
	}
	if len(m.Entrypoints) == 0 || len(m.Entrypoints) > 64 {
		return errors.New("signed OSv module list must contain 1 to 64 paths")
	}
	previousFeature := ""
	for _, feature := range m.AgentFeatures {
		if feature != "environment" && feature != "stdin" && feature != "pristine-v1" && feature != "input-files-v1" && !(m.Protocol == "osv-sandbox-artifacts/v7" && (feature == "remote-infer-v1" || feature == "vsock-proxy-v1")) || feature <= previousFeature {
			return errors.New("unsupported, unsorted or duplicate signed OSv agent feature")
		}
		previousFeature = feature
	}
	if slices.Contains(m.AgentFeatures, "input-files-v1") && !slices.Contains(m.AgentFeatures, "pristine-v1") {
		return errors.New("OSv input-files-v1 requires pristine-v1")
	}
	modules := make(map[string]struct{}, len(m.Entrypoints))
	previous := ""
	for index, path := range m.Entrypoints {
		if !validOSvModulePath(path) || index > 0 && path <= previous {
			return errors.New("signed OSv module paths must be canonical, sorted and unique")
		}
		modules[path] = struct{}{}
		previous = path
	}
	if len(allowedEntrypoints) == 0 {
		return errors.New("runtime OSv module allowlist must not be empty")
	}
	seen := make(map[string]struct{}, len(allowedEntrypoints))
	for _, path := range allowedEntrypoints {
		if !validOSvModulePath(path) {
			return fmt.Errorf("runtime OSv module path %q is invalid", path)
		}
		if _, ok := seen[path]; ok {
			return fmt.Errorf("runtime OSv module path %q is duplicated", path)
		}
		seen[path] = struct{}{}
		if _, ok := modules[path]; !ok {
			return fmt.Errorf("runtime OSv module path %q is not signed", path)
		}
	}
	return nil
}

func (m SignedArtifactManifest) activeAt(now time.Time) error {
	if m.CreatedAt.After(now.Add(5*time.Minute)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.CreatedAt) {
		return errors.New("artifact manifest validity window is invalid or expired")
	}
	return nil
}

func VerifyArtifactManifest(config Config, resolved ResolvedArtifacts) error {
	_, err := verifyArtifactManifest(config, resolved)
	return err
}

func verifyArtifactManifest(config Config, resolved ResolvedArtifacts) (*SignedArtifactManifest, error) {
	manifestConfig := config.ArtifactManifest
	if manifestConfig == nil {
		return nil, nil
	}
	if config.Jailer == nil {
		return nil, errors.New("signed artifact verification requires a jailer configuration")
	}
	manifestPath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.Path, "artifact manifest")
	if err != nil {
		return nil, err
	}
	signaturePath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.SignaturePath, "artifact signature")
	if err != nil {
		return nil, err
	}
	publicKeyInfo, err := os.Stat(manifestConfig.PublicKeyPath)
	if err != nil || !publicKeyInfo.Mode().IsRegular() || publicKeyInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("artifact public key must be a regular file not writable by group or other")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	encodedSignature, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, err
	}
	encodedPublicKey, err := os.ReadFile(manifestConfig.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	manifest, err := VerifySignedArtifactMetadata(manifestBytes, encodedSignature, encodedPublicKey, config.Backend, config.AllowedEntrypoints)
	if err != nil {
		return nil, err
	}
	manifestResolved, err := ResolveArtifacts(config.ArtifactRoot, manifest.Kernel, manifest.Image)
	if err != nil {
		return nil, fmt.Errorf("resolve signed artifacts: %w", err)
	}
	if manifestResolved.KernelPath != resolved.KernelPath || manifestResolved.ImagePath != resolved.ImagePath ||
		!strings.EqualFold(manifest.Kernel.SHA256, config.Kernel.SHA256) || !strings.EqualFold(manifest.Image.SHA256, config.Image.SHA256) {
		return nil, errors.New("runtime artifact configuration does not match signed manifest")
	}
	kernelInfo, _ := os.Stat(resolved.KernelPath)
	imageInfo, _ := os.Stat(resolved.ImagePath)
	if kernelInfo.Size() != manifest.KernelSize || imageInfo.Size() != manifest.ImageSize {
		return nil, errors.New("signed artifact size mismatch")
	}
	if err := verifyExecutableHash(config.HypervisorPath, manifest.FirecrackerSHA256, "firecracker"); err != nil {
		return nil, err
	}
	if err := verifyExecutableHash(config.Jailer.Path, manifest.JailerSHA256, "jailer"); err != nil {
		return nil, err
	}
	sbomPath, err := confinedRegularFile(config.ArtifactRoot, manifestConfig.SBOMPath, "SBOM")
	if err != nil {
		return nil, err
	}
	sbomInfo, _ := os.Stat(sbomPath)
	sbomHash, err := fileSHA256(sbomPath)
	if err != nil || sbomInfo.Size() != manifest.SBOMSize || !strings.EqualFold(sbomHash, manifest.SBOMSHA256) {
		return nil, errors.New("signed SBOM hash or size mismatch")
	}
	if manifest.Protocol == "osv-sandbox-artifacts/v2" || manifest.Protocol == "osv-sandbox-artifacts/v7" || manifest.GuestInference != nil {
		if manifest.GuestInference != nil && sbomInfo.Size() > 64<<20 {
			return nil, errors.New("v7 SBOM exceeds size limit")
		}
		sbomBytes, err := os.ReadFile(sbomPath)
		if err != nil {
			return nil, err
		}
		if config.Backend == "firecracker-osv" {
			if err := verifyOSvSBOM(sbomBytes, *manifest); err != nil {
				return nil, fmt.Errorf("OSv SBOM is inconsistent with signed manifest: %w", err)
			}
		}
		if manifest.GuestInference != nil {
			if err := manifest.ValidateGuestInferenceSBOM(sbomBytes); err != nil {
				return nil, fmt.Errorf("v7 image BOM differs from guest SDK profile: %w", err)
			}
		}
	}
	return manifest, nil
}

// VerifySignedArtifactMetadata authenticates bounded metadata before downloading
// large artifacts. It does not verify image/SBOM bytes or host executables;
// admission must still use VerifyArtifactManifest afterwards.
func VerifySignedArtifactMetadata(manifestBytes, encodedSignature, encodedPublicKey []byte, backend string, allowedEntrypoints []string) (*SignedArtifactManifest, error) {
	if len(manifestBytes) > 1<<20 || len(encodedSignature) > 4096 || len(encodedPublicKey) > 4096 {
		return nil, errors.New("signed artifact metadata exceeds size limit")
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedPublicKey)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("artifact manifest public key is not a base64 Ed25519 key")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), manifestBytes, signature) {
		return nil, errors.New("artifact manifest Ed25519 signature verification failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	var manifest SignedArtifactManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode artifact manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("artifact manifest must contain exactly one JSON object")
	}
	if err := manifest.ValidateProfile(backend, allowedEntrypoints); err != nil {
		return nil, err
	}
	if err := manifest.activeAt(time.Now()); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(manifestBytes)
	manifest.digestSHA256 = hex.EncodeToString(digest[:])
	return &manifest, nil
}

func verifyOSvSBOM(data []byte, manifest SignedArtifactManifest) error {
	var document struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Hashes  []struct {
				Algorithm string `json:"alg"`
				Content   string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.5" {
		return errors.New("unsupported OSv SBOM format")
	}
	expected := map[string]string{
		"osv-kernel":           manifest.Kernel.SHA256,
		"osv-rootfs":           manifest.Image.SHA256,
		"firecracker":          manifest.FirecrackerSHA256,
		"jailer":               manifest.JailerSHA256,
		"osv-job-agent":        "",
		"osv-sandboxd":         "",
		"osv-sandbox-launcher": "",
		"OSv":                  "",
	}
	for _, path := range manifest.Entrypoints {
		expected["osv-module"+path] = ""
	}
	seen := make(map[string]struct{}, len(document.Components))
	for _, component := range document.Components {
		if _, exists := seen[component.Name]; exists {
			return fmt.Errorf("duplicate SBOM component %q", component.Name)
		}
		seen[component.Name] = struct{}{}
		if component.Name == "OSv" {
			if component.Version != manifest.OSvUpstreamCommit {
				return errors.New("OSv upstream commit differs from signed manifest")
			}
			continue
		}
		wanted, ok := expected[component.Name]
		if !ok {
			return fmt.Errorf("unexpected OSv SBOM component %q", component.Name)
		}
		found := ""
		for _, hash := range component.Hashes {
			if hash.Algorithm == "SHA-256" {
				if found != "" {
					return fmt.Errorf("duplicate SHA-256 for SBOM component %q", component.Name)
				}
				found = hash.Content
			}
		}
		if len(found) != 64 {
			return fmt.Errorf("missing SHA-256 for SBOM component %q", component.Name)
		}
		if _, err := hex.DecodeString(found); err != nil {
			return fmt.Errorf("invalid SHA-256 for SBOM component %q", component.Name)
		}
		if wanted != "" && !strings.EqualFold(wanted, found) {
			return fmt.Errorf("SHA-256 differs for SBOM component %q", component.Name)
		}
	}
	for name := range expected {
		if _, exists := seen[name]; !exists {
			return fmt.Errorf("missing OSv SBOM component %q", name)
		}
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
	if config.Preview != nil {
		paths = append(paths, struct{ name, path string }{"preview TLS certificate", config.Preview.CertFile}, struct{ name, path string }{"preview TLS private key", config.Preview.KeyFile})
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
