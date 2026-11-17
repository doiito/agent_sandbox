package sandbox

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testCodeProfile() *SignedCodeRuntime {
	return &SignedCodeRuntime{Architecture: "amd64", KernelProtocol: "osv-code-kernel/v2", PythonVersion: "3.12.16", NodeVersion: "22.23.4", TypeScriptVersion: "5.9.3", PrewarmLanguage: "python",
		RuntimeInventorySHA256: strings.Repeat("a", 64), KernelScriptsSHA256: map[string]string{"python.py": strings.Repeat("b", 64), "node.cjs": strings.Repeat("c", 64)}, MinimumCPUFeatures: []string{"sse4_1"}}
}

func TestCodeCapabilitiesRequireSignedEnabledTemplateAndCopyProfile(t *testing.T) {
	s := codeTestSession(t, func(net.Conn, *bufio.Reader, linuxCodeRequest) { t.Error("discovery contacted guest") })
	report, err := s.manager.Capabilities()
	if err != nil || !report.Features.CodeContexts || len(report.CodeLanguages) != 3 || report.Limits.CodeContexts != 4 || report.Limits.CodeExecutionIDs != 256 {
		t.Fatal("signed enabled template lost code capability", report, err)
	}
	for _, method := range []string{"POST /v2/sessions/{id}/contexts", "POST /v2/sessions/{id}/contexts/default", "GET /v2/sessions/{id}/contexts", "GET /v2/sessions/{id}/contexts/{context}", "POST /v2/sessions/{id}/contexts/{context}/restart", "DELETE /v2/sessions/{id}/contexts/{context}", "POST /v2/sessions/{id}/code-executions", "GET /v2/sessions/{id}/code-executions/{execution}", "DELETE /v2/sessions/{id}/code-executions/{execution}"} {
		if !slices.Contains(report.Methods, method) {
			t.Fatal("code route absent from discovery", method)
		}
	}
	report.CodeRuntime.KernelScriptsSHA256["python.py"] = "mutated"
	report.CodeRuntime.MinimumCPUFeatures[0] = "mutated"
	if s.manager.manifest.CodeRuntime.validate() != nil {
		t.Fatal("discovery aliased signed runtime")
	}
	s.manager.config.AllowedEntrypoints = []string{codeEntrypoint("javascript")}
	report, _ = s.manager.Capabilities()
	if !slices.Equal(report.CodeLanguages, []string{"javascript", "typescript"}) {
		t.Fatal("template policy ignored", report.CodeLanguages)
	}
	backend := s.manager.backend.(FirecrackerLinuxBackend)
	backend.CodeContexts = false
	s.manager.backend = backend
	report, _ = s.manager.Capabilities()
	if report.Features.CodeContexts || report.CodeRuntime != nil {
		t.Fatal("disabled backend advertised code")
	}
	backend.CodeContexts = true
	s.manager.backend = backend
	s.manager.manifest.Protocol = "osv-sandbox-artifacts/v4"
	report, _ = s.manager.Capabilities()
	if report.Features.CodeContexts || report.CodeRuntime != nil {
		t.Fatal("old profile advertised code")
	}
}
func TestCodeSignedProfileRejectsOldProfilesWrongVersionsAndUnboundInputs(t *testing.T) {
	manifest := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v5", Backend: "firecracker-linux", AgentFeatures: []string{"code-contexts-v1", "vsock-proxy-v1", "workspace-watch-v1"}, CodeRuntime: testCodeProfile()}
	if manifest.ValidateProfile("firecracker-linux", nil) != nil {
		t.Fatal("valid v5 profile refused")
	}
	for _, edit := range []func(*SignedArtifactManifest){func(m *SignedArtifactManifest) { m.Protocol = "osv-sandbox-artifacts/v4" }, func(m *SignedArtifactManifest) { m.Backend = "firecracker-osv" }, func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"workspace-watch-v1", "code-contexts-v1"} }, func(m *SignedArtifactManifest) { m.CodeRuntime.NodeVersion = "22.0.0" }, func(m *SignedArtifactManifest) { delete(m.CodeRuntime.KernelScriptsSHA256, "python.py") }, func(m *SignedArtifactManifest) { m.CodeRuntime.RuntimeInventorySHA256 = "" }, func(m *SignedArtifactManifest) { m.CodeRuntime.PrewarmLanguage = "ruby" }, func(m *SignedArtifactManifest) { m.CodeRuntime.MinimumCPUFeatures = nil }} {
		copy := manifest
		copy.CodeRuntime = manifest.CodeRuntime.clone()
		copy.AgentFeatures = append([]string{}, manifest.AgentFeatures...)
		edit(&copy)
		if copy.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatal("invalid signed code profile accepted", copy)
		}
	}
}
func TestCodeCPUBaselineRequiresEveryReportedCoreAndCorrectArchitecture(t *testing.T) {
	p := testCodeProfile()
	if p.validateHost("amd64", "flags : sse2 sse4_1\nflags : sse4_1 avx\n") != nil {
		t.Fatal("supported CPU refused")
	}
	for _, cpu := range []string{"flags : sse4_1\nflags : sse2\n", "flags : sse2\n", "processor: 0\n"} {
		if p.validateHost("amd64", cpu) == nil {
			t.Fatal("missing baseline accepted", cpu)
		}
	}
	if p.validateHost("arm64", "Features : asimd\n") == nil {
		t.Fatal("cross-architecture code image admitted")
	}
	p.Architecture = "arm64"
	p.MinimumCPUFeatures = []string{"asimd"}
	if p.validateHost("arm64", "Features : fp asimd aes\n") != nil {
		t.Fatal("ARM SIMD baseline refused")
	}
}
func TestCodeV5SignatureActuallyBindsRuntimeProfile(t *testing.T) {
	root := t.TempDir()
	paths := map[string]string{}
	for _, name := range []string{"kernel", "image", "firecracker", "jailer", "sbom"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = p
		if name == "firecracker" || name == "jailer" {
			if err := os.Chmod(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "public")
	_ = os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o600)
	hash := func(name string) string {
		value, err := fileSHA256(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	now := time.Now().UTC()
	m := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v5", Backend: "firecracker-linux", AgentFeatures: []string{"code-contexts-v1"}, CodeRuntime: testCodeProfile(), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		Kernel: Artifact{Path: "kernel", SHA256: hash("kernel")}, Image: Artifact{Path: "image", SHA256: hash("image"), Format: "raw"}, KernelSize: 6, ImageSize: 5,
		FirecrackerSHA256: hash("firecracker"), JailerSHA256: hash("jailer"), SBOMSHA256: hash("sbom"), SBOMSize: 4}
	manifestPath := filepath.Join(root, "manifest")
	signaturePath := filepath.Join(root, "signature")
	write := func(resign bool) {
		data, _ := json.Marshal(m)
		_ = os.WriteFile(manifestPath, data, 0o600)
		if resign {
			_ = os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, data))), 0o600)
		}
	}
	config := Config{Backend: "firecracker-linux", ArtifactRoot: root, Kernel: m.Kernel, Image: m.Image, HypervisorPath: paths["firecracker"], Jailer: &JailerConfig{Path: paths["jailer"]}, ArtifactManifest: &ArtifactManifestConfig{Path: manifestPath, SignaturePath: signaturePath, PublicKeyPath: publicPath, SBOMPath: "sbom"}}
	resolved := ResolvedArtifacts{KernelPath: paths["kernel"], ImagePath: paths["image"], Format: "raw"}
	write(true)
	if _, err := verifyArtifactManifest(config, resolved); err != nil {
		t.Fatal(err)
	}
	m.CodeRuntime.PrewarmLanguage = "typescript"
	write(false)
	if _, err := verifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("unsigned runtime mutation accepted")
	}
	write(true)
	if _, err := verifyArtifactManifest(config, resolved); err != nil {
		t.Fatal("valid signed prewarm change refused", err)
	}
}
