package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPortV6ProfileCompositionAndLegacyIsolation(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		features := []string{"port-forward-v1"}
		for i, name := range []string{"code-contexts-v1", "vsock-proxy-v1", "workspace-watch-v1"} {
			if mask&(1<<i) != 0 {
				features = append(features, name)
			}
		}
		slices.Sort(features)
		manifest := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v6", Backend: "firecracker-linux", AgentFeatures: features, digestSHA256: strings.Repeat("a", 64)}
		if mask&1 != 0 {
			manifest.CodeRuntime = testCodeProfile()
		}
		if err := manifest.ValidateProfile("firecracker-linux", nil); err != nil {
			t.Fatal(features, err)
		}
		m := &Manager{config: Config{Backend: "firecracker-linux"}, manifest: &manifest}
		if !m.hasLinuxPortFeature() || m.hasLinuxCodeFeature() != (mask&1 != 0) || m.hasLinuxProxyFeature() != (mask&2 != 0) || m.hasLinuxWatchFeature() != (mask&4 != 0) {
			t.Fatal("v6 conflated features", features)
		}
		copy := manifest
		copy.Protocol = "osv-sandbox-artifacts/v5"
		if copy.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatal("port flag accepted in v5")
		}
	}
	base := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v6", Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}}
	for _, edit := range []func(*SignedArtifactManifest){
		func(m *SignedArtifactManifest) { m.Backend = "firecracker-osv" },
		func(m *SignedArtifactManifest) { m.AgentFeatures = nil },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"workspace-watch-v1"} },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"port-forward-v1", "port-forward-v1"} },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"workspace-watch-v1", "port-forward-v1"} },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"port-forward-v1", "unknown"} },
		func(m *SignedArtifactManifest) { m.CodeRuntime = testCodeProfile() },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"code-contexts-v1", "port-forward-v1"} },
		func(m *SignedArtifactManifest) { m.Entrypoints = []string{"/agent"} },
		func(m *SignedArtifactManifest) { m.OSvROFSCache = "disabled" },
	} {
		copy := base
		edit(&copy)
		if copy.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatal("invalid v6 accepted", copy)
		}
	}
}

func TestPortV6SignatureProjectLoaderBindsFeatureAndRejectsOldProtocol(t *testing.T) {
	root := t.TempDir()
	paths := map[string]string{}
	for _, name := range []string{"kernel", "image", "firecracker", "jailer", "sbom"} {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(name), 0o700); err != nil {
			t.Fatal(err)
		}
		paths[name] = p
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "public")
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := func(name string) string {
		value, err := fileSHA256(paths[name])
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	now := time.Now().UTC()
	m := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v6", Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Kernel: Artifact{Path: "kernel", SHA256: hash("kernel")}, Image: Artifact{Path: "image", SHA256: hash("image"), Format: "raw"}, KernelSize: 6, ImageSize: 5, FirecrackerSHA256: hash("firecracker"), JailerSHA256: hash("jailer"), SBOMSHA256: hash("sbom"), SBOMSize: 4}
	manifestPath, signaturePath := filepath.Join(root, "manifest"), filepath.Join(root, "signature")
	write := func(sign bool) {
		data, _ := json.Marshal(m)
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if sign {
			if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, data))), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	config := Config{Backend: "firecracker-linux", ArtifactRoot: root, Kernel: m.Kernel, Image: m.Image, HypervisorPath: paths["firecracker"], Jailer: &JailerConfig{Path: paths["jailer"]}, ArtifactManifest: &ArtifactManifestConfig{Path: manifestPath, SignaturePath: signaturePath, PublicKeyPath: publicPath, SBOMPath: "sbom"}}
	resolved := ResolvedArtifacts{KernelPath: paths["kernel"], ImagePath: paths["image"], Format: "raw"}
	write(true)
	checked, err := verifyArtifactManifest(config, resolved)
	if err != nil || !validSHA256Hex(checked.digestSHA256) {
		t.Fatal(err)
	}
	m.AgentFeatures = append(m.AgentFeatures, "workspace-watch-v1")
	write(false)
	if _, err := verifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("unsigned feature modification accepted by project loader")
	}
	write(true)
	if _, err := verifyArtifactManifest(config, resolved); err != nil {
		t.Fatal(err)
	}
	m.Protocol = "osv-sandbox-artifacts/v5"
	write(true)
	if _, err := verifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("old profile gained ports despite valid signature")
	}
}

func TestPortV6DiscoveryRequiresEnabledSignedProfileAndCopiesEffectiveTenantPolicy(t *testing.T) {
	for _, version := range []string{"v1", "v3", "v4", "v5", "v6"} {
		for _, enabled := range []bool{false, true} {
			m := &Manager{config: Config{Backend: "firecracker-linux"}, backend: FirecrackerLinuxBackend{PortForward: enabled}, manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/" + version, Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}, digestSHA256: strings.Repeat("a", 64)}}
			report, err := m.Capabilities()
			if err != nil {
				t.Fatal(err)
			}
			want := version == "v6" && enabled
			if report.Features.PortForward != want || (report.Limits.PortConnections == 8) != want {
				t.Fatal(version, enabled, report)
			}
			if !want {
				continue
			}
			for _, verb := range []string{"POST", "GET", "DELETE"} {
				if !slices.Contains(report.Methods, verb+" /v2/sessions/{id}/ports/{port}/connections/{connection}") {
					t.Fatal("missing port route", verb)
				}
			}
			if report.Limits.PortConnectionIDs != 256 || report.Limits.PortFrameBytes != 16384 || report.Limits.PortMaxBytes != 67108864 || report.Limits.PortTimeoutMS != 300000 {
				t.Fatal(report.Limits)
			}
			original, _ := cloneCapabilityReport(report)
			policy := &PortPolicy{AllowedPorts: []PortRange{{1024, 65535}}, MaxConcurrent: 3, Preview: true}
			tenant := &tenantRuntime{policy: TenantPolicy{Ports: policy, AllowedEntrypoints: []string{"*"}}}
			report.restrictEntrypoints(tenant)
			if !report.Features.PortForward || report.PortForwardPolicy.Preview || report.Limits.PortTenantConnections != 3 || !slices.Equal(report.PortForwardPolicy.AllowedPorts, []PortRange{{1024, 3127}, {3129, 65535}}) {
				t.Fatal(report)
			}
			report.PortForwardPolicy.AllowedPorts[0].From = 2000
			if policy.AllowedPorts[0].From != 1024 || original.PortForwardPolicy != nil || !original.Features.PortForward {
				t.Fatal("filtered discovery mutated source")
			}
			for _, ports := range []*PortPolicy{nil, {AllowedPorts: []PortRange{}, MaxConcurrent: 1}, {AllowedPorts: []PortRange{{3128, 3128}}, MaxConcurrent: 1}} {
				copy, _ := cloneCapabilityReport(original)
				tenant.policy.Ports = ports
				copy.restrictEntrypoints(tenant)
				if copy.Features.PortForward || copy.PortForwardPolicy != nil || copy.Limits.PortConnections != 0 {
					t.Fatal("denied policy advertised port", copy)
				}
				for _, method := range copy.Methods {
					if strings.Contains(method, "/ports/") {
						t.Fatal("denied policy advertised route")
					}
				}
			}
		}
	}
}
