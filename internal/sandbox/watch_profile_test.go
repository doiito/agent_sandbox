package sandbox

import (
	"strings"
	"testing"
)

func TestLinuxWatchSignedProfileKeepsProxyIndependent(t *testing.T) {
	for _, features := range [][]string{{"workspace-watch-v1"}, {"vsock-proxy-v1", "workspace-watch-v1"}} {
		profile := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v4", Backend: "firecracker-linux", AgentFeatures: features}
		if err := profile.ValidateProfile("firecracker-linux", nil); err != nil {
			t.Fatal(err)
		}
		manager := &Manager{config: Config{Backend: "firecracker-linux"}, manifest: &profile}
		if !manager.hasLinuxWatchFeature() || manager.hasLinuxProxyFeature() != (len(features) == 2) {
			t.Fatal("signed Linux features were conflated")
		}
		profile.Protocol = "osv-sandbox-artifacts/v3"
		if profile.ValidateProfile("firecracker-linux", nil) == nil || manager.hasLinuxWatchFeature() {
			t.Fatal("legacy profile gained workspace watch")
		}
	}
	for _, features := range [][]string{nil, {"vsock-proxy-v1"}, {"workspace-watch-v1", "workspace-watch-v1"}, {"workspace-watch-v1", "vsock-proxy-v1"}, {"unknown", "workspace-watch-v1"}} {
		profile := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v4", Backend: "firecracker-linux", AgentFeatures: features}
		if profile.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatalf("invalid signed feature set accepted: %v", features)
		}
	}
	profile := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v4", Backend: "firecracker-osv", AgentFeatures: []string{"workspace-watch-v1"}}
	if profile.ValidateProfile("firecracker-osv", []string{"/python3.12.so"}) == nil {
		t.Fatal("OSv gained a Linux watch feature")
	}
}

func TestDirectoryWatchCapabilitiesAreBoundToActualSignedTemplate(t *testing.T) {
	for _, protocol := range []string{"osv-sandbox-artifacts/v1", "osv-sandbox-artifacts/v3", "osv-sandbox-artifacts/v4"} {
		for _, enabled := range []bool{false, true} {
			m := &Manager{config: Config{Backend: "firecracker-linux"}, backend: FirecrackerLinuxBackend{FileWatch: enabled}, manifest: &SignedArtifactManifest{Protocol: protocol, Backend: "firecracker-linux", AgentFeatures: []string{"workspace-watch-v1"}, digestSHA256: strings.Repeat("a", 64)}}
			report, err := m.Capabilities()
			if err != nil {
				t.Fatal(err)
			}
			want := protocol == "osv-sandbox-artifacts/v4" && enabled
			if report.Features.FileWatch != want || report.Features.RecursiveFileWatch != want || report.Features.FileWatchEntry != want || (report.Limits.FileWatchActive == 4) != want {
				t.Fatal("watch capability is not bound to template and backend", protocol, enabled, report.Features)
			}
		}
	}
}
