package sandbox

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSessionArtifactV8ComposesExistingSignedFeatures(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		features := []string{"workspace-artifacts-v1"}
		for i, name := range []string{"code-contexts-v1", "port-forward-v1", "vsock-proxy-v1", "workspace-watch-v1"} {
			if mask&(1<<i) != 0 {
				features = append(features, name)
			}
		}
		slices.Sort(features)
		m := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v8", Backend: "firecracker-linux", AgentFeatures: features, digestSHA256: strings.Repeat("a", 64)}
		if mask&1 != 0 {
			m.CodeRuntime = testCodeProfile()
		}
		if err := m.ValidateProfile("firecracker-linux", nil); err != nil {
			t.Fatal(features, err)
		}
		manager := &Manager{config: Config{Backend: "firecracker-linux"}, manifest: &m}
		if !manager.hasLinuxArtifactFeature() || manager.hasLinuxCodeFeature() != (mask&1 != 0) || manager.hasLinuxPortFeature() != (mask&2 != 0) || manager.hasLinuxProxyFeature() != (mask&4 != 0) || manager.hasLinuxWatchFeature() != (mask&8 != 0) {
			t.Fatal("v8 lost or conflated existing features", features)
		}
	}
	m := inferenceV7Manifest("firecracker-linux")
	m.Protocol = "osv-sandbox-artifacts/v8"
	m.AgentFeatures = append(m.AgentFeatures, "workspace-artifacts-v1")
	if err := m.ValidateProfile("firecracker-linux", nil); err != nil {
		t.Fatal(err)
	}
	if !signedRemoteInferenceFeature("firecracker-linux", &m) {
		t.Fatal("v8 lost inference capability")
	}
	bom, _ := json.Marshal(inferenceV7BOM(m))
	if err := m.ValidateGuestInferenceSBOM(bom); err != nil {
		t.Fatal("v8 lost signed SDK/image BOM validation", err)
	}
	for _, edit := range []func(*SignedArtifactManifest){
		func(m *SignedArtifactManifest) { m.AgentFeatures = append(m.AgentFeatures, "workspace-artifacts-v1") },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"workspace-artifacts-v1", "unknown"} },
		func(m *SignedArtifactManifest) {
			m.AgentFeatures = []string{"workspace-watch-v1", "workspace-artifacts-v1"}
		},
		func(m *SignedArtifactManifest) { m.Backend = "firecracker-osv" },
		func(m *SignedArtifactManifest) { m.GuestInference = nil },
		func(m *SignedArtifactManifest) { m.CodeRuntime = nil },
	} {
		copy := m
		copy.AgentFeatures = slices.Clone(m.AgentFeatures)
		edit(&copy)
		if copy.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatal("invalid v8 accepted", copy.AgentFeatures)
		}
	}
	for _, protocol := range []string{"osv-sandbox-artifacts/v1", "osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7"} {
		m.Protocol = protocol
		if m.ValidateProfile("firecracker-linux", nil) == nil || (&Manager{config: Config{Backend: "firecracker-linux"}, manifest: &m}).hasLinuxArtifactFeature() {
			t.Fatal("legacy profile gained artifacts", protocol)
		}
	}
}
