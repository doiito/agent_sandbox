package sandbox

import (
	"errors"
	"slices"
)

// v8 adds only the workspace artifact transport. Existing feature combinations
// retain their v1-v7 validators, including all runtime and inference bindings.
func (m SignedArtifactManifest) validateWorkspaceArtifactProfile(backend string, entrypoints []string) error {
	if backend != "firecracker-linux" || m.Backend != backend ||
		!slices.Contains(m.AgentFeatures, "workspace-artifacts-v1") {
		return errors.New("v8 requires a signed Linux workspace-artifacts-v1 profile")
	}
	previous := ""
	features := make([]string, 0, len(m.AgentFeatures))
	for _, feature := range m.AgentFeatures {
		if feature <= previous {
			return errors.New("unsupported, unsorted or duplicate v8 feature")
		}
		previous = feature
		if feature != "workspace-artifacts-v1" {
			features = append(features, feature)
		}
	}
	m.AgentFeatures = features
	m.Protocol = "osv-sandbox-artifacts/v1"
	switch {
	case m.GuestInference != nil || slices.Contains(features, "remote-infer-v1"):
		m.Protocol = "osv-sandbox-artifacts/v7"
	case slices.Contains(features, "port-forward-v1"):
		m.Protocol = "osv-sandbox-artifacts/v6"
	case slices.Contains(features, "code-contexts-v1"):
		m.Protocol = "osv-sandbox-artifacts/v5"
	case slices.Contains(features, "workspace-watch-v1"):
		m.Protocol = "osv-sandbox-artifacts/v4"
	case len(features) != 0:
		m.Protocol = "osv-sandbox-artifacts/v3"
	default:
		m.Backend = ""
	}
	return m.ValidateProfile(backend, entrypoints)
}

func (m *Manager) hasLinuxArtifactFeature() bool {
	return m != nil && m.config.Backend == "firecracker-linux" && m.manifest != nil &&
		m.manifest.Protocol == "osv-sandbox-artifacts/v8" && m.manifest.Backend == "firecracker-linux" &&
		validSHA256Hex(m.manifest.digestSHA256) && slices.Contains(m.manifest.AgentFeatures, "workspace-artifacts-v1")
}
