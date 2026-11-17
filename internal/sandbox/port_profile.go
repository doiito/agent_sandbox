package sandbox

import "slices"

func portManifestProtocol(protocol string) bool {
	return protocol == "osv-sandbox-artifacts/v6" || protocol == "osv-sandbox-artifacts/v7" || protocol == "osv-sandbox-artifacts/v8"
}

// Port forwarding never becomes implicit for old v4/v5 templates.
func (m *Manager) hasLinuxPortFeature() bool {
	return m != nil && m.config.Backend == "firecracker-linux" && m.manifest != nil &&
		portManifestProtocol(m.manifest.Protocol) && m.manifest.Backend == "firecracker-linux" &&
		validSHA256Hex(m.manifest.digestSHA256) && slices.Contains(m.manifest.AgentFeatures, "port-forward-v1")
}
