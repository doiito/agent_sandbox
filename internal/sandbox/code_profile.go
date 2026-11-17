package sandbox

import (
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
)

// SignedCodeRuntime binds the interpreter contract to the signed image. The
// inventory and script hashes are independently produced by the image builder.
type SignedCodeRuntime struct {
	Architecture           string            `json:"architecture"`
	KernelProtocol         string            `json:"kernel_protocol"`
	PythonVersion          string            `json:"python_version"`
	NodeVersion            string            `json:"node_version"`
	TypeScriptVersion      string            `json:"typescript_version"`
	PrewarmLanguage        string            `json:"prewarm_language"`
	RuntimeInventorySHA256 string            `json:"runtime_inventory_sha256"`
	KernelScriptsSHA256    map[string]string `json:"kernel_scripts_sha256"`
	MinimumCPUFeatures     []string          `json:"minimum_cpu_features"`
}

// Validate checks the public runtime contract independently of a full signed
// artifact manifest. Gateways already receive authenticated capabilities.
func (r *SignedCodeRuntime) Validate() error { return r.validate() }

func (r *SignedCodeRuntime) validate() error {
	if r == nil || r.KernelProtocol != "osv-code-kernel/v2" || r.PythonVersion != "3.12.16" || r.NodeVersion != "22.23.4" ||
		r.TypeScriptVersion != "5.9.3" || !codeLanguage(r.PrewarmLanguage) || !validSHA256Hex(r.RuntimeInventorySHA256) || len(r.KernelScriptsSHA256) != 2 ||
		!validSHA256Hex(r.KernelScriptsSHA256["python.py"]) || !validSHA256Hex(r.KernelScriptsSHA256["node.cjs"]) {
		return errors.New("invalid signed code runtime profile")
	}
	features := []string{"sse4_1"}
	if r.Architecture == "arm64" {
		features = []string{"asimd"}
	} else if r.Architecture != "amd64" {
		return errors.New("unsupported code runtime architecture")
	}
	if !slices.Equal(features, r.MinimumCPUFeatures) {
		return errors.New("code runtime CPU baseline is missing or unsupported")
	}
	return nil
}
func (r *SignedCodeRuntime) clone() *SignedCodeRuntime {
	if r == nil {
		return nil
	}
	copy := *r
	copy.MinimumCPUFeatures = slices.Clone(r.MinimumCPUFeatures)
	copy.KernelScriptsSHA256 = map[string]string{}
	for name, digest := range r.KernelScriptsSHA256 {
		copy.KernelScriptsSHA256[name] = digest
	}
	return &copy
}
func (r *SignedCodeRuntime) validateHost(arch, cpuinfo string) error {
	if err := r.validate(); err != nil {
		return err
	}
	if r.Architecture != arch {
		return errors.New("signed code template architecture differs from host")
	}
	key := "flags"
	if arch == "arm64" {
		key = "Features"
	}
	count := 0
	for _, line := range strings.Split(cpuinfo, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		count++
		features := strings.Fields(value)
		for _, feature := range r.MinimumCPUFeatures {
			if !slices.Contains(features, feature) {
				return errors.New("host CPU does not meet signed code template baseline")
			}
		}
	}
	if count == 0 {
		return errors.New("host CPU features unavailable for signed code template")
	}
	return nil
}
func (m *Manager) hasLinuxCodeFeature() bool {
	return m.config.Backend == "firecracker-linux" && m.manifest != nil && (m.manifest.Protocol == "osv-sandbox-artifacts/v5" || m.manifest.Protocol == "osv-sandbox-artifacts/v6" || m.manifest.Protocol == "osv-sandbox-artifacts/v7" || m.manifest.Protocol == "osv-sandbox-artifacts/v8") &&
		m.manifest.CodeRuntime != nil && slices.Contains(m.manifest.AgentFeatures, "code-contexts-v1")
}
func (m *Manager) enableLinuxCodeFeature() error {
	if !m.hasLinuxCodeFeature() {
		return nil
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return err
	}
	if err = m.manifest.CodeRuntime.validateHost(runtime.GOARCH, string(data)); err != nil {
		return err
	}
	backend := m.backend.(FirecrackerLinuxBackend)
	backend.CodeContexts = true
	backend.CodePrewarm = m.manifest.CodeRuntime.PrewarmLanguage
	m.backend = backend
	return nil
}
