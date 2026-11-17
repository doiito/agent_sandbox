package sandbox

import (
	"errors"
	"time"
)

type TemplateSelector struct {
	Backend                string `json:"backend"`
	ArtifactManifestSHA256 string `json:"artifact_manifest_sha256"`
}

type TemplateReport struct {
	ID              string           `json:"id"`
	Available       bool             `json:"available"`
	UnavailableCode string           `json:"unavailable_code,omitempty"`
	Capabilities    CapabilityReport `json:"capabilities"`
}

type TemplateCatalogReport struct {
	Protocol          string           `json:"protocol"`
	DefaultTemplateID string           `json:"default_template_id"`
	Templates         []TemplateReport `json:"templates"`
}

func (m *Manager) lifecycleOwner() *Manager {
	if m.owner != nil {
		return m.owner
	}
	return m
}

func (m *Manager) templateMembers() []*Manager {
	if m.catalog != nil {
		return m.catalog.members
	}
	return []*Manager{m}
}

func (m *Manager) selectTemplate(backend, digest string) (*Manager, error) {
	if backend == "" && digest == "" {
		return m, nil
	}
	if backend == "" || !validSHA256Hex(digest) {
		return nil, ErrInvalidSelector
	}
	for _, member := range m.templateMembers() {
		if member.manifest != nil && member.config.Backend == backend && member.manifest.digestSHA256 == digest {
			return member, nil
		}
	}
	return nil, ErrTemplateMismatch
}

func (m *Manager) CapabilitiesFor(backend, digest string) (CapabilityReport, error) {
	if backend == "" && digest == "" && m.catalog == nil {
		return m.Capabilities()
	}
	selected, err := m.selectTemplate(backend, digest)
	if err != nil {
		return CapabilityReport{}, err
	}
	if err := selected.artifactAvailability(time.Now()); err != nil {
		return CapabilityReport{}, err
	}
	return selected.Capabilities()
}

func (m *Manager) TemplateCatalog() (TemplateCatalogReport, error) {
	if m.isStopping() {
		return TemplateCatalogReport{}, ErrUnavailable
	}
	report := TemplateCatalogReport{Protocol: "osv-sandbox-template-catalog/v1", DefaultTemplateID: m.lifecycleOwner().config.defaultTemplateID(), Templates: []TemplateReport{}}
	for _, member := range m.templateMembers() {
		capability, err := member.Capabilities()
		if err == nil {
			err = member.artifactAvailability(time.Now())
		}
		entry := TemplateReport{ID: member.config.defaultTemplateID(), Available: err == nil, Capabilities: capability}
		if err != nil {
			entry.UnavailableCode = "policy_unavailable"
			entry.Capabilities = CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: member.config.Backend, ArtifactAuthenticated: member.manifest != nil,
				Methods: []string{}, AllowedEntrypoints: append([]string(nil), member.config.AllowedEntrypoints...)}
			if member.manifest != nil {
				entry.Capabilities.ArtifactManifestSHA256 = member.manifest.digestSHA256
			}
			// Existing code sessions retain their immutable runtime contract and
			// original lease. Availability here controls admission of new VMs.
			if capability.Features.CodeContexts {
				entry.Capabilities.Features.CodeContexts = true
				entry.Capabilities.Features.Sessions = true
				entry.Capabilities.ArtifactManifestProtocol = capability.ArtifactManifestProtocol
				entry.Capabilities.CodeRuntime = capability.CodeRuntime.clone()
				entry.Capabilities.CodeLanguages = append([]string{}, capability.CodeLanguages...)
				entry.Capabilities.Limits = capability.Limits
			}
		}
		if entry.Capabilities.ArtifactAuthenticated {
			report.Templates = append(report.Templates, entry)
		}
	}
	return report, nil
}

func capabilitiesFor(runner Runner, backend, digest string) (CapabilityReport, error) {
	if source, ok := runner.(interface {
		CapabilitiesFor(string, string) (CapabilityReport, error)
	}); ok {
		return source.CapabilitiesFor(backend, digest)
	}
	if (backend == "") != (digest == "") || digest != "" && !validSHA256Hex(digest) {
		return CapabilityReport{}, ErrInvalidSelector
	}
	report, err := runner.Capabilities()
	if err != nil {
		return CapabilityReport{}, err
	}
	if backend != "" && (backend != report.Backend || digest != report.ArtifactManifestSHA256) {
		return CapabilityReport{}, ErrTemplateMismatch
	}
	return report, nil
}

func templateCatalogFor(runner Runner) (TemplateCatalogReport, error) {
	if source, ok := runner.(interface {
		TemplateCatalog() (TemplateCatalogReport, error)
	}); ok {
		return source.TemplateCatalog()
	}
	capability, err := runner.Capabilities()
	if err != nil {
		return TemplateCatalogReport{}, err
	}
	if !capability.ArtifactAuthenticated {
		return TemplateCatalogReport{}, errors.New("authenticated templates unavailable")
	}
	return TemplateCatalogReport{Protocol: "osv-sandbox-template-catalog/v1", DefaultTemplateID: "default", Templates: []TemplateReport{{ID: "default", Available: true, Capabilities: capability}}}, nil
}
