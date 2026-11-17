package sandbox

import (
	"errors"
	"fmt"
)

// TemplateConfig overrides only template policy. Host ownership, capacity,
// identity allocation and refill policy remain properties of the service.
type TemplateConfig struct {
	ID                 string                  `json:"id"`
	Backend            string                  `json:"backend"`
	ArtifactRoot       string                  `json:"artifact_root"`
	Kernel             Artifact                `json:"kernel"`
	Image              Artifact                `json:"image"`
	ArtifactManifest   *ArtifactManifestConfig `json:"artifact_manifest"`
	AllowedEntrypoints []string                `json:"allowed_entrypoints"`
	LinuxGuest         *LinuxGuestConfig       `json:"linux_guest,omitempty"`
	Defaults           *Defaults               `json:"defaults,omitempty"`
	WarmProfiles       []WarmPoolProfile       `json:"warm_profiles,omitempty"`
}

func (t TemplateConfig) snapshot() TemplateConfig {
	t.AllowedEntrypoints = append([]string(nil), t.AllowedEntrypoints...)
	t.WarmProfiles = append([]WarmPoolProfile(nil), t.WarmProfiles...)
	if t.ArtifactManifest != nil {
		value := *t.ArtifactManifest
		t.ArtifactManifest = &value
	}
	if t.LinuxGuest != nil {
		value := *t.LinuxGuest
		t.LinuxGuest = &value
	}
	if t.Defaults != nil {
		value := *t.Defaults
		t.Defaults = &value
	}
	return t
}

func (c Config) defaultTemplateID() string {
	if c.TemplateID != "" {
		return c.TemplateID
	}
	return "default"
}

func (c Config) forTemplate(t TemplateConfig) Config {
	child := c.snapshot()
	child.Templates = nil
	child.TemplateID = t.ID
	child.Backend, child.ArtifactRoot = t.Backend, t.ArtifactRoot
	child.Kernel, child.Image = t.Kernel, t.Image
	child.ArtifactManifest = t.ArtifactManifest
	child.AllowedEntrypoints = t.AllowedEntrypoints
	child.LinuxGuest = t.LinuxGuest
	if t.Backend == "firecracker-linux" && t.LinuxGuest == nil && c.Backend == "firecracker-linux" {
		child.LinuxGuest = c.LinuxGuest
	}
	if t.Defaults != nil {
		child.Defaults = *t.Defaults
	}
	child.WarmPool = nil
	if len(t.WarmProfiles) != 0 && c.WarmPool != nil {
		pool := *c.WarmPool
		pool.Profiles = t.WarmProfiles
		child.WarmPool = &pool
	}
	child = child.snapshot()
	child.ApplyDefaults()
	return child
}

func validTemplateID(id string) bool { return len(id) <= 32 && safeTenantID(id) }

func (c Config) validateTemplates() error {
	if !validTemplateID(c.defaultTemplateID()) {
		return errors.New("template_id must be a safe identifier of at most 32 bytes")
	}
	if len(c.Templates) == 0 {
		return nil
	}
	if len(c.Templates) > 15 || !c.Production || c.ArtifactManifest == nil {
		return errors.New("templates requires a signed production service and at most 15 additional templates")
	}
	ids := map[string]bool{c.defaultTemplateID(): true}
	configs := []Config{c}
	for _, item := range c.Templates {
		if !validTemplateID(item.ID) || ids[item.ID] ||
			(item.Backend != "firecracker-linux" && item.Backend != "firecracker-osv") || item.ArtifactManifest == nil {
			return errors.New("invalid, unsigned or duplicate template")
		}
		ids[item.ID] = true
		if len(item.WarmProfiles) > 0 && (c.WarmPool == nil || !c.WarmPool.Enabled) {
			return errors.New("template warm_profiles requires the service warm_pool policy")
		}
		child := c.forTemplate(item)
		if err := child.Validate(); err != nil {
			return fmt.Errorf("template %s: %w", item.ID, err)
		}
		configs = append(configs, child)
	}
	var instances, memory, cpus, pids int64
	for _, config := range configs {
		if config.WarmPool == nil || !config.WarmPool.Enabled {
			continue
		}
		for _, profile := range config.WarmPool.Profiles {
			count := int64(profile.MinReady)
			instances += count
			memory += count * (int64(profile.MemoryMiB) + capacityOverhead(config))
			cpus += count * int64(profile.VCPUs)
			pids += count * capacityPids(config)
		}
	}
	v := c.VMCapacity
	if instances > int64(v.MaxInstances) || memory > v.ReservedMemoryMiB || cpus > v.ReservedVCPUs || pids > v.ReservedPids {
		return errors.New("all template warm_pool minimum reservations must fit the shared vm_capacity")
	}
	return nil
}
