package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"runtime"
)

type WarmPoolProfile struct {
	Name      string `json:"name"`
	MemoryMiB int    `json:"memory_mib"`
	VCPUs     int    `json:"vcpus"`
	MinReady  int    `json:"min_ready"`
	MaxReady  int    `json:"max_ready"`
}

type WarmPoolConfig struct {
	Enabled               bool              `json:"enabled"`
	OnMiss                string            `json:"on_miss"`
	MaxBooting            int               `json:"max_booting"`
	RefillPerSecond       float64           `json:"refill_per_second"`
	RefillBurst           int               `json:"refill_burst"`
	MaxIdleAgeMS          int               `json:"max_idle_age_ms"`
	HealthIntervalMS      int               `json:"health_interval_ms"`
	CheckTimeoutMS        int               `json:"check_timeout_ms"`
	BootTimeoutMS         int               `json:"boot_timeout_ms"`
	CheckoutTimeoutMS     int               `json:"checkout_timeout_ms"`
	StartupTimeoutMS      int               `json:"startup_timeout_ms"`
	MinAvailableMemoryMiB int64             `json:"min_available_memory_mib"`
	Profiles              []WarmPoolProfile `json:"profiles"`
}

func (c *Config) applyWarmPoolDefaults() {
	p := c.WarmPool
	if p == nil || !p.Enabled {
		return
	}
	if p.OnMiss == "" {
		p.OnMiss = "cold"
	}
	if p.MaxBooting == 0 {
		p.MaxBooting = min(2, c.VMCapacity.MaxInstances)
	}
	if p.RefillPerSecond == 0 {
		p.RefillPerSecond = 2
	}
	if p.RefillBurst == 0 {
		p.RefillBurst = 2
	}
	if p.MaxIdleAgeMS == 0 {
		p.MaxIdleAgeMS = 120000
	}
	if p.HealthIntervalMS == 0 {
		p.HealthIntervalMS = 1000
	}
	if p.CheckTimeoutMS == 0 {
		p.CheckTimeoutMS = 500
	}
	if p.BootTimeoutMS == 0 {
		p.BootTimeoutMS = 10000
	}
	if p.CheckoutTimeoutMS == 0 {
		p.CheckoutTimeoutMS = 10000
	}
	if p.StartupTimeoutMS == 0 {
		p.StartupTimeoutMS = 30000
	}
	if p.MinAvailableMemoryMiB == 0 {
		p.MinAvailableMemoryMiB = 128
	}
}

func (c Config) validateWarmPool() error {
	p := c.WarmPool
	if p == nil || !p.Enabled {
		return nil
	}
	if (c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv") || c.Jailer == nil || c.ArtifactManifest == nil {
		return errors.New("warm_pool requires a jailed, signed Linux or OSv template")
	}
	if p.OnMiss != "cold" && p.OnMiss != "reject" {
		return errors.New("warm_pool.on_miss must be cold or reject")
	}
	if p.MaxBooting < 1 || p.MaxBooting > min(16, c.VMCapacity.MaxInstances) ||
		math.IsNaN(p.RefillPerSecond) || math.IsInf(p.RefillPerSecond, 0) ||
		p.RefillPerSecond < 0.1 || p.RefillPerSecond > 100 || p.RefillBurst < 1 || p.RefillBurst > 16 {
		return errors.New("invalid warm_pool refill concurrency or rate")
	}
	if p.MaxIdleAgeMS < 1000 || p.MaxIdleAgeMS > 240000 ||
		p.HealthIntervalMS < 100 || p.HealthIntervalMS > 30000 ||
		p.CheckTimeoutMS < 10 || p.CheckTimeoutMS > 5000 ||
		p.BootTimeoutMS < 500 || p.BootTimeoutMS > 30000 ||
		p.CheckoutTimeoutMS < p.CheckTimeoutMS || p.CheckoutTimeoutMS > 30000 ||
		p.StartupTimeoutMS < 1000 || p.StartupTimeoutMS > 120000 ||
		p.MinAvailableMemoryMiB < 1 || p.MinAvailableMemoryMiB > 1<<30 {
		return errors.New("invalid warm_pool lifetime, deadline or memory threshold")
	}
	if len(p.Profiles) == 0 || len(p.Profiles) > 32 {
		return errors.New("warm_pool requires 1 to 32 fixed profiles")
	}
	names, sizes := map[string]bool{}, map[[2]int]bool{}
	var instances, memory, cpus, pids int64
	for _, profile := range p.Profiles {
		if !safeTenantID(profile.Name) || len(profile.Name) > 32 || names[profile.Name] || sizes[[2]int{profile.MemoryMiB, profile.VCPUs}] ||
			profile.MemoryMiB < c.Limits.MinMemoryMiB || profile.MemoryMiB > c.Limits.MaxMemoryMiB ||
			profile.VCPUs < 1 || profile.VCPUs > c.Limits.MaxVCPUs ||
			profile.MinReady < 0 || profile.MaxReady < max(1, profile.MinReady) || profile.MaxReady > 64 {
			return errors.New("invalid or duplicate warm_pool profile")
		}
		names[profile.Name], sizes[[2]int{profile.MemoryMiB, profile.VCPUs}] = true, true
		count := int64(profile.MinReady)
		instances += count
		memory += count * (int64(profile.MemoryMiB) + capacityOverhead(c))
		cpus += count * int64(profile.VCPUs)
		pids += count * capacityPids(c)
	}
	if instances == 0 || instances > int64(c.VMCapacity.MaxInstances) || memory > c.VMCapacity.ReservedMemoryMiB ||
		cpus > c.VMCapacity.ReservedVCPUs || pids > c.VMCapacity.ReservedPids {
		return errors.New("warm_pool minimum reservations do not fit vm_capacity")
	}
	return nil
}

// Each manager owns immutable policy objects. Callers cannot mutate pool keys
// or the backend's security parameters through their original Config pointers.
func (c Config) snapshot() Config {
	if c.OTLP != nil {
		value := *c.OTLP
		value.Signals = append([]string(nil), value.Signals...)
		if value.TraceSamplePermille != nil {
			sample := *value.TraceSamplePermille
			value.TraceSamplePermille = &sample
		}
		c.OTLP = &value
	}
	if c.Templates != nil {
		items := make([]TemplateConfig, len(c.Templates))
		for i, item := range c.Templates {
			items[i] = item.snapshot()
		}
		c.Templates = items
	}
	if c.Jailer != nil {
		value := *c.Jailer
		c.Jailer = &value
	}
	if c.LinuxGuest != nil {
		value := *c.LinuxGuest
		c.LinuxGuest = &value
	}
	if c.VMCapacity != nil {
		value := *c.VMCapacity
		c.VMCapacity = &value
	}
	if c.ArtifactManifest != nil {
		value := *c.ArtifactManifest
		c.ArtifactManifest = &value
	}
	if c.TLS != nil {
		value := *c.TLS
		c.TLS = &value
	}
	if c.WarmPool != nil {
		value := *c.WarmPool
		value.Profiles = append([]WarmPoolProfile(nil), value.Profiles...)
		c.WarmPool = &value
	}
	c.AllowedEntrypoints = append([]string(nil), c.AllowedEntrypoints...)
	return c
}

func (m *Manager) warmProfileKey(memoryMiB, vcpus int) string {
	protocol := pristineProtocolForBackend(m.config.Backend)
	if m.hasOSvInputFeature() {
		protocol = "OSP2/revision-2/OSJ1"
	}
	// The authenticated manifest binds the VMM, jailer, kernel/rootfs and SBOM
	// guest bytes. Policy/arch/spec are additional, immutable key inputs.
	data, _ := json.Marshal(struct {
		Backend          string
		Manifest         string
		Arch             string
		Protocol         string
		MemoryMiB, VCPUs int
		Jailer           *JailerConfig
		Guest            *LinuxGuestConfig
		Limits           Limits
		Entrypoints      []string
		Network          string
	}{m.config.Backend, m.manifest.digestSHA256, runtime.GOARCH, protocol, memoryMiB, vcpus,
		m.config.Jailer, m.config.LinuxGuest, m.config.Limits, m.config.AllowedEntrypoints, "none"})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
