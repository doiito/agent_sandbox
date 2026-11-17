package sandbox

import (
	"math"
	"strings"
	"testing"
)

func warmConfigForTest() Config {
	c := testConfig()
	c.Backend = "firecracker-linux"
	c.LinuxGuest = &LinuxGuestConfig{}
	c.Jailer = &JailerConfig{UID: 230000, GID: 230000, IdentityPoolSize: 4, MemoryOverheadMiB: 128, PidsMax: 64}
	c.ArtifactManifest = &ArtifactManifestConfig{}
	c.VMCapacity = nil
	c.WarmPool = &WarmPoolConfig{Enabled: true, Profiles: []WarmPoolProfile{{Name: "small", MemoryMiB: 128, VCPUs: 1, MinReady: 1, MaxReady: 2}}}
	c.ApplyDefaults()
	return c
}

func TestWarmPoolConfigurationRejectsUnsafeOrImpossiblePools(t *testing.T) {
	if err := warmConfigForTest().validateWarmPool(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"backend", "unsigned", "duplicate", "memory", "instances", "cpu", "pids", "rate", "idle", "deadline", "empty"} {
		t.Run(name, func(t *testing.T) {
			c := warmConfigForTest()
			switch name {
			case "backend":
				c.Backend = "qemu"
			case "unsigned":
				c.ArtifactManifest = nil
			case "duplicate":
				c.WarmPool.Profiles = append(c.WarmPool.Profiles, c.WarmPool.Profiles[0])
			case "memory":
				c.VMCapacity.ReservedMemoryMiB = 1
			case "instances":
				c.WarmPool.Profiles[0].MinReady = 5
				c.WarmPool.Profiles[0].MaxReady = 5
			case "cpu":
				c.VMCapacity.ReservedVCPUs = 0
			case "pids":
				c.VMCapacity.ReservedPids = 0
			case "rate":
				c.WarmPool.RefillPerSecond = math.NaN()
			case "idle":
				c.WarmPool.MaxIdleAgeMS = 300000
			case "deadline":
				c.WarmPool.CheckoutTimeoutMS = 1
			case "empty":
				c.WarmPool.Profiles = nil
			}
			if err := c.validateWarmPool(); err == nil {
				t.Fatal("unsafe pool accepted")
			}
		})
	}
}

func TestWarmPoolPolicyAndReturnedConfigCannotMutateProfileKey(t *testing.T) {
	original := warmConfigForTest()
	m := &Manager{config: original.snapshot(), manifest: &SignedArtifactManifest{digestSHA256: strings.Repeat("a", 64)}}
	key := m.warmProfileKey(128, 1)
	original.Jailer.UID++
	original.WarmPool.Profiles[0].MemoryMiB = 256
	original.AllowedEntrypoints[0] = "/other"
	returned := m.Config()
	returned.Jailer.GID++
	returned.WarmPool.Profiles[0].MaxReady = 64
	returned.AllowedEntrypoints[0] = "/changed"
	if key != m.warmProfileKey(128, 1) || m.config.WarmPool.Profiles[0].MemoryMiB != 128 || m.config.WarmPool.Profiles[0].MaxReady != 2 {
		t.Fatal("external configuration mutated manager policy")
	}
	if key == m.warmProfileKey(256, 1) {
		t.Fatal("different VM specs shared a key")
	}
	m.manifest.digestSHA256 = strings.Repeat("b", 64)
	if key == m.warmProfileKey(128, 1) {
		t.Fatal("different signed generations shared a key")
	}
}
