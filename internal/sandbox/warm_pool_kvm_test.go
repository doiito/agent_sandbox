package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Startup diagnosis against an installed signed guest. This bypasses HTTP
// and is deliberately separate from the public pool E2E and performance gate.
func TestWarmPoolStartupAndBindingOnKVM(t *testing.T) {
	path := os.Getenv("OSV_WARM_POOL_KVM_CONFIG")
	if path == "" {
		t.Skip("set OSV_WARM_POOL_KVM_CONFIG to an idle isolated fixture")
	}
	if os.Geteuid() != 0 || !strings.Contains(path, "/osv-offline-validation-") {
		t.Fatal("requires isolated root fixture")
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.WarmPool == nil || !c.WarmPool.Enabled {
		t.Fatal("requires enabled signed pool")
	}
	m, err := NewManager(c)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := OpenAuditLog(c.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		_ = audit.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.StartWarmPool(ctx, audit); err != nil {
		t.Fatal(err)
	}
	m.pool.mu.Lock()
	first := m.pool.profiles[0].ready[0].id
	m.pool.mu.Unlock()
	s, err := m.StartSession(ctx, SessionCreateRequest{Backend: c.Backend, ArtifactManifestSHA256: m.manifest.digestSHA256, MemoryMiB: 128, VCPUs: 1, TTLMS: 10000,
		InputFiles: []InputFile{{Path: "prompt", Data: []byte("kvm-pool")}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.instance.id != first || s.info.StartupMode != "warm" {
		t.Fatal("session did not claim the already booted VM")
	}
	r, err := s.Run(ctx, SessionCommandRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "cat /input/prompt; if printf bad > /input/prompt; then exit 31; fi"}, TimeoutMS: 3000})
	var guest struct {
		Stdout string `json:"stdout"`
	}
	if err != nil || r.RunResult.State != "succeeded" || json.Unmarshal(r.RunResult.GuestResult, &guest) != nil || guest.Stdout != "kvm-pool" {
		t.Fatalf("bound session failed: state=%s error=%v", r.RunResult.State, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	job, err := m.Run(ctx, RunRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "printf warmed-job"}, MemoryMiB: 256, VCPUs: 1, TimeoutMS: 10000})
	if err != nil || job.State != "succeeded" || job.StartupMode != "warm" || json.Unmarshal(job.GuestResult, &guest) != nil || guest.Stdout != "warmed-job" {
		t.Fatalf("bound job failed: state=%s mode=%s error=%v", job.State, job.StartupMode, err)
	}
	t.Logf("actual prebooted VM claimed; session startup_us=%d job startup_us=%d", s.info.StartupDurationUS, job.StartupDurationUS)
}
