package sandbox

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mixedFakePools(t *testing.T) (*Manager, *Manager, *warmPool, *warmPool) {
	t.Helper()
	root, p := fakeWarmManager(t, 2)
	child, q := fakeWarmManager(t, 2)
	root.config.Limits.MaxConcurrent = 2
	root.capacity = newResourceLedger(root.config)
	child.owner, child.capacity = root, root.capacity
	child.config.RunRoot = root.config.RunRoot
	child.config.TemplateID = "second"
	child.manifest.digestSHA256 = strings.Repeat("b", 64)
	q.manifest = child.manifest.digestSHA256
	for _, profile := range q.profiles {
		profile.key = child.warmProfileKey(profile.config.MemoryMiB, profile.config.VCPUs)
	}
	c := newTemplateCatalog(root, []*Manager{root, child})
	root.catalog, child.catalog = c, c
	return root, child, p, q
}

func TestCatalogPoolSharesRefillRateBootLimitAndMinimumFairness(t *testing.T) {
	root, _, p, q := mixedFakePools(t)
	root.config.WarmPool.MaxBooting = 1
	root.config.WarmPool.RefillPerSecond = 5
	root.config.WarmPool.RefillBurst = 1
	root.catalog.tokens = 1
	var running, maximum atomic.Int32
	entered := make(chan time.Time, 8)
	for _, pool := range []*warmPool{p, q} {
		old := pool.boot
		pool.boot = func(ctx context.Context, profile WarmPoolProfile, reservation *vmReservation) (*vmInstance, error) {
			active := running.Add(1)
			defer running.Add(-1)
			for {
				prev := maximum.Load()
				if active <= prev || maximum.CompareAndSwap(prev, active) {
					break
				}
			}
			entered <- time.Now()
			return old(ctx, profile, reservation)
		}
	}
	startFakeWarmPool(t, root)
	first, second := <-entered, <-entered
	if maximum.Load() != 1 || second.Sub(first) < 150*time.Millisecond {
		t.Fatal("per-template refill multiplied the global rate or boot limit", maximum.Load(), second.Sub(first))
	}
	snapshot, _ := root.WarmPoolStatus()
	if !snapshot.Healthy || len(snapshot.Profiles) != 2 || snapshot.Profiles[0].Ready != 1 || snapshot.Profiles[1].Ready != 1 || snapshot.Profiles[1].TemplateID != "second" || snapshot.Profiles[1].Name != "second/small" {
		t.Fatal("catalog starved a minimum or lost pool identity", snapshot)
	}
	if capacity := root.Capacity(); capacity.Active != 0 || capacity.Instances != 2 {
		t.Fatal("capacity counted one ledger multiple times", capacity)
	}
}

func TestCatalogPoolForegroundReclaimsOtherTemplateAndShutdownOwnsAll(t *testing.T) {
	root, child, p, q := mixedFakePools(t)
	// The helper processes do not drop uid; this verifies the real shared
	// reservation/owner state. Physical VMM identity is an additional KVM gate.
	policy := root.config.snapshot()
	policy.Jailer = &JailerConfig{UID: 230000, GID: 230000, IdentityPoolSize: 2, MemoryOverheadMiB: 128, PidsMax: 64}
	policy.VMCapacity.ReservedPids = 128
	root.capacity = newResourceLedger(policy)
	child.capacity = root.capacity
	startFakeWarmPool(t, root)
	q.mu.Lock()
	old := q.profiles[0].ready[0]
	q.mu.Unlock()
	prepared := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer prepared.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	physical, active, err := child.reserveCold(384, 1, ctx)
	if err != nil {
		t.Fatal("cold demand did not reclaim another template's pristine VM", err)
	}
	defer active.release()
	v, err := child.startVM(ctx, helperBackend{mode: "pool-wait"}, RunRequest{Args: []string{"--sandbox-job-id", "abcdef0123456789abcdef01"}}, physical)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	if old.ctx.Err() == nil || physical.identity.uid == prepared.instance.physical.identity.uid || root.Capacity().Instances != 2 || root.Capacity().Active != 2 || root.VMInstances().States[string(vmActive)]+root.VMInstances().States[string(vmBooting)] != 2 {
		t.Fatal("shared ownership or unique reservations failed", root.Capacity(), root.VMInstances())
	}
	if err := v.Destroy(); err != nil {
		t.Fatal(err)
	}
	active.release()
	if err := prepared.close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if s := child.Capacity(); s.Instances != 0 || s.Active != 0 || s.AvailableIdentities != 2 || !child.VMInstances().Stopping {
		t.Fatal("root shutdown missed a child resource", s, child.VMInstances())
	}
}
