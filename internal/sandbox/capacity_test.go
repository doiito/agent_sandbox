package sandbox

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
)

func capacityConfig() Config {
	c := Config{ArtifactRoot: "/unused", Backend: "firecracker-linux",
		Jailer:     &JailerConfig{UID: 230000, GID: 240000, IdentityPoolSize: 4},
		Limits:     Limits{MaxConcurrent: 2, MaxMemoryMiB: 512, MaxVCPUs: 4},
		VMCapacity: &VMCapacityConfig{MaxInstances: 4}}
	c.ApplyDefaults()
	return c
}

func TestCapacityPristineReservationsDoNotConsumeActiveSlots(t *testing.T) {
	c := capacityConfig()
	l := newResourceLedger(c)
	var physical []*vmReservation
	for i := 0; i < c.VMCapacity.MaxInstances; i++ {
		r, err := l.reservePhysical(128, 1)
		if err != nil {
			t.Fatal(err)
		}
		physical = append(physical, r)
	}
	if s := l.snapshot(); s.Active != 0 || s.Instances != 4 || s.AvailableIdentities != 0 {
		t.Fatalf("pristine reservation accounting: %+v", s)
	}
	// Checkout does not request a second physical slot or identity, even with
	// all physical slots occupied by pristine instances.
	a, err := l.reserveActive()
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.reserveActive()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.reserveActive(); !errors.Is(err, ErrBusy) {
		t.Fatalf("active limit: %v", err)
	}
	a.release()
	b.release()
	if _, _, err := l.reserveCold(128, 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("cold physical limit: %v", err)
	}
	if l.snapshot().Active != 0 {
		t.Fatal("failed cold reservation consumed active capacity")
	}
	var wg sync.WaitGroup
	for _, r := range physical {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(r *vmReservation) { defer wg.Done(); r.release() }(r)
		}
	}
	wg.Wait()
	if s := l.snapshot(); s != (VMCapacitySnapshot{AvailableIdentities: 4}) {
		t.Fatalf("release imbalance: %+v", s)
	}
}

func TestCapacityBudgetsRejectIndependentlyWithoutPartialAdmission(t *testing.T) {
	for _, dimension := range []string{"memory", "vcpu", "pids"} {
		t.Run(dimension, func(t *testing.T) {
			c := capacityConfig()
			switch dimension {
			case "memory":
				c.VMCapacity.ReservedMemoryMiB = 128 + int64(c.Jailer.MemoryOverheadMiB)
			case "vcpu":
				c.VMCapacity.ReservedVCPUs = 1
			case "pids":
				c.VMCapacity.ReservedPids = int64(c.Jailer.PidsMax)
			}
			if err := c.validateCapacity(); err != nil {
				t.Fatal(err)
			}
			l := newResourceLedger(c)
			ready, err := l.reservePhysical(128, 1)
			if err != nil {
				t.Fatal(err)
			}
			before := l.snapshot()
			if _, _, err := l.reserveCold(128, 1); !errors.Is(err, ErrBusy) {
				t.Fatalf("over %s admitted: %v", dimension, err)
			}
			if after := l.snapshot(); before != after {
				t.Fatalf("failed admission changed accounting: %+v -> %+v", before, after)
			}
			ready.release()
		})
	}
}

func TestCapacityConcurrentIdentityOwnershipAndFrozenConfiguration(t *testing.T) {
	c := capacityConfig()
	l := newResourceLedger(c)
	c.Jailer.UID = 999999
	c.VMCapacity.MaxInstances = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners := make(map[jailIdentity]bool)
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				physical, active, err := l.reserveCold(128, 1)
				if errors.Is(err, ErrBusy) {
					continue
				}
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if owners[physical.identity] || physical.identity.uid < 230000 || physical.identity.uid >= 230004 {
					t.Errorf("duplicate or mutated identity: %+v", physical.identity)
				}
				owners[physical.identity] = true
				mu.Unlock()
				if s := l.snapshot(); s.Active > 2 || s.Instances > 4 || s.ReservedMemoryMiB > 4*640 || s.ReservedVCPUs > 16 {
					t.Errorf("capacity exceeded: %+v", s)
				}
				mu.Lock()
				delete(owners, physical.identity)
				mu.Unlock()
				physical.release()
				active.release()
				active.release()
			}
		}()
	}
	close(start)
	wg.Wait()
	if s := l.snapshot(); s != (VMCapacitySnapshot{AvailableIdentities: 4}) {
		t.Fatalf("concurrent leak: %+v", s)
	}
}

func TestCapacityCleanupFailureRetainsResourcesAndClosesAdmission(t *testing.T) {
	m := testManager(t, "output")
	// The invalid cgroup name injects a cleanup failure before any cgroup path
	// can be accessed. The workdir and resource ownership must be retained.
	m.config.Jailer = &JailerConfig{ParentCgroup: "../outside", UID: 230000, GID: 230000, IdentityPoolSize: 4,
		MemoryOverheadMiB: 128, PidsMax: 64}
	m.config.VMCapacity = nil
	m.config.applyCapacityDefaults()
	m.capacity = newResourceLedger(m.config)
	if _, err := m.Run(context.Background(), RunRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cleanup failure not reported: %v", err)
	}
	s := m.Capacity()
	if !s.Blocked || s.Active != 1 || s.Instances != 1 || s.AvailableIdentities != 3 || s.ReservedPids != 64 {
		t.Fatalf("cleanup failure released ownership: %+v", s)
	}
	if report := m.Doctor(); report.VMCapacity == nil || *report.VMCapacity != s {
		t.Fatalf("doctor lost retained resource ownership: %+v", report.VMCapacity)
	}
	entries, err := os.ReadDir(m.config.RunRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("cleanup evidence not retained: %v %v", entries, err)
	}
	if _, _, err := m.capacity.reserveCold(128, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocked ledger admitted work: %v", err)
	}
	if _, err := m.capacity.reservePhysical(128, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocked ledger admitted prewarm: %v", err)
	}
	if _, err := m.capacity.reserveActive(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocked ledger admitted checkout: %v", err)
	}
}

func TestCapacityConfigurationRejectsImpossibleBudgets(t *testing.T) {
	for _, name := range []string{"instances", "identity", "memory", "vcpu", "pids"} {
		t.Run(name, func(t *testing.T) {
			c := capacityConfig()
			switch name {
			case "instances":
				c.VMCapacity.MaxInstances = 1
			case "identity":
				c.Jailer.IdentityPoolSize = 3
			case "memory":
				c.VMCapacity.ReservedMemoryMiB = 1
			case "vcpu":
				c.VMCapacity.ReservedVCPUs = -1
			case "pids":
				c.VMCapacity.ReservedPids = 1
			}
			if err := c.validateCapacity(); err == nil {
				t.Fatal("invalid capacity accepted")
			}
		})
	}
}
