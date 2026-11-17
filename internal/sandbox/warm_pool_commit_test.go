package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPristineClaimPersistsOnlyFinalOwnership(t *testing.T) {
	for _, memory := range []int{128, 256} {
		t.Run(map[int]string{128: "warm", 256: "cold"}[memory], func(t *testing.T) {
			m, p := fakeWarmManager(t, 2)
			p.config.HealthIntervalMS = 30000
			prepare := p.prepare
			var calls atomic.Int32
			p.prepare = func(ctx context.Context, v *vmInstance, request pristinePreparation) error {
				calls.Add(1)
				lease, err := readProcessLease(filepath.Join(v.workdir, "lease.json"))
				if err != nil {
					return err
				}
				phase := vmReady
				if memory == 256 {
					phase = vmBooting
				}
				if lease.Phase != string(phase) || lease.RequestID != "" || lease.Tenant != "" {
					t.Errorf("preparation rewrote durable ownership before the final commit: %+v", lease)
				}
				v.mu.Lock()
				state := v.state
				v.mu.Unlock()
				if state != vmClaiming {
					t.Error("preparing VM was not exclusively claiming")
				}
				return prepare(ctx, v, request)
			}
			startFakeWarmPool(t, m)
			owned := acquireFake(t, p, memory, "0123456789abcdef01234567")
			defer owned.close()
			lease, err := readProcessLease(filepath.Join(owned.instance.workdir, "lease.json"))
			if err != nil || lease.Phase != string(vmActive) || lease.RequestID != owned.binding.ID || lease.Tenant != "tenant-a" {
				t.Fatalf("VM delivered before final durable ownership: %+v %v", lease, err)
			}
			if calls.Load() != 1 || owned.startupMode != map[int]string{128: "warm", 256: "cold"}[memory] {
				t.Fatal("preparation repeated or actual startup path changed")
			}
		})
	}
}

func TestPristineFinalCommitFailureDestroysAcknowledgedVM(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.HealthIntervalMS = 30000
	prepare := p.prepare
	var prepared *vmInstance
	var calls atomic.Int32
	p.prepare = func(ctx context.Context, v *vmInstance, request pristinePreparation) error {
		calls.Add(1)
		prepared = v
		if err := prepare(ctx, v, request); err != nil {
			return err
		}
		// The real atomic lease writer must refuse an existing staging file.
		return os.WriteFile(filepath.Join(v.workdir, ".lease.tmp"), []byte("commit failure"), 0600)
	}
	startFakeWarmPool(t, m)
	owned, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now())
	if owned != nil || !errors.Is(err, ErrUnavailable) || calls.Load() != 1 || prepared == nil {
		t.Fatalf("acknowledged but uncommitted VM delivered or retried: %+v %v", owned, err)
	}
	if prepared.ctx.Err() == nil || m.Capacity().Active != 0 {
		t.Fatal("commit failure retained the VM or its active reservation")
	}
	if _, err := os.Stat(prepared.workdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed commit retained a usable VM directory")
	}
}

func TestRecoveryDestroysPreparedVMWithOriginalDurablePhase(t *testing.T) {
	for _, phase := range []vmState{vmBooting, vmReady} {
		t.Run(string(phase), func(t *testing.T) {
			runRoot, cgroupRoot := t.TempDir(), t.TempDir()
			name := "job-0123456789abcdef01234567-1"
			workdir, cgroup := filepath.Join(runRoot, name), filepath.Join(cgroupRoot, name)
			for _, path := range []string{workdir, cgroup} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			child := exec.Command("sleep", "30")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
			if err := writeProcessLeaseOwned(workdir, child.Process.Pid, processLease{
				VMID: "0123456789abcdef01234567", PoolKey: "original", Phase: string(phase),
			}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(workdir, "prepared-input"), []byte("must not be reused"), 0400); err != nil {
				t.Fatal(err)
			}
			var killed bool
			count, err := reconcileRunRootAt(runRoot, cgroupRoot, func(path string) error {
				if path != cgroup {
					t.Fatalf("unexpected recovery target: %s", path)
				}
				if err := child.Process.Kill(); err != nil {
					return err
				}
				_ = child.Wait()
				killed = true
				return os.Remove(path)
			})
			if err != nil || count != 1 || !killed {
				t.Fatalf("recovery retained a VM with stale durable phase: %d %v", count, err)
			}
			for _, path := range []string{workdir, cgroup} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery left prepared state reusable: %s", path)
				}
			}
		})
	}
}
