package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAtomicWarmClaimUsesOnePrepareAndRechecksOwnership(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.HealthIntervalMS = 30000
	probe, prepare, check := p.probe, p.prepare, p.checkClaim
	var probes, preparations, checks atomic.Int32
	p.probe = func(ctx context.Context, v *vmInstance) (time.Duration, error) {
		probes.Add(1)
		return probe(ctx, v)
	}
	p.checkClaim = func(v *vmInstance, id, tenant string) error {
		checks.Add(1)
		return check(v, id, tenant)
	}
	var sent pristineBinding
	p.prepare = func(ctx context.Context, v *vmInstance, request pristinePreparation) error {
		preparations.Add(1)
		sent = request.Binding
		return prepare(ctx, v, request)
	}
	startFakeWarmPool(t, m)
	lease := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer lease.close()
	if probes.Load() != 1 || preparations.Load() != 1 || checks.Load() != 2 || sent != lease.binding || !sent.valid() {
		t.Fatal("warm claim did not use one atomic prepare with both ownership checks")
	}
	if lease.startupMode != "warm" || lease.startupTiming.Schema != "osv-startup-timing/v2" {
		t.Fatal("atomic warm path or timing semantics not identified")
	}
}

func TestAtomicWarmLifetimeUsesConservativeVerifiedBounds(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(100*time.Second))
	defer cancel()
	v := &vmInstance{ctx: ctx}
	if remainingPristineLifetime(v, now) != 0 {
		t.Fatal("missing guest bound synthesized from owner lifetime")
	}
	v.guestDeadline = now.Add(50 * time.Second)
	if remainingPristineLifetime(v, now) != 50*time.Second {
		t.Fatal("guest bound was extended")
	}
	v.guestDeadline = now.Add(200 * time.Second)
	if remainingPristineLifetime(v, now) != 100*time.Second {
		t.Fatal("owner bound was extended")
	}
	v.guestDeadline = now.Add(-time.Second)
	if remainingPristineLifetime(v, now) >= 0 {
		t.Fatal("expired guest accepted")
	}
	v.ctx = context.Background()
	v.guestDeadline = now.Add(time.Hour)
	if remainingPristineLifetime(v, now) != 0 {
		t.Fatal("missing original owner deadline accepted")
	}
	v.ctx = ctx
	cancel()
	if remainingPristineLifetime(v, now) != 0 {
		t.Fatal("canceled owner retained usable lifetime")
	}
}

func TestAtomicWarmMissingOrShortGuestLeaseNeverPrepares(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "short"}[missing], func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS, p.config.OnMiss = 30000, "reject"
			var prepared atomic.Int32
			p.prepare = func(context.Context, *vmInstance, pristinePreparation) error { prepared.Add(1); return nil }
			startFakeWarmPool(t, m)
			p.mu.Lock()
			bad := p.profiles[0].ready[0]
			bad.controlMu.Lock()
			bad.guestDeadline = time.Time{}
			if !missing {
				bad.guestDeadline = time.Now().Add(5 * time.Second)
			}
			bad.controlMu.Unlock()
			p.mu.Unlock()
			if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); !errors.Is(err, ErrBusy) {
				t.Fatalf("unusable verified bound admitted: %v", err)
			}
			if prepared.Load() != 0 || bad.ctx.Err() == nil || m.Capacity().Active != 0 {
				t.Fatal("unusable VM prepared, retained or leaked active budget")
			}
		})
	}
}

func TestAtomicWarmClaimRejectsTamperedHostLeaseBeforePrepare(t *testing.T) {
	for _, field := range []string{"pid", "ticks", "vm", "key", "phase", "request", "tenant", "instance", "created"} {
		t.Run(field, func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS, p.config.OnMiss = 30000, "reject"
			check := p.checkClaim
			p.checkClaim = func(v *vmInstance, id, tenant string) error {
				path := filepath.Join(v.workdir, "lease.json")
				lease, err := readProcessLease(path)
				if err != nil {
					return err
				}
				switch field {
				case "pid":
					lease.PID++
				case "ticks":
					lease.StartTimeTicks++
				case "vm":
					lease.VMID = "wrong"
				case "key":
					lease.PoolKey = "wrong"
				case "phase":
					lease.Phase = string(vmActive)
				case "request":
					lease.RequestID = "wrong"
				case "tenant":
					lease.Tenant = "wrong"
				case "instance":
					lease.InstanceID = "wrong"
				case "created":
					lease.CreatedAt = lease.CreatedAt.Add(time.Second)
				}
				data, err := json.Marshal(lease)
				if err != nil {
					return err
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					return err
				}
				return check(v, id, tenant)
			}
			var prepared atomic.Int32
			p.prepare = func(context.Context, *vmInstance, pristinePreparation) error { prepared.Add(1); return nil }
			startFakeWarmPool(t, m)
			if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); !errors.Is(err, ErrBusy) {
				t.Fatalf("invalid host claim accepted: %v", err)
			}
			if prepared.Load() != 0 || m.Capacity().Active != 0 {
				t.Fatal("host mismatch reached tenant preparation or retained budget")
			}
		})
	}
	if err := verifyPristineCgroup(&JailerConfig{ParentCgroup: "atomic-test-unrelated"}, os.Getpid(), "/unused/job-other"); err == nil {
		t.Fatal("foreign cgroup ownership accepted")
	}
}

func TestAtomicWarmPreparedFailureCannotDeliverOrRetry(t *testing.T) {
	for _, failure := range []string{"lost-ack", "lease-change", "cgroup-change", "owner-death", "parent-cancel", "signature-expiry"} {
		t.Run(failure, func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS, p.config.CheckoutTimeoutMS = 30000, 3000
			if failure == "signature-expiry" {
				m.manifest.ExpiresAt = time.Now().Add(time.Second)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls, checks atomic.Int32
			check := p.checkClaim
			p.checkClaim = func(v *vmInstance, id, tenant string) error {
				if checks.Add(1) == 2 && failure == "cgroup-change" {
					return errors.New("injected cgroup ownership mismatch")
				}
				return check(v, id, tenant)
			}
			var victim *vmInstance
			p.prepare = func(_ context.Context, v *vmInstance, _ pristinePreparation) error {
				calls.Add(1)
				victim = v
				switch failure {
				case "lost-ack":
					return io.ErrUnexpectedEOF
				case "lease-change":
					return os.WriteFile(filepath.Join(v.workdir, "lease.json"), []byte("{}"), 0600)
				case "owner-death":
					if err := v.command.Process.Kill(); err != nil {
						return err
					}
					<-v.exited
				case "parent-cancel":
					cancel()
				case "signature-expiry":
					time.Sleep(time.Until(m.manifest.ExpiresAt) + 5*time.Millisecond)
				}
				return nil
			}
			startFakeWarmPool(t, m)
			if lease, err := p.acquire(ctx, 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("uncertain or invalid prepared VM delivered: %+v %v", lease, err)
			}
			if calls.Load() != 1 || victim == nil || victim.ctx.Err() == nil || m.Capacity().Active != 0 {
				t.Fatal("failed prepared claim retried or retained usable ownership")
			}
		})
	}
}

type atomicWarmSlowClaimAudit struct{ AuditRecorder }

func (a atomicWarmSlowClaimAudit) Append(event AuditEvent) error {
	if event.Event == "pool.claimed" {
		time.Sleep(1100 * time.Millisecond)
	}
	return a.AuditRecorder.Append(event)
}

func TestAtomicWarmExpiredPreparationOrCommitCannotDeliver(t *testing.T) {
	for _, duringCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepare", true: "commit"}[duringCommit], func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS, p.config.CheckoutTimeoutMS = 30000, 3000
			prepare := p.prepare
			p.prepare = func(ctx context.Context, v *vmInstance, request pristinePreparation) error {
				if !duringCommit {
					time.Sleep(1100 * time.Millisecond)
				}
				return prepare(ctx, v, request)
			}
			var audit AuditRecorder
			if duringCommit {
				audit = atomicWarmSlowClaimAudit{&AuditLog{writer: io.Discard, sync: func() error { return nil }}}
			}
			if err := m.StartWarmPool(context.Background(), audit); err != nil {
				t.Fatal(err)
			}
			if lease, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); lease != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("expired request handed out after prepare/commit: %+v %v", lease, err)
			}
			if m.Capacity().Active != 0 {
				t.Fatal("expired claim retained active budget")
			}
		})
	}
}

func TestAtomicWarmZombieCannotPassLiveOwnershipCheck(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^$")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	workdir := t.TempDir()
	lease := processLease{VMID: "0123456789abcdef01234567", PoolKey: "test-key", Phase: string(vmReady)}
	if err := writeProcessLeaseOwned(workdir, command.Process.Pid, lease); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for {
		_, state, err := readProcessStat(command.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if state == 'Z' {
			break
		}
		if time.Now().After(until) {
			t.Fatal("child did not reach unreaped zombie state")
		}
		time.Sleep(time.Millisecond)
	}
	stored, err := readProcessLease(filepath.Join(workdir, "lease.json"))
	if err != nil || !processMatchesLease(stored) {
		t.Fatalf("test did not retain matching zombie identity: %v", err)
	}
	v := &vmInstance{ctx: context.Background(), workdir: workdir, command: command, id: lease.VMID, poolKey: lease.PoolKey, exited: make(chan struct{})}
	if _, err := readOwnedPristineLease(v); err == nil {
		t.Fatal("unreaped dead VM passed live claim check")
	}
}

func TestAtomicWarmExitedOwnerCannotBeRevivedByMatchingLivePID(t *testing.T) {
	workdir := t.TempDir()
	lease := processLease{VMID: "0123456789abcdef01234567", PoolKey: "test-key", Phase: string(vmReady)}
	if err := writeProcessLeaseOwned(workdir, os.Getpid(), lease); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	close(finished)
	v := &vmInstance{ctx: context.Background(), workdir: workdir, command: &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}},
		id: lease.VMID, poolKey: lease.PoolKey, exited: finished}
	if _, err := readOwnedPristineLease(v); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed original owner was revived by a matching live process")
	}
}

func TestAtomicWarmUnsentPrepareReselectsOnlyAfterDestroyAndWithinPolicy(t *testing.T) {
	for _, policy := range []string{"cold", "reject", "canceled", "already-cold"} {
		t.Run(policy, func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS = 30000
			if policy == "reject" {
				p.config.OnMiss = "reject"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var first *vmInstance
			var nonce [32]byte
			var calls atomic.Int32
			p.prepare = func(_ context.Context, v *vmInstance, request pristinePreparation) error {
				if calls.Add(1) == 1 {
					first, nonce = v, request.Binding.nonce
					if policy == "canceled" {
						cancel()
					}
					return errors.Join(errPristinePrepareNotSent, io.ErrClosedPipe)
				}
				if first.ctx.Err() == nil || first.id == v.id || request.Binding.nonce == nonce {
					return errors.New("reselected before destruction or reused instance/binding")
				}
				return request.validate()
			}
			startFakeWarmPool(t, m)
			memory := 128
			if policy == "already-cold" {
				memory = 256
			}
			lease, err := p.acquire(ctx, memory, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now())
			if policy == "cold" {
				if err != nil || lease == nil {
					t.Fatalf("certified unsent warm failure did not follow cold miss policy: %v", err)
				}
				defer lease.close()
				if calls.Load() != 2 || lease.startupMode != "cold" || p.snapshot().Discarded["prepare_not_sent"] != 1 || timingSum(lease.startupTiming) != lease.startupUS {
					t.Fatal("failed preparation/reselection was not accounted accurately")
				}
			} else {
				if lease != nil || err == nil || calls.Load() != 1 || m.Capacity().Active != 0 || first == nil || first.ctx.Err() == nil {
					t.Fatalf("request canceled/rejected/cold path retried or delivered: %+v %v", lease, err)
				}
			}
		})
	}
}
