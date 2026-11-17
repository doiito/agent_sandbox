package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests run actual disposable helper processes and the real resource
// ledger/owner. Guest RPC is replaced, so they make no KVM isolation claim.
func fakeWarmManager(t *testing.T, instances int) (*Manager, *warmPool) {
	t.Helper()
	m := testManager(t, "pool-wait")
	m.config.Backend = "firecracker-linux"
	m.config.AllowedEntrypoints = []string{"/bin/sh"}
	m.config.Limits.MaxConcurrent = 1
	m.config.VMCapacity = &VMCapacityConfig{MaxInstances: instances, ReservedMemoryMiB: int64(instances) * 512, ReservedVCPUs: int64(instances) * 4, ReservedPids: int64(instances)}
	m.config.WarmPool = &WarmPoolConfig{Enabled: true, OnMiss: "cold", MaxBooting: min(2, instances), RefillPerSecond: 100, RefillBurst: 2,
		MaxIdleAgeMS: 120000, HealthIntervalMS: 100, CheckTimeoutMS: 100, BootTimeoutMS: 1000, CheckoutTimeoutMS: 1000, StartupTimeoutMS: 3000, MinAvailableMemoryMiB: 128,
		Profiles: []WarmPoolProfile{{Name: "small", MemoryMiB: 128, VCPUs: 1, MinReady: 1, MaxReady: 1}}}
	m.capacity = newResourceLedger(m.config)
	m.backend = FirecrackerLinuxBackend{}
	m.manifest = &SignedArtifactManifest{CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), digestSHA256: strings.Repeat("a", 64)}
	p, err := newWarmPool(m)
	if err != nil {
		t.Fatal(err)
	}
	m.pool = p
	p.availableMemory = func() (int64, error) { return 1 << 20, nil }
	p.boot = func(ctx context.Context, profile WarmPoolProfile, r *vmReservation) (*vmInstance, error) {
		return m.startVM(ctx, helperBackend{mode: "pool-wait"}, RunRequest{Args: []string{"--sandbox-job-id", "0123456789abcdef01234567"}, poolKey: m.warmProfileKey(profile.MemoryMiB, profile.VCPUs)}, r)
	}
	p.probe = func(_ context.Context, v *vmInstance) (time.Duration, error) {
		lease, err := readProcessLease(filepath.Join(v.workdir, "lease.json"))
		if err != nil || v.ctx.Err() != nil || !processMatchesLease(lease) {
			return 0, ErrUnavailable
		}
		return 600 * time.Second, nil
	}
	var mu sync.Mutex
	prepared := map[string]bool{}
	p.prepare = func(_ context.Context, v *vmInstance, r pristinePreparation) error {
		mu.Lock()
		defer mu.Unlock()
		if prepared[v.id] {
			return errors.New("VM prepared twice")
		}
		prepared[v.id] = true
		return r.validate()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return m, p
}

func startFakeWarmPool(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.StartWarmPool(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func waitWarm(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("warm pool condition timed out")
}

func acquireFake(t *testing.T, p *warmPool, memory int, id string) *preparedVM {
	t.Helper()
	v, err := p.acquire(context.Background(), memory, 1, 1000, "session", id, "tenant-a", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWarmPoolOneUseAndSeparateCapacity(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	startFakeWarmPool(t, m)
	if c := m.Capacity(); c.Active != 0 || c.Instances != 1 {
		t.Fatalf("idle pool charged active capacity: %+v", c)
	}
	p.mu.Lock()
	readyID := p.profiles[0].ready[0].id
	p.mu.Unlock()
	first := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer first.close()
	if first.startupMode != "warm" || first.instance.id != readyID || m.Capacity().Active != 1 || m.Capacity().Instances != 1 {
		t.Fatal("checkout failed to transfer the existing VM")
	}
	lease, err := readProcessLease(filepath.Join(first.instance.workdir, "lease.json"))
	if err != nil || lease.Phase != "active" || lease.RequestID != first.binding.ID || lease.Tenant != "tenant-a" {
		t.Fatalf("durable claim missing: %+v %v", lease, err)
	}
	if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "1123456789abcdef01234567", "tenant-b", nil, time.Now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("active limit bypassed: %v", err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	waitWarm(t, func() bool { return p.snapshot().Profiles[0].Ready == 1 })
	second := acquireFake(t, p, 128, "2123456789abcdef01234567")
	defer second.close()
	if second.instance.id == first.instance.id || second.binding.nonce == first.binding.nonce {
		t.Fatal("used VM or binding reused")
	}
	if p.snapshot().Hits != 2 {
		t.Fatal("warm hit accounting lost")
	}
}

func TestWarmPoolLostPrepareAckDestroysWithoutRetry(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	var calls atomic.Int32
	var old *vmInstance
	p.prepare = func(_ context.Context, v *vmInstance, _ pristinePreparation) error {
		calls.Add(1)
		old = v
		return io.ErrUnexpectedEOF
	}
	startFakeWarmPool(t, m)
	if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost ACK accepted: %v", err)
	}
	if calls.Load() != 1 || old.ctx.Err() == nil || m.Capacity().Active != 0 {
		t.Fatal("lost ACK retried or retained tenant execution capacity")
	}
	if _, err := os.Stat(old.workdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed preparation retained a usable directory")
	}
	waitWarm(t, func() bool { s := p.snapshot(); return s.Profiles[0].Ready == 1 })
	p.mu.Lock()
	replacement := p.profiles[0].ready[0].id
	p.mu.Unlock()
	if replacement == old.id {
		t.Fatal("poisoned VM returned to pool")
	}
}

func TestWarmPoolForegroundReclaimsIdleWithoutRefillStealing(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	startFakeWarmPool(t, m)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(proceed) }) }
	defer unblock()
	p.prepare = func(ctx context.Context, v *vmInstance, _ pristinePreparation) error {
		close(entered)
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan *preparedVM, 1)
	errs := make(chan error, 1)
	go func() {
		v, err := p.acquire(context.Background(), 256, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now())
		done <- v
		errs <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("foreground did not obtain reclaimed capacity")
	}
	for range 3 {
		p.signal()
		time.Sleep(40 * time.Millisecond)
		s := p.snapshot()
		if s.Foreground != 1 || s.Profiles[0].Booting != 0 || m.Capacity().Instances != 1 || m.Capacity().ReservedMemoryMiB != 256 {
			t.Fatalf("refill stole foreground capacity: %+v %+v", s, m.Capacity())
		}
	}
	unblock()
	v := <-done
	err := <-errs
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	if v.startupMode != "cold" {
		t.Fatal("mismatched profile reported warm")
	}
	if p.snapshot().Misses["profile_mismatch"] != 1 {
		t.Fatal("profile mismatch not recorded")
	}
}

func TestWarmPoolCheckoutCancelDuringHealthCheck(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	var probes atomic.Int32
	entered := make(chan struct{})
	realProbe := p.probe
	p.probe = func(ctx context.Context, v *vmInstance) (time.Duration, error) {
		if probes.Add(1) == 2 {
			close(entered)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return realProbe(ctx, v)
	}
	startFakeWarmPool(t, m)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("health check did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.acquire(ctx, 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled checkout: %v", err)
	}
	if m.Capacity().Active != 0 {
		t.Fatal("canceled checkout leaked active reservation")
	}
	waitWarm(t, func() bool {
		s := p.snapshot()
		return s.Checking == 0 && s.Profiles[0].Ready == 1 && s.Discarded["unhealthy"] == 1
	})
}

func TestWarmPoolProfileBackoffDoesNotBlockAnotherProfile(t *testing.T) {
	m, p := fakeWarmManager(t, 2)
	first := p.profiles[0]
	second := &warmProfile{config: WarmPoolProfile{Name: "large", MemoryMiB: 256, VCPUs: 1, MinReady: 1, MaxReady: 1}, key: m.warmProfileKey(256, 1), desired: 1, boots: map[*warmBoot]struct{}{}}
	p.profiles = append(p.profiles, second)
	boot := p.boot
	var failures atomic.Int32
	p.boot = func(ctx context.Context, profile WarmPoolProfile, r *vmReservation) (*vmInstance, error) {
		if profile.MemoryMiB == 128 && failures.Add(1) <= 2 {
			r.release()
			return nil, errors.New("injected boot failure")
		}
		return boot(ctx, profile, r)
	}
	started := make(chan error, 1)
	go func() { started <- m.StartWarmPool(context.Background(), nil) }()
	waitWarm(t, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(second.ready) == 1 && first.failures > 0 && time.Until(first.retryAt) > 0
	})
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if p.snapshot().RefillFailures != 2 {
		t.Fatal("refill failure/backoff accounting changed")
	}
}

func TestWarmPoolMemoryPressureRetiresIdleButPreservesActive(t *testing.T) {
	m, p := fakeWarmManager(t, 2)
	var memory atomic.Int64
	memory.Store(1 << 20)
	p.availableMemory = func() (int64, error) { return memory.Load(), nil }
	startFakeWarmPool(t, m)
	active := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer active.close()
	waitWarm(t, func() bool { return p.snapshot().Profiles[0].Ready == 1 })
	memory.Store(0)
	waitWarm(t, func() bool {
		s := p.snapshot()
		return s.MemoryPressure && s.Profiles[0].Ready == 0 && m.Capacity().Instances == 1
	})
	if active.instance.ctx.Err() != nil || m.Capacity().Active != 1 {
		t.Fatal("pressure terminated active tenant")
	}
	memory.Store(1 << 20)
	waitWarm(t, func() bool { s := p.snapshot(); return !s.MemoryPressure && s.Profiles[0].Ready == 1 })
}

func TestWarmPoolTemplateExpiryRetiresIdleAndRejectsCheckout(t *testing.T) {
	m, p := fakeWarmManager(t, 2)
	m.manifest.ExpiresAt = time.Now().Add(500 * time.Millisecond)
	startFakeWarmPool(t, m)
	active := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer active.close()
	waitWarm(t, func() bool {
		s := p.snapshot()
		return !s.Healthy && s.Profiles[0].Ready == 0 && m.Capacity().Instances == 1
	})
	if active.instance.ctx.Err() != nil {
		t.Fatal("expiry killed already admitted tenant")
	}
	if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "1123456789abcdef01234567", "tenant-b", nil, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired template admitted: %v", err)
	}
}

func TestWarmPoolConcurrentClaimsUseOnePristineVMOnce(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.OnMiss = "reject"
	m.config.Limits.MaxConcurrent = 2
	m.capacity.limits.MaxConcurrent = 2
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(proceed) })
	var preparations atomic.Int32
	p.prepare = func(ctx context.Context, _ *vmInstance, _ pristinePreparation) error {
		if preparations.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	startFakeWarmPool(t, m)
	type outcome struct {
		v   *preparedVM
		err error
	}
	results := make(chan outcome, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			v, err := p.acquire(context.Background(), 128, 1, 1000, "session", fmt.Sprintf("%024x", i+1), "tenant-a", nil, time.Now())
			results <- outcome{v, err}
		}(i)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no claimant reached preparation")
	}
	for range 7 {
		select {
		case r := <-results:
			if !errors.Is(r.err, ErrBusy) {
				if r.v != nil {
					_ = r.v.close()
				}
				t.Fatalf("second claim accepted: %v", r.err)
			}
		case <-time.After(time.Second):
			t.Fatal("losing claimant blocked")
		}
	}
	once.Do(func() { close(proceed) })
	r := <-results
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.v.close()
	if preparations.Load() != 1 || p.snapshot().Hits != 1 {
		t.Fatal("pristine VM was prepared more than once")
	}
}

func TestWarmPoolMinimumRebalancesIdleExtras(t *testing.T) {
	m, p := fakeWarmManager(t, 3)
	p.profiles[0].config.MaxReady = 2
	p.profiles = append(p.profiles, &warmProfile{config: WarmPoolProfile{Name: "large", MemoryMiB: 256, VCPUs: 1, MinReady: 1, MaxReady: 1}, key: m.warmProfileKey(256, 1), desired: 1, boots: map[*warmBoot]struct{}{}})
	startFakeWarmPool(t, m)
	first := acquireFake(t, p, 128, "0123456789abcdef01234567")
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	waitWarm(t, func() bool { s := p.snapshot(); return s.Profiles[0].Ready == 2 && s.Profiles[1].Ready == 1 })
	cold := acquireFake(t, p, 384, "1123456789abcdef01234567")
	defer cold.close()
	if cold.startupMode != "cold" {
		t.Fatal("unconfigured spec was not cold")
	}
	waitWarm(t, func() bool {
		s := p.snapshot()
		return s.Profiles[0].Ready == 1 && s.Profiles[1].Ready == 1 && s.Discarded["minimum_rebalance"] == 1
	})
	if cold.instance.ctx.Err() != nil || m.Capacity().Instances != 3 {
		t.Fatal("minimum rebalance affected active tenant or capacity")
	}
}
func TestWarmPoolHostLifetimeAlsoBoundsCheckout(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.OnMiss = "reject"
	boot := p.boot
	p.boot = func(ctx context.Context, profile WarmPoolProfile, r *vmReservation) (*vmInstance, error) {
		limited, cancel := context.WithTimeout(ctx, 5*time.Second)
		v, err := boot(limited, profile, r)
		if v != nil {
			context.AfterFunc(v.ctx, cancel)
		} else {
			cancel()
		}
		return v, err
	}
	var preparations atomic.Int32
	p.prepare = func(context.Context, *vmInstance, pristinePreparation) error { preparations.Add(1); return nil }
	startFakeWarmPool(t, m)
	if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "0123456789abcdef01234567", "tenant-a", nil, time.Now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("short host lifetime accepted: %v", err)
	}
	if preparations.Load() != 0 || m.Capacity().Active != 0 {
		t.Fatal("checkout prepared a guest past its owner deadline")
	}
}
func TestWarmPoolAuditFailureRetiresIdleAndPreservesActive(t *testing.T) {
	m, p := fakeWarmManager(t, 2)
	var fail atomic.Bool
	audit := &AuditLog{writer: io.Discard, sync: func() error {
		if fail.Load() {
			return io.ErrClosedPipe
		}
		return nil
	}}
	if err := m.StartWarmPool(context.Background(), audit); err != nil {
		t.Fatal(err)
	}
	active := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer active.close()
	waitWarm(t, func() bool { return p.snapshot().Profiles[0].Ready == 1 })
	fail.Store(true)
	if err := audit.Append(AuditEvent{Event: "injected.disk.failure"}); err == nil {
		t.Fatal("fault did not latch")
	}
	if _, err := p.acquire(context.Background(), 128, 1, 1000, "session", "1123456789abcdef01234567", "tenant-b", nil, time.Now()); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("failed audit allowed checkout: %v", err)
	}
	waitWarm(t, func() bool {
		s := p.snapshot()
		return !s.Healthy && s.Profiles[0].Ready == 0 && m.Capacity().Instances == 1
	})
	if active.instance.ctx.Err() != nil {
		t.Fatal("audit failure killed an already admitted tenant")
	}
}
