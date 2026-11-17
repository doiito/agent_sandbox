package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type warmProfile struct {
	config            WarmPoolProfile
	key               string
	ready             []*vmInstance
	boots             map[*warmBoot]struct{}
	desired, failures int
	retryAt           time.Time
}

type warmBoot struct {
	profile *warmProfile
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
}

type WarmProfileSnapshot struct {
	TemplateID             string `json:"template_id,omitempty"`
	Backend                string `json:"backend,omitempty"`
	ArtifactManifestSHA256 string `json:"artifact_manifest_sha256,omitempty"`
	Name                   string `json:"name"`
	Key                    string `json:"key"`
	Ready                  int    `json:"ready"`
	Booting                int    `json:"booting"`
	Desired                int    `json:"desired"`
	RetryInMS              int64  `json:"retry_in_ms"`
}

type WarmPoolSnapshot struct {
	Enabled        bool                  `json:"enabled"`
	Running        bool                  `json:"running"`
	Healthy        bool                  `json:"healthy"`
	Degraded       bool                  `json:"degraded"`
	MemoryPressure bool                  `json:"memory_pressure"`
	Foreground     int                   `json:"foreground"`
	Checking       int                   `json:"checking"`
	Retiring       int                   `json:"retiring"`
	Hits           uint64                `json:"hits"`
	Misses         map[string]uint64     `json:"misses"`
	Discarded      map[string]uint64     `json:"discarded"`
	RefillFailures uint64                `json:"refill_failures"`
	Profiles       []WarmProfileSnapshot `json:"profiles"`
}

type warmPool struct {
	manager                                         *Manager
	config                                          WarmPoolConfig
	backend                                         pristineVMBackend
	manifest                                        string
	ctx                                             context.Context
	cancel                                          context.CancelFunc
	startOne                                        sync.Once
	startErr                                        error
	audit                                           AuditRecorder
	failed                                          atomic.Bool
	mu                                              sync.Mutex
	profiles                                        []*warmProfile
	started, initialized, closed, pressure, invalid bool
	foreground, checking, next                      int
	tokens                                          float64
	tokenAt, memoryAt                               time.Time
	hits, refillFailures                            uint64
	misses, discarded                               map[string]uint64
	changed                                         chan struct{}
	wake                                            chan struct{}
	loopDone                                        chan struct{}
	workers                                         sync.WaitGroup
	retiring                                        map[*vmInstance]struct{}
	boot                                            func(context.Context, WarmPoolProfile, *vmReservation) (*vmInstance, error)
	probe                                           func(context.Context, *vmInstance) (time.Duration, error)
	prepare                                         func(context.Context, *vmInstance, pristinePreparation) error
	checkClaim                                      func(*vmInstance, string, string) error
	availableMemory                                 func() (int64, error)
}

func newWarmPool(m *Manager) (*warmPool, error) {
	b, err := newPristineVMBackend(m)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &warmPool{manager: m, config: *m.config.WarmPool, backend: b, manifest: m.manifest.digestSHA256,
		ctx: ctx, cancel: cancel, changed: make(chan struct{}), wake: make(chan struct{}, 1), loopDone: make(chan struct{}),
		misses: map[string]uint64{}, discarded: map[string]uint64{}, retiring: map[*vmInstance]struct{}{}, availableMemory: availableMemoryMiB}
	for _, profile := range p.config.Profiles {
		p.profiles = append(p.profiles, &warmProfile{config: profile, key: m.warmProfileKey(profile.MemoryMiB, profile.VCPUs),
			desired: profile.MinReady, boots: map[*warmBoot]struct{}{}})
	}
	p.boot = func(ctx context.Context, profile WarmPoolProfile, reservation *vmReservation) (*vmInstance, error) {
		return m.startVM(ctx, b, RunRequest{MemoryMiB: profile.MemoryMiB, VCPUs: profile.VCPUs,
			poolKey: m.warmProfileKey(profile.MemoryMiB, profile.VCPUs)}, reservation)
	}
	p.probe = p.probeGuest
	p.prepare = p.prepareGuest
	p.checkClaim = p.checkClaimOwnership
	return p, nil
}

func (p *warmPool) signal() {
	if p.manager.catalog != nil {
		p.manager.catalog.notify()
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *warmPool) changeLocked() { close(p.changed); p.changed = make(chan struct{}); p.signal() }

func (m *Manager) StartWarmPool(ctx context.Context, audit AuditRecorder) error {
	if m.catalog != nil && m.owner == nil {
		return m.catalog.start(ctx, audit)
	}
	return m.startWarmPoolSingle(ctx, audit)
}

func (m *Manager) startWarmPoolSingle(ctx context.Context, audit AuditRecorder) error {
	if m.pool == nil {
		if m.preparedCold != nil {
			return m.preparedCold.start(ctx, audit)
		}
		return nil
	}
	p := m.pool
	p.startOne.Do(func() {
		p.mu.Lock()
		if p.closed || ctx.Err() != nil || (m.config.Production && audit == nil) {
			p.mu.Unlock()
			p.startErr = ErrUnavailable
			return
		}
		p.audit = audit
		p.started = true
		p.tokens = float64(p.config.RefillBurst)
		p.tokenAt = time.Now()
		p.mu.Unlock()
		stopParent := context.AfterFunc(ctx, p.stop)
		go func() { <-p.ctx.Done(); stopParent() }()
		go p.loop()
		startup, cancel := context.WithTimeout(ctx, time.Duration(p.config.StartupTimeoutMS)*time.Millisecond)
		defer cancel()
		for {
			p.mu.Lock()
			ready := true
			for _, profile := range p.profiles {
				if liveReady(profile) < profile.config.MinReady {
					ready = false
				}
			}
			changed := p.changed
			stopped := p.closed || p.failed.Load() || p.invalid
			if ready && !stopped {
				p.initialized = true
			}
			p.mu.Unlock()
			if stopped {
				p.startErr = ErrUnavailable
				break
			}
			if ready {
				return
			}
			select {
			case <-changed:
			case <-startup.Done():
				p.startErr = fmt.Errorf("%w: initial warm pool not ready: %v", ErrUnavailable, startup.Err())
			}
			if p.startErr != nil {
				break
			}
		}
		p.stop()
	})
	return p.startErr
}

func (p *warmPool) stop() {
	p.mu.Lock()
	p.closed = true
	p.changeLocked()
	p.mu.Unlock()
	p.cancel()
}

func (p *warmPool) wait(ctx context.Context) error {
	p.mu.Lock()
	started := p.started
	p.mu.Unlock()
	if !started {
		return nil
	}
	done := make(chan struct{})
	go func() { <-p.loopDone; p.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *warmPool) event(kind string, v *vmInstance, id, tenant, code, mode string, elapsed time.Duration) error {
	if p.audit == nil && !p.manager.config.Production {
		return nil
	}
	var vmID, key string
	if v != nil {
		vmID, key = v.id, v.poolKey
	}
	if p.audit == nil || p.audit.Append(AuditEvent{Event: kind, VMID: vmID, ProfileSHA256: key,
		JobID: id, Tenant: tenant, Code: code, StartupMode: mode, DurationMS: elapsed.Milliseconds()}) != nil {
		p.failed.Store(true)
		p.signal()
		return errAuditUnavailable
	}
	return nil
}

func (p *warmPool) validTemplate() bool {
	return p.manager.manifest != nil && p.manager.manifest.digestSHA256 == p.manifest && p.manager.artifactAvailability(time.Now()) == nil
}

func (p *warmPool) loop() {
	defer close(p.loopDone)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
		p.maintain()
		p.refill()
	}
}

func (p *warmPool) refill() {
	if p.manager.catalog != nil {
		p.manager.catalog.refill()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.tokens = min(float64(p.config.RefillBurst), p.tokens+now.Sub(p.tokenAt).Seconds()*p.config.RefillPerSecond)
	p.tokenAt = now
	if p.closed || p.failed.Load() || p.invalid || p.pressure || p.foreground > 0 || p.manager.cleanupFailed.Load() {
		return
	}
	booting := 0
	for _, profile := range p.profiles {
		booting += len(profile.boots)
	}
	for booting < p.config.MaxBooting && p.tokens >= 1 {
		var selected *warmProfile
		// Satisfy minimum deficits before growing hot profiles.
		for pass := 0; pass < 2 && selected == nil; pass++ {
			for offset := 0; offset < len(p.profiles); offset++ {
				i := (p.next + offset) % len(p.profiles)
				profile := p.profiles[i]
				target := profile.desired
				if pass == 0 {
					target = profile.config.MinReady
				}
				if len(profile.ready)+len(profile.boots) < target && !now.Before(profile.retryAt) {
					selected = profile
					p.next = (i + 1) % len(p.profiles)
					break
				}
			}
		}
		if selected == nil {
			return
		}
		reservation, err := p.manager.reservePoolPhysical(selected.config.MemoryMiB, selected.config.VCPUs)
		if err != nil {
			if errors.Is(err, ErrBusy) && len(selected.ready)+len(selected.boots) < selected.config.MinReady {
				var victim *vmInstance
				var source *warmProfile
				for _, profile := range p.profiles {
					if len(profile.ready) > profile.config.MinReady {
						for _, v := range profile.ready {
							if victim == nil || v.started.Before(victim.started) {
								victim, source = v, profile
							}
						}
					}
				}
				if victim != nil {
					p.removeLocked(source, victim)
					p.retiring[victim] = struct{}{}
					p.discarded["minimum_rebalance"]++
					p.workers.Add(1)
					go func() {
						defer p.workers.Done()
						_ = victim.Destroy()
						_ = p.event("pool.discarded", victim, "", "", "minimum_rebalance", "", 0)
						p.finishRetire(victim)
					}()
				}
			}
			return
		}
		ctx, cancel := context.WithTimeout(p.ctx, 600*time.Second)
		boot := &warmBoot{profile: selected, started: now, ctx: ctx, cancel: cancel, done: make(chan struct{})}
		selected.boots[boot] = struct{}{}
		p.tokens--
		booting++
		p.workers.Add(1)
		go p.fillOne(boot, reservation)
	}
}

func (p *warmPool) fillOne(boot *warmBoot, reservation *vmReservation) {
	defer p.workers.Done()
	defer close(boot.done)
	v, err := p.boot(boot.ctx, boot.profile.config, reservation)
	if err == nil {
		err = p.event("pool.created", v, "", "", "", "", 0)
	}
	if err == nil {
		v.controlMu.Lock()
		ctx, cancel := context.WithTimeout(boot.ctx, time.Duration(p.config.BootTimeoutMS)*time.Millisecond)
		sent := time.Now()
		var remaining time.Duration
		remaining, err = p.probe(ctx, v)
		cancel()
		if err == nil {
			v.guestDeadline = sent.Add(remaining)
			v.checkedAt = time.Now()
			err = v.transitionPristine(vmBooting, vmReady, "", "")
		}
		if err == nil {
			err = p.event("pool.ready", v, "", "", "", "", 0)
		}
		v.controlMu.Unlock()
	}
	p.mu.Lock()
	delete(boot.profile.boots, boot)
	// A probe can return context.Canceled because the VMM exited. Only an
	// explicit scheduler/owner cancellation makes this an expected discard.
	bootCanceled := errors.Is(boot.ctx.Err(), context.Canceled)
	if err == nil && boot.ctx.Err() != nil {
		err = boot.ctx.Err()
	}
	if err == nil && v.ctx.Err() != nil {
		err = errors.Join(ErrUnavailable, v.waitError())
	}
	keep := err == nil && boot.ctx.Err() == nil && !p.closed && !p.failed.Load() && !p.invalid && !p.pressure
	if keep {
		// Once ready, VM termination should release its boot lifetime timer.
		// During probing the VM already cancels its own RPC; propagating that
		// cancellation back to boot.ctx would hide unexpected process exits.
		context.AfterFunc(v.ctx, boot.cancel)
		boot.profile.ready = append(boot.profile.ready, v)
		boot.profile.failures = 0
		boot.profile.retryAt = time.Time{}
		p.changeLocked()
	} else if v != nil {
		p.retiring[v] = struct{}{}
	}
	p.mu.Unlock()
	if !keep {
		if err != nil && !bootCanceled && p.ctx.Err() == nil {
			serial := ""
			if v != nil {
				serial = v.output.String()
				if len(serial) > 4096 {
					serial = serial[len(serial)-4096:]
				}
			}
			slog.Warn("warm pool refill failed", "profile", boot.profile.config.Name, "error", err, "boot_serial_tail", serial)
		}
		boot.cancel()
		if v != nil {
			err = errors.Join(err, v.Destroy())
		} else {
			reservation.release()
		}
		p.mu.Lock()
		refillFailed := err != nil && !bootCanceled && p.ctx.Err() == nil
		if refillFailed {
			p.refillFailures++
			boot.profile.failures++
			boot.profile.retryAt = time.Now().Add(time.Duration(1<<min(boot.profile.failures, 7)) * 200 * time.Millisecond)
		}
		p.changeLocked()
		p.mu.Unlock()
		if refillFailed {
			_ = p.event("pool.refill_failed", v, "", "", "boot_failed", "", 0)
		} else {
			_ = p.event("pool.discarded", v, "", "", "boot_cancelled", "", 0)
		}
		if v != nil {
			p.finishRetire(v)
		}
	}
}

func (p *warmPool) maintain() {
	now := time.Now()
	valid := p.validTemplate()
	if p.audit != nil && p.audit.Err() != nil {
		p.failed.Store(true)
	}
	p.mu.Lock()
	readMemory := now.Sub(p.memoryAt) >= time.Duration(p.config.HealthIntervalMS)*time.Millisecond
	p.mu.Unlock()
	var memory int64
	var memoryErr error
	if readMemory {
		memory, memoryErr = p.availableMemory()
	}
	type retired struct {
		v      *vmInstance
		reason string
	}
	var retire []retired
	p.mu.Lock()
	if readMemory {
		p.memoryAt = now
		p.pressure = memoryErr != nil || memory < p.config.MinAvailableMemoryMiB
	}
	p.invalid = !valid
	for _, profile := range p.profiles {
		kept := profile.ready[:0]
		for _, v := range profile.ready {
			reason := ""
			switch {
			case v.ctx.Err() != nil:
				reason = "dead"
			case p.failed.Load():
				reason = "audit"
			case p.invalid:
				reason = "template_invalid"
			case p.pressure:
				reason = "memory_pressure"
			case now.Sub(v.started) >= time.Duration(p.config.MaxIdleAgeMS)*time.Millisecond:
				reason = "idle_expired"
			}
			if reason != "" {
				retire = append(retire, retired{v, reason})
				p.retiring[v] = struct{}{}
				p.discarded[reason]++
				if reason == "idle_expired" {
					profile.desired = max(profile.config.MinReady, profile.desired-1)
				}
				continue
			}
			kept = append(kept, v)
			// Long foreground work must not let an already-open guest read
			// time out. Necessary expiry maintenance shares the same 4 slots.
			if (p.foreground == 0 || v.pristineControlNeedsMaintenance(now)) && p.checking < 4 && now.Sub(v.checkedAt) >= time.Duration(p.config.HealthIntervalMS)*time.Millisecond && v.controlMu.TryLock() {
				p.checking++
				p.workers.Add(1)
				go p.checkOne(profile, v)
			}
		}
		profile.ready = kept
		if p.invalid || p.pressure || p.failed.Load() {
			for boot := range profile.boots {
				boot.cancel()
			}
		}
	}
	if len(retire) > 0 {
		p.changeLocked()
	}
	p.mu.Unlock()
	for _, item := range retire {
		_ = item.v.Destroy()
		_ = p.event("pool.discarded", item.v, "", "", item.reason, "", 0)
		p.finishRetire(item.v)
	}
}

func (p *warmPool) checkOne(profile *warmProfile, v *vmInstance) {
	defer p.workers.Done()
	ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.config.CheckTimeoutMS)*time.Millisecond)
	sent := time.Now()
	remaining, err := p.probe(ctx, v)
	cancel()
	if err == nil {
		v.guestDeadline = sent.Add(remaining)
	}
	p.mu.Lock()
	p.checking--
	if err == nil {
		v.checkedAt = time.Now()
	}
	if err != nil {
		p.removeLocked(profile, v)
		p.retiring[v] = struct{}{}
		p.discarded["unhealthy"]++
	}
	v.controlMu.Unlock()
	p.changeLocked()
	p.mu.Unlock()
	if err != nil {
		_ = v.Destroy()
		_ = p.event("pool.discarded", v, "", "", "unhealthy", "", 0)
		p.finishRetire(v)
	}
}

func (p *warmPool) finishRetire(v *vmInstance) {
	p.mu.Lock()
	delete(p.retiring, v)
	p.changeLocked()
	p.mu.Unlock()
}

func liveReady(profile *warmProfile) int {
	count := 0
	for _, v := range profile.ready {
		if v.ctx.Err() == nil {
			count++
		}
	}
	return count
}

func (p *warmPool) removeLocked(profile *warmProfile, v *vmInstance) {
	for i, item := range profile.ready {
		if item == v {
			profile.ready = append(profile.ready[:i], profile.ready[i+1:]...)
			return
		}
	}
}

func (p *warmPool) probeGuest(ctx context.Context, v *vmInstance) (time.Duration, error) {
	lease, err := readOwnedPristineLease(v)
	if err != nil {
		return 0, err
	}

	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(v.ctx, cancel)
	defer stop()
	defer cancel()
	linux, preconnected := p.preconnectedLinux()
	var remaining time.Duration
	if preconnected {
		dial := firecrackerVsockDial(dialFirecrackerVsock)
		if lease.Phase == string(vmReady) || v.idleControl.Load() != nil {
			dial = v.takePristineControl
		}
		remaining, err = linux.probeVMWithDial(call, v.workdir, dial)
	} else {
		remaining, err = p.backend.probeVM(call, v.workdir)
	}
	if err != nil {
		return 0, fmt.Errorf("pristine readiness: %w", err)
	}
	// The first reply proves jailer setup completed before the final cgroup check.
	if err := verifyPristineCgroup(p.manager.config.Jailer, lease.PID, v.workdir); err != nil {
		return 0, err
	}
	v.recordBootReadyAt(time.Now())
	if preconnected {
		if err := v.armPristineControl(call, linux.FirecrackerLinuxBackend); err != nil {
			return 0, fmt.Errorf("preconnect pristine control: %w", err)
		}
	}
	return remaining, nil
}

func readOwnedPristineLease(v *vmInstance) (processLease, error) {
	if v.ctx.Err() != nil {
		return processLease{}, ErrUnavailable
	}
	select {
	case <-v.exited:
		return processLease{}, ErrUnavailable
	default:
	}
	lease, err := readProcessLease(filepath.Join(v.workdir, "lease.json"))
	if err != nil || lease.InstanceID != filepath.Base(v.workdir) || lease.PID != v.command.Process.Pid || lease.VMID != v.id || lease.PoolKey != v.poolKey {
		return processLease{}, errors.New("pristine VM lease ownership mismatch")
	}
	ticks, state, err := readProcessStat(lease.PID)
	if err != nil || ticks != lease.StartTimeTicks || state == 'Z' || state == 'X' || state == 'x' || v.ctx.Err() != nil {
		return processLease{}, errors.New("pristine VM process generation is not live")
	}
	select {
	case <-v.exited:
		return processLease{}, ErrUnavailable
	default:
	}
	return lease, nil
}

func (p *warmPool) checkClaimOwnership(v *vmInstance, id, tenant string) error {
	return checkPristineClaimOwnership(p.manager.config.Jailer, v, id, tenant)
}

func checkPristineClaimOwnership(jailer *JailerConfig, v *vmInstance, id, tenant string) error {
	lease, err := readOwnedPristineLease(v)
	if err != nil {
		return err
	}
	if !v.ownsPristineClaim(lease, id, tenant) {
		return errors.New("pristine VM claim ownership mismatch")
	}
	return verifyPristineCgroup(jailer, lease.PID, v.workdir)
}

// The caller holds controlMu. Both bounds originate in monotonic host clocks;
// the guest bound was learned before the VM became ready, never synthesized.
func remainingPristineLifetime(v *vmInstance, now time.Time) time.Duration {
	if v.ctx.Err() != nil {
		return 0
	}
	ownerDeadline, ok := v.ctx.Deadline()
	if !ok || v.guestDeadline.IsZero() {
		return 0
	}
	deadline := v.guestDeadline
	if ownerDeadline.Before(deadline) {
		deadline = ownerDeadline
	}
	return deadline.Sub(now)
}

func errIfFalse(ok bool) error {
	if !ok {
		return errors.New("guest rejected request")
	}
	return nil
}

func (p *warmPool) prepareGuest(ctx context.Context, v *vmInstance, request pristinePreparation) error {
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(v.ctx, cancel)
	defer stop()
	defer cancel()
	if linux, ok := p.preconnectedLinux(); ok {
		return linux.prepareVMWithDial(call, request, v.workdir, v.takePristineControl)
	}
	return p.backend.prepareVM(call, request, v.workdir)
}

func availableMemoryMiB() (int64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			return value / 1024, err
		}
	}
	return 0, errors.New("host MemAvailable is unavailable")
}

func (p *warmPool) snapshot() WarmPoolSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := WarmPoolSnapshot{Enabled: true, Running: p.started && !p.closed, Healthy: p.initialized && !p.closed && !p.invalid && !p.failed.Load() && !p.manager.cleanupFailed.Load(),
		MemoryPressure: p.pressure, Foreground: p.foreground, Checking: p.checking, Retiring: len(p.retiring), Hits: p.hits, RefillFailures: p.refillFailures, Misses: map[string]uint64{}, Discarded: map[string]uint64{}}
	for key, value := range p.misses {
		s.Misses[key] = value
	}
	for key, value := range p.discarded {
		s.Discarded[key] = value
	}
	for _, profile := range p.profiles {
		s.Profiles = append(s.Profiles, WarmProfileSnapshot{Name: profile.config.Name, Key: profile.key, Ready: liveReady(profile), Booting: len(profile.boots), Desired: profile.desired, RetryInMS: max(0, time.Until(profile.retryAt).Milliseconds())})
		if liveReady(profile) < profile.config.MinReady {
			s.Degraded = true
		}
	}
	return s
}
