package sandbox

import (
	"context"
	"errors"
	"time"
)

type preparedVM struct {
	backend       pristineVMBackend
	instance      *vmInstance
	active        *activeReservation
	binding       pristineBinding
	startupMode   string
	startupUS     int64
	startupTiming *StartupTiming
	vmBootUS      int64
	leaseStart    time.Time
	maxExpiresAt  time.Time
}

func (v *preparedVM) close() error {
	err := v.instance.Destroy()
	if err == nil {
		v.active.release()
	}
	return err
}

func (p *warmPool) acquire(parent context.Context, memoryMiB, vcpus, ttlMS int, mode, id, tenant string, files []InputFile, started time.Time, network ...string) (result *preparedVM, acquireErr error) {
	networkMode := "none"
	if len(network) > 1 {
		return nil, errors.New("ambiguous guest network")
	}
	if len(network) == 1 && network[0] != "" {
		networkMode = network[0]
	}
	if networkMode != "none" && (networkMode != "proxy" || !p.manager.hasGuestProxyFeature()) {
		return nil, errors.New("unsupported prepared guest network")
	}
	entered := time.Now()
	if p.manager.catalog != nil {
		leave := p.manager.catalog.enterForeground()
		defer leave()
	}
	if started.IsZero() {
		started = entered
	}
	timing := startupClock{started: started, last: started}
	timing.mark(startupAdmission, entered)
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.config.CheckoutTimeoutMS)*time.Millisecond)
	defer cancel()
	p.mu.Lock()
	if !p.initialized {
		p.mu.Unlock()
		return nil, ErrUnavailable
	}
	recorder := p.audit
	p.mu.Unlock()
	if recorder != nil && recorder.Err() != nil {
		p.failed.Store(true)
		p.signal()
		return nil, errAuditUnavailable
	}
	p.mu.Lock()
	if !p.started || p.closed || p.failed.Load() || p.invalid || !p.validTemplate() {
		p.mu.Unlock()
		return nil, ErrUnavailable
	}
	active, err := p.manager.reservePoolActive()
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	p.foreground++
	p.changeLocked()
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.foreground--; p.changeLocked(); p.mu.Unlock() }()
	var owned *vmInstance
	var binding pristineBinding
	var leaseStart time.Time
	var maxExpiresAt time.Time
	var unattached *vmReservation
	var unlock func()
	success := false
	defer func() {
		if unlock != nil {
			unlock()
		}
		if success {
			return
		}
		if owned != nil {
			if err := owned.Destroy(); err != nil {
				acquireErr = errors.Join(acquireErr, err)
				return
			}
		}
		if unattached != nil {
			unattached.release()
		}
		active.release()
	}()
	var matching *warmProfile
	for _, profile := range p.profiles {
		if profile.config.MemoryMiB == memoryMiB && profile.config.VCPUs == vcpus {
			matching = profile
			break
		}
	}
	actualMode, reason := "warm", "empty"
	if matching == nil {
		reason = "profile_mismatch"
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.failed.Load() || p.invalid {
			p.mu.Unlock()
			return nil, ErrUnavailable
		}
		busy := false
		if matching != nil && !p.pressure {
			for _, candidate := range matching.ready {
				if !candidate.controlMu.TryLock() {
					busy = true
					continue
				}
				candidate.mu.Lock()
				valid := candidate.state == vmReady && candidate.ctx.Err() == nil
				if valid {
					candidate.state = vmClaiming
				}
				candidate.mu.Unlock()
				p.removeLocked(matching, candidate)
				owned = candidate
				unlock = candidate.controlMu.Unlock
				if !valid {
					reason = "dead"
				}
				break
			}
		}
		changed := p.changed
		p.mu.Unlock()
		if owned == nil {
			if busy {
				select {
				case <-changed:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			p.mu.Lock()
			p.misses[reason]++
			p.mu.Unlock()
			if p.config.OnMiss == "reject" {
				return nil, ErrBusy
			}
			actualMode = "cold"
			unattached, err = p.foregroundPhysical(ctx, memoryMiB, vcpus)
			if err != nil {
				return nil, err
			}
			lifetime, stopLifetime := context.WithTimeout(p.ctx, 600*time.Second)
			stopRequest := context.AfterFunc(ctx, stopLifetime)
			owned, err = p.boot(lifetime, WarmPoolProfile{MemoryMiB: memoryMiB, VCPUs: vcpus}, unattached)
			if owned != nil {
				context.AfterFunc(owned.ctx, stopLifetime)
			}
			if !stopRequest() || ctx.Err() != nil {
				stopLifetime()
				err = errors.Join(err, ctx.Err())
			}
			if err != nil {
				if owned == nil {
					stopLifetime()
				}
				return nil, err
			}
			unattached = nil
			owned.controlMu.Lock()
			unlock = owned.controlMu.Unlock
			if err := owned.beginPristineClaim(vmBooting, id, tenant); err != nil {
				return nil, err
			}
			if err := p.event("pool.created", owned, id, tenant, reason, actualMode, 0); err != nil {
				return nil, err
			}
		} else {
			if owned.ctx.Err() != nil {
				err = ErrUnavailable
			} else {
				err = owned.beginPristineClaim(vmReady, id, tenant)
			}
			if err != nil {
				if cleanErr := owned.Destroy(); cleanErr != nil {
					return nil, cleanErr
				}
				unlock()
				unlock = nil
				owned = nil
				reason = "dead"
				continue
			}
		}
		sent := time.Now()
		timing.mark(startupSelection, sent)
		var remaining time.Duration
		var probeErr error
		if actualMode == "cold" {
			probeCtx, stopProbe := context.WithTimeout(ctx, time.Duration(p.config.BootTimeoutMS)*time.Millisecond)
			remaining, probeErr = p.probe(probeCtx, owned)
			stopProbe()
			if deadline, ok := owned.ctx.Deadline(); ok {
				remaining = min(remaining, time.Until(deadline))
			}
			owned.guestDeadline = sent.Add(remaining)
		}
		if probeErr == nil {
			probeErr = p.checkClaim(owned, id, tenant)
		}
		remaining = remainingPristineLifetime(owned, time.Now())
		key := p.manager.warmProfileKey(memoryMiB, vcpus)
		timing.mark(startupReadiness, time.Now())
		if probeErr != nil || owned.poolKey != key || remaining <= time.Duration(ttlMS)*time.Millisecond+func() time.Duration {
			if mode == "session" {
				return 10 * time.Second
			}
			return 5 * time.Second
		}() ||
			(actualMode == "warm" && time.Since(owned.started) >= time.Duration(p.config.MaxIdleAgeMS)*time.Millisecond) {
			if cleanErr := owned.Destroy(); cleanErr != nil {
				return nil, cleanErr
			}
			unlock()
			unlock = nil
			owned = nil
			if actualMode == "cold" {
				return nil, errors.Join(ErrUnavailable, probeErr)
			}
			reason = "unhealthy"
			if probeErr == nil {
				reason = "lifetime"
			}
			p.mu.Lock()
			p.discarded[reason]++
			p.mu.Unlock()
			continue
		}
		if ctx.Err() != nil || !p.validTemplate() {
			return nil, ErrUnavailable
		}
		binding, err = newPristineBinding(id)
		if err != nil {
			return nil, err
		}
		leaseStart = time.Now()
		timing.mark(startupSelection, leaseStart)
		prepareTTL := ttlMS
		if mode == "session" {
			// Keep the original verified owner/guest cap. Soft TTL may change only within it.
			prepareTTL = int((remainingPristineLifetime(owned, leaseStart) - 10*time.Second).Milliseconds())
			prepareTTL = min(prepareTTL, sessionLifetimeMS(p.manager.config))
			if prepareTTL < ttlMS {
				return nil, ErrUnavailable
			}
		}
		maxExpiresAt = leaseStart.Add(time.Duration(prepareTTL) * time.Millisecond)
		prepareErr := p.prepare(ctx, owned, pristinePreparation{Binding: binding, Mode: mode, TTLMS: prepareTTL, InputFiles: files, Network: networkMode})
		timing.mark(startupPreparation, time.Now())
		if prepareErr != nil {
			if actualMode == "warm" && ctx.Err() == nil && errors.Is(prepareErr, errPristinePrepareNotSent) {
				if err := owned.Destroy(); err != nil {
					return nil, err
				}
				if err := p.event("pool.discarded", owned, id, tenant, "prepare_not_sent", actualMode, 0); err != nil {
					return nil, err
				}
				unlock()
				unlock = nil
				owned = nil
				reason = "prepare_not_sent"
				p.mu.Lock()
				p.discarded[reason]++
				p.mu.Unlock()
				continue
			}
			return nil, errors.Join(ErrUnavailable, prepareErr)
		}
		break
	}
	if ctx.Err() != nil || !p.validTemplate() || !time.Now().Before(leaseStart.Add(time.Duration(ttlMS)*time.Millisecond)) {
		return nil, ErrUnavailable
	}
	if err := p.checkClaim(owned, id, tenant); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if networkMode == "proxy" {
		if err := owned.bindGuestProxy(tenant, id); err != nil {
			return nil, err
		}
	}
	if err := owned.transitionPristine(vmClaiming, vmActive, id, tenant); err != nil {
		return nil, err
	}
	timing.mark(startupOwnership, time.Now())
	if err := p.event("pool.claimed", owned, id, tenant, "", actualMode, time.Since(started)); err != nil {
		return nil, err
	}
	timing.mark(startupAudit, time.Now())
	if ctx.Err() != nil || owned.ctx.Err() != nil || !time.Now().Before(leaseStart.Add(time.Duration(ttlMS)*time.Millisecond)) {
		return nil, ErrUnavailable
	}
	p.mu.Lock()
	if actualMode == "warm" {
		p.hits++
	}
	if matching != nil {
		matching.desired = min(matching.config.MaxReady, max(matching.config.MinReady, matching.desired)+1)
	}
	p.mu.Unlock()
	finished := time.Now()
	var bootUS int64
	if actualMode == "cold" {
		bootUS = owned.bootDurationUS()
	}
	result = &preparedVM{backend: p.backend, instance: owned, active: active, binding: binding, startupMode: actualMode, startupUS: finished.Sub(started).Microseconds(),
		startupTiming: timing.finish(finished), vmBootUS: bootUS, leaseStart: leaseStart, maxExpiresAt: maxExpiresAt}
	success = true
	return result, nil
}

// A foreground demand remains registered until its guest is prepared. Every
// cleanup is outside the pool mutex; refill cannot steal the released budget.
func (p *warmPool) foregroundPhysical(ctx context.Context, memoryMiB, vcpus int) (*vmReservation, error) {
	if p.manager.catalog != nil {
		return p.manager.catalog.foregroundPhysical(ctx, memoryMiB, vcpus)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.failed.Load() || p.invalid {
			p.mu.Unlock()
			return nil, ErrUnavailable
		}
		reservation, err := p.manager.reservePoolPhysical(memoryMiB, vcpus)
		if err == nil {
			p.mu.Unlock()
			return reservation, nil
		}
		if !errors.Is(err, ErrBusy) {
			p.mu.Unlock()
			return nil, err
		}
		var victim *vmInstance
		var source *warmProfile
		for _, profile := range p.profiles {
			for _, v := range profile.ready {
				if victim == nil || v.started.Before(victim.started) {
					victim, source = v, profile
				}
			}
		}
		if victim != nil {
			p.removeLocked(source, victim)
			p.retiring[victim] = struct{}{}
			p.discarded["foreground"]++
			p.changeLocked()
			p.mu.Unlock()
			err := victim.Destroy()
			p.finishRetire(victim)
			if err != nil {
				return nil, err
			}
			_ = p.event("pool.discarded", victim, "", "", "foreground", "", 0)
			continue
		}
		var boot *warmBoot
		for _, profile := range p.profiles {
			for candidate := range profile.boots {
				if boot == nil || candidate.started.Before(boot.started) {
					boot = candidate
				}
			}
		}
		if boot == nil {
			changed, pending := p.changed, len(p.retiring) > 0
			p.mu.Unlock()
			if pending {
				select {
				case <-changed:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, ErrBusy
		}
		boot.cancel()
		done := boot.done
		p.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
