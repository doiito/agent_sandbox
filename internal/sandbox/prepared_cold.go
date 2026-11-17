package sandbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// A signed OSP2 guest always boots unprepared, including when pooling is off.
// This driver owns no queue, refill worker or speculative VM reservation.
type preparedColdRuntime struct {
	manager  *Manager
	backend  pristineVMBackend
	startOne sync.Once
	mu       sync.RWMutex
	ctx      context.Context
	audit    AuditRecorder
	startErr error
	failed   atomic.Bool
}

func newPreparedColdRuntime(m *Manager) (*preparedColdRuntime, error) {
	backend, err := newPristineVMBackend(m)
	if err != nil {
		return nil, err
	}
	return &preparedColdRuntime{manager: m, backend: backend}, nil
}

func (c *preparedColdRuntime) start(ctx context.Context, audit AuditRecorder) error {
	c.startOne.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if ctx.Err() != nil || c.manager.config.Production && audit == nil {
			c.startErr = ErrUnavailable
			return
		}
		c.ctx, c.audit = ctx, audit
	})
	return c.startErr
}

func (c *preparedColdRuntime) available() (context.Context, error) {
	c.mu.RLock()
	ctx, audit := c.ctx, c.audit
	c.mu.RUnlock()
	if ctx == nil || ctx.Err() != nil || c.failed.Load() || c.manager.isStopping() {
		return nil, ErrUnavailable
	}
	if audit != nil && audit.Err() != nil {
		c.failed.Store(true)
		return nil, errAuditUnavailable
	}
	if err := c.manager.artifactAvailability(time.Now()); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (c *preparedColdRuntime) event(kind string, v *vmInstance, id, tenant string, elapsed time.Duration) error {
	c.mu.RLock()
	audit := c.audit
	c.mu.RUnlock()
	if audit == nil && !c.manager.config.Production {
		return nil
	}
	if audit == nil || audit.Append(AuditEvent{Event: kind, VMID: v.id, ProfileSHA256: v.poolKey,
		JobID: id, Tenant: tenant, StartupMode: "cold", DurationMS: elapsed.Milliseconds()}) != nil {
		c.failed.Store(true)
		return errAuditUnavailable
	}
	return nil
}

func (c *preparedColdRuntime) acquire(ctx context.Context, request RunRequest, id string, started time.Time) (result *preparedVM, acquireErr error) {
	lifecycle, err := c.available()
	if err != nil {
		return nil, err
	}
	m := c.manager
	if request.Network != "none" && (request.Network != "proxy" || !m.hasGuestProxyFeature()) {
		return nil, errors.New("unsupported prepared guest network")
	}
	if m.catalog != nil {
		leave := m.catalog.enterForeground()
		defer leave()
	}
	timing := startupClock{started: started, last: started}
	timing.mark(startupAdmission, time.Now())
	physical, active, err := m.reserveCold(request.MemoryMiB, request.VCPUs, ctx)
	if err != nil {
		return nil, err
	}
	var owned *vmInstance
	success := false
	defer func() {
		if success {
			return
		}
		if owned != nil {
			if err := owned.Destroy(); err != nil {
				acquireErr = errors.Join(acquireErr, err)
				return
			}
		} else {
			physical.release()
		}
		active.release()
	}()
	// Preserve the original owner bound learned during boot. The request's
	// shorter timeout cancels preparation, without masquerading as guest TTL.
	lifetime, stopLifetime := context.WithTimeout(lifecycle, 600*time.Second)
	stopRequest := context.AfterFunc(ctx, stopLifetime)
	defer func() {
		stopRequest()
		if !success || ctx.Err() != nil {
			stopLifetime()
		}
	}()
	owned, err = m.startVM(lifetime, c.backend, RunRequest{MemoryMiB: request.MemoryMiB,
		VCPUs: request.VCPUs, Network: "none", poolKey: m.warmProfileKey(request.MemoryMiB, request.VCPUs)}, physical)
	if owned != nil {
		context.AfterFunc(owned.ctx, stopLifetime)
	}
	if err != nil {
		return nil, err
	}
	owned.controlMu.Lock()
	defer owned.controlMu.Unlock()
	if err := owned.beginPristineClaim(vmBooting, id, request.tenantID); err != nil {
		return nil, err
	}
	if err := c.event("vm.created", owned, id, request.tenantID, 0); err != nil {
		return nil, err
	}
	sent := time.Now()
	timing.mark(startupSelection, sent)
	call, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(owned.ctx, cancel)
	defer stopOwner()
	defer cancel()
	remaining, err := c.backend.probeVM(call, owned.workdir)
	if err != nil {
		return nil, err
	}
	owned.guestDeadline = sent.Add(remaining)
	if err := checkPristineClaimOwnership(m.config.Jailer, owned, id, request.tenantID); err != nil {
		return nil, err
	}
	owned.recordBootReadyAt(time.Now())
	timing.mark(startupReadiness, time.Now())
	ttl := max(1000, request.TimeoutMS)
	if remainingPristineLifetime(owned, time.Now()) <= time.Duration(ttl)*time.Millisecond+5*time.Second {
		return nil, ErrUnavailable
	}
	if _, err := c.available(); err != nil {
		return nil, err
	}
	binding, err := newPristineBinding(id)
	if err != nil {
		return nil, err
	}
	leaseStart := time.Now()
	timing.mark(startupSelection, leaseStart)
	if err := c.backend.prepareVM(call, pristinePreparation{Binding: binding, Mode: "job", TTLMS: ttl,
		InputFiles: request.InputFiles, Network: request.Network}, owned.workdir); err != nil {
		return nil, err // A missing ACK is terminal; never retry or run.
	}
	timing.mark(startupPreparation, time.Now())
	if _, err := c.available(); err != nil {
		return nil, err
	}
	if err := checkPristineClaimOwnership(m.config.Jailer, owned, id, request.tenantID); err != nil {
		return nil, err
	}
	if request.Network == "proxy" {
		if err := owned.bindGuestProxy(request.tenantID, id); err != nil {
			return nil, err
		}
	}
	if err := owned.transitionPristine(vmClaiming, vmActive, id, request.tenantID); err != nil {
		return nil, err
	}
	timing.mark(startupOwnership, time.Now())
	if err := c.event("vm.claimed", owned, id, request.tenantID, time.Since(started)); err != nil {
		return nil, err
	}
	timing.mark(startupAudit, time.Now())
	if call.Err() != nil || !time.Now().Before(leaseStart.Add(time.Duration(ttl)*time.Millisecond)) {
		return nil, ErrUnavailable
	}
	finished := time.Now()
	success = true
	return &preparedVM{backend: c.backend, instance: owned, active: active, binding: binding,
		startupMode: "cold", startupUS: finished.Sub(started).Microseconds(), startupTiming: timing.finish(finished),
		vmBootUS: owned.bootDurationUS(), leaseStart: leaseStart, maxExpiresAt: leaseStart.Add(time.Duration(ttl) * time.Millisecond)}, nil
}
