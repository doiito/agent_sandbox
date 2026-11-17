package sandbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// The catalog mutex is always acquired before a pool mutex. Foreground
// registration happens before entering any pool; cleanup never holds it.
type templateCatalog struct {
	root        *Manager
	members     []*Manager
	mu          sync.Mutex
	next        int
	tokens      float64
	tokenAt     time.Time
	foreground  atomic.Int64
	rebalancing bool
	wake        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	startOne    sync.Once
	startErr    error
}

func newTemplateCatalog(root *Manager, members []*Manager) *templateCatalog {
	ctx, cancel := context.WithCancel(context.Background())
	c := &templateCatalog{root: root, members: members, wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, tokenAt: time.Now()}
	if root.config.WarmPool != nil {
		c.tokens = float64(root.config.WarmPool.RefillBurst)
	}
	return c
}

func (c *templateCatalog) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *templateCatalog) enterForeground() func() {
	c.mu.Lock()
	c.foreground.Add(1)
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.foreground.Add(-1)
		c.mu.Unlock()
		for _, member := range c.members {
			if member.pool != nil {
				member.pool.signal()
			}
		}
	}
}

func (c *templateCatalog) start(ctx context.Context, audit AuditRecorder) error {
	c.startOne.Do(func() {
		stop := context.AfterFunc(ctx, c.cancel)
		go func() { <-c.ctx.Done(); stop() }()
		results := make(chan error, len(c.members))
		for _, member := range c.members {
			go func(m *Manager) { results <- m.startWarmPoolSingle(ctx, audit) }(member)
		}
		for range c.members {
			c.startErr = errors.Join(c.startErr, <-results)
		}
		if c.startErr != nil {
			c.cancel()
			for _, member := range c.members {
				if member.pool != nil {
					member.pool.stop()
				}
			}
		}
	})
	return c.startErr
}

func (c *templateCatalog) refill() {
	c.mu.Lock()
	defer c.mu.Unlock()
	policy := c.root.config.WarmPool
	if policy == nil || !policy.Enabled || c.ctx.Err() != nil || c.foreground.Load() > 0 {
		return
	}
	now := time.Now()
	c.tokens = min(float64(policy.RefillBurst), c.tokens+now.Sub(c.tokenAt).Seconds()*policy.RefillPerSecond)
	c.tokenAt = now
	for c.tokens >= 1 {
		booting := 0
		minimumDeficit := false
		for _, member := range c.members {
			p := member.pool
			if p == nil {
				continue
			}
			p.mu.Lock()
			for _, profile := range p.profiles {
				booting += len(profile.boots)
				if !p.closed && !p.failed.Load() && !p.invalid && len(profile.ready)+len(profile.boots) < profile.config.MinReady {
					minimumDeficit = true
				}
			}
			p.mu.Unlock()
		}
		if booting >= policy.MaxBooting {
			return
		}
		started := false
		busy := false
		for offset := 0; offset < len(c.members); offset++ {
			i := (c.next + offset) % len(c.members)
			p := c.members[i].pool
			if p == nil {
				continue
			}
			ok, err := p.refillCatalogOne(minimumDeficit, now)
			busy = busy || errors.Is(err, ErrBusy)
			if ok {
				c.tokens--
				c.next = (i + 1) % len(c.members)
				started = true
				break
			}
		}
		if !started {
			if busy && minimumDeficit && !c.rebalancing {
				c.rebalancing = true
				go func() {
					ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
					_, _ = c.reclaimOne(ctx, true)
					cancel()
					c.mu.Lock()
					c.rebalancing = false
					c.mu.Unlock()
					for _, member := range c.members {
						if member.pool != nil {
							member.pool.signal()
						}
					}
				}()
			}
			return
		}
	}
}

func (p *warmPool) refillCatalogOne(minimumOnly bool, now time.Time) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.closed || p.failed.Load() || p.invalid || p.pressure || p.foreground > 0 || p.manager.lifecycleOwner().cleanupFailed.Load() {
		return false, nil
	}
	for offset := 0; offset < len(p.profiles); offset++ {
		i := (p.next + offset) % len(p.profiles)
		profile := p.profiles[i]
		target := profile.desired
		if minimumOnly {
			target = profile.config.MinReady
		}
		if len(profile.ready)+len(profile.boots) >= target || now.Before(profile.retryAt) {
			continue
		}
		reservation, err := p.manager.reservePoolPhysical(profile.config.MemoryMiB, profile.config.VCPUs)
		if err != nil {
			return false, err
		}
		ctx, cancel := context.WithTimeout(p.ctx, 600*time.Second)
		boot := &warmBoot{profile: profile, started: now, ctx: ctx, cancel: cancel, done: make(chan struct{})}
		profile.boots[boot] = struct{}{}
		p.next = (i + 1) % len(p.profiles)
		p.workers.Add(1)
		go p.fillOne(boot, reservation)
		return true, nil
	}
	return false, nil
}

// Reclaim only unassigned pristine supply. Never hold two pools' mutexes or
// wait for process/worker cleanup under either the scheduler or a pool lock.
func (c *templateCatalog) reclaimOne(ctx context.Context, excessOnly bool) (bool, error) {
	for ctx.Err() == nil {
		var selected *warmPool
		var selectedProfile *warmProfile
		var victim *vmInstance
		var boot *warmBoot
		for _, member := range c.members {
			p := member.pool
			if p == nil {
				continue
			}
			p.mu.Lock()
			if !p.closed {
				for _, profile := range p.profiles {
					if excessOnly && len(profile.ready)+len(profile.boots) <= profile.config.MinReady {
						continue
					}
					for _, v := range profile.ready {
						if victim == nil || v.started.Before(victim.started) {
							victim, selected, selectedProfile = v, p, profile
							boot = nil
						}
					}
					if victim == nil {
						for b := range profile.boots {
							if boot == nil || b.started.Before(boot.started) {
								boot, selected, selectedProfile = b, p, profile
							}
						}
					}
				}
			}
			p.mu.Unlock()
		}
		if selected == nil {
			return false, nil
		}
		p := selected
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			continue
		}
		if excessOnly && len(selectedProfile.ready)+len(selectedProfile.boots) <= selectedProfile.config.MinReady {
			p.mu.Unlock()
			continue
		}
		if victim != nil {
			found := false
			for _, v := range selectedProfile.ready {
				found = found || v == victim
			}
			if !found {
				p.mu.Unlock()
				continue
			}
			p.removeLocked(selectedProfile, victim)
			p.retiring[victim] = struct{}{}
			p.workers.Add(1)
			code := "catalog_foreground"
			if excessOnly {
				code = "catalog_minimum_rebalance"
			}
			p.discarded[code]++
			p.changeLocked()
			p.mu.Unlock()
			err := victim.Destroy()
			p.finishRetire(victim)
			if err == nil {
				err = p.event("pool.discarded", victim, "", "", code, "", 0)
			}
			p.workers.Done()
			return true, err
		}
		if _, ok := selectedProfile.boots[boot]; !ok {
			p.mu.Unlock()
			continue
		}
		boot.cancel()
		p.changeLocked()
		p.mu.Unlock()
		select {
		case <-boot.done:
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return false, ctx.Err()
}

func (c *templateCatalog) pendingRetirement() bool {
	for _, member := range c.members {
		if p := member.pool; p != nil {
			p.mu.Lock()
			pending := len(p.retiring) > 0
			p.mu.Unlock()
			if pending {
				return true
			}
		}
	}
	return false
}

func (c *templateCatalog) foregroundPhysical(ctx context.Context, memory, vcpus int) (*vmReservation, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, err := c.root.reservePoolPhysical(memory, vcpus)
		if !errors.Is(err, ErrBusy) {
			return r, err
		}
		reclaimed, err := c.reclaimOne(ctx, false)
		if err != nil {
			return nil, err
		}
		if reclaimed {
			continue
		}
		if !c.pendingRetirement() {
			return nil, ErrBusy
		}
		select {
		case <-c.wake:
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *templateCatalog) reserveCold(ctx context.Context, memory, vcpus int) (*vmReservation, *activeReservation, error) {
	if policy := c.root.config.WarmPool; policy != nil && policy.Enabled {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(policy.CheckoutTimeoutMS)*time.Millisecond)
		defer cancel()
	}
	leave := c.enterForeground()
	defer leave()
	active, err := c.root.reservePoolActive()
	if err != nil {
		return nil, nil, err
	}
	physical, err := c.foregroundPhysical(ctx, memory, vcpus)
	if err != nil {
		active.release()
		return nil, nil, err
	}
	return physical, active, nil
}

func (c *templateCatalog) snapshot() WarmPoolSnapshot {
	s := WarmPoolSnapshot{Healthy: true, Running: true, Misses: map[string]uint64{}, Discarded: map[string]uint64{}, Foreground: int(c.foreground.Load())}
	for _, member := range c.members {
		if member.pool == nil {
			continue
		}
		one := member.pool.snapshot()
		s.Enabled = true
		s.Running = s.Running && one.Running
		s.Healthy = s.Healthy && one.Healthy
		s.Degraded = s.Degraded || one.Degraded
		s.MemoryPressure = s.MemoryPressure || one.MemoryPressure
		s.Checking += one.Checking
		s.Retiring += one.Retiring
		s.Hits += one.Hits
		s.RefillFailures += one.RefillFailures
		for reason, count := range one.Misses {
			s.Misses[reason] += count
		}
		for reason, count := range one.Discarded {
			s.Discarded[reason] += count
		}
		for _, profile := range one.Profiles {
			profile.TemplateID = member.config.defaultTemplateID()
			profile.Backend = member.config.Backend
			if member.manifest != nil {
				profile.ArtifactManifestSHA256 = member.manifest.digestSHA256
			}
			if member != c.root {
				profile.Name = profile.TemplateID + "/" + profile.Name
			}
			s.Profiles = append(s.Profiles, profile)
		}
	}
	if !s.Enabled {
		s.Running = false
	}
	return s
}
