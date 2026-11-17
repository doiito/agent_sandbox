package sandbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionRenewableLeaseKeepsOwnerAndExpiresWithoutResurrection(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	startFakeWarmPool(t, m)
	lease := acquireFake(t, p, 128, "0123456789abcdef01234567")
	ctx, cancel := context.WithCancel(lease.instance.ctx)
	s := &Session{manager: m, instance: lease.instance, active: lease.active, ctx: ctx, cancel: cancel, info: SessionInfo{ID: "0123456789abcdef01234567", State: "running", CreatedAt: time.Now().UTC()}}
	s.opMu.Lock() // Model an active command while retaining the real VM owner/process.
	defer s.opMu.Unlock()
	defer s.Close()
	now := time.Now()
	s.startLeaseWatch(now.Add(60*time.Millisecond), now.Add(1500*time.Millisecond))
	originalPID := s.instance.command.Process.Pid
	if _, err := s.SetTimeout(1000); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if info := s.Info(); info.State != "running" || s.instance.ctx.Err() != nil || s.instance.command.Process.Pid != originalPID || m.Capacity().Active != 1 {
		t.Fatal("old soft deadline destroyed or replaced owner", info)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := s.SetTimeout(1000); err != nil {
					t.Error(err)
				}
				_ = s.Info()
			}
		}()
	}
	wg.Wait()
	before := s.Info()
	if _, err := s.SetTimeout(2000); !errors.Is(err, ErrTimeoutBeyondLifetime) {
		t.Fatal("hard bound bypassed", err)
	}
	if !s.Info().ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatal("rejected renewal changed expiry")
	}
	waitWarm(t, func() bool { return s.closed.Load() && m.Capacity().Active == 0 })
	if _, err := s.SetTimeout(1000); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("expired session resurrected", err)
	}
	s.instance.mu.Lock()
	state := s.instance.state
	s.instance.mu.Unlock()
	if state != vmDestroyed || s.instance.ctx.Err() == nil {
		t.Fatal("expired owner was not destroyed", state)
	}
}
func TestSessionPreparationHardWindowDoesNotExtendJobs(t *testing.T) {
	binding, _ := newLinuxGuestBinding("0123456789abcdef01234567")
	r := linuxPrepareRequest{Binding: binding, Mode: "session", TTLMS: sessionMaxLifetimeMS}
	if err := r.validate(); err != nil {
		t.Fatal(err)
	}
	r.Mode = "job"
	if r.validate() == nil {
		t.Fatal("job lease inherited session lifetime")
	}
	r.Mode = "session"
	r.TTLMS = sessionMaxLifetimeMS + 1
	if r.validate() == nil {
		t.Fatal("session cap bypassed")
	}
}

func TestSessionLifetimeOperatorPolicyValidation(t *testing.T) {
	config := testConfig()
	config.Backend = "firecracker-linux"
	for _, value := range []int{-1, 999, 600001} {
		config.SessionMaxLifetimeMS = value
		if config.Validate() == nil {
			t.Fatal("invalid session lifetime accepted", value)
		}
	}
	config.SessionMaxLifetimeMS = 60000
	request := SessionCreateRequest{Backend: config.Backend, ArtifactManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	request.Normalize(config)
	if request.TTLMS != 60000 {
		t.Fatal("default TTL exceeds operator window", request.TTLMS)
	}
	request.TTLMS = 60001
	if !errors.Is(request.Validate(config), ErrTimeoutBeyondLifetime) {
		t.Fatal("operator window did not bound create")
	}
}
