package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// Real disposable processes exercise lifecycle cancellation; RPC alone is fake.
func TestWarmRefillProcessExitClassification(t *testing.T) {
	for _, mode := range []string{"vm-exit", "explicit-cancel", "pool-stop", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			var auditBytes bytes.Buffer
			p.audit = &AuditLog{writer: &auditBytes, sync: func() error { return nil }}
			ctx, cancel := context.WithTimeout(p.ctx, time.Minute)
			defer cancel()
			profile := p.profiles[0]
			boot := &warmBoot{profile: profile, started: time.Now(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
			profile.boots[boot] = struct{}{}
			reservation, err := m.reservePoolPhysical(128, 1)
			if err != nil {
				t.Fatal(err)
			}
			p.probe = func(_ context.Context, v *vmInstance) (time.Duration, error) {
				if mode == "explicit-cancel" {
					cancel()
				}
				if mode == "pool-stop" {
					p.cancel()
				}
				if err := v.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Error(err)
				}
				select {
				case <-v.exited:
				case <-time.After(2 * time.Second):
					t.Fatal("helper failed to exit")
				}
				select {
				case <-v.ctx.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("VM lifetime did not end")
				}
				return 0, context.Canceled
			}
			if mode == "deadline" {
				cancel()
				ctx, expire := context.WithDeadline(p.ctx, time.Now().Add(-time.Second))
				defer expire()
				boot.ctx, boot.cancel = ctx, expire
			}
			p.workers.Add(1)
			p.fillOne(boot, reservation)
			want := uint64(1)
			if mode == "explicit-cancel" || mode == "pool-stop" {
				want = 0
			}
			s := p.snapshot()
			if s.RefillFailures != want || profile.failures != int(want) ||
				(want == 1 && !profile.retryAt.After(time.Now())) || (want == 0 && !profile.retryAt.IsZero()) {
				t.Errorf("%s failure/backoff: counter=%d profile=%d retry=%v want=%d", mode, s.RefillFailures, profile.failures, profile.retryAt, want)
			}
			var failureEvents, cancellationEvents int
			for _, line := range bytes.Split(bytes.TrimSpace(auditBytes.Bytes()), []byte{'\n'}) {
				var event AuditEvent
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				if event.Event == "pool.refill_failed" {
					failureEvents++
				}
				if event.Event == "pool.discarded" && event.Code == "boot_cancelled" {
					cancellationEvents++
				}
			}
			if failureEvents != int(want) || cancellationEvents != 1-int(want) {
				t.Errorf("audit failure=%d cancellation=%d", failureEvents, cancellationEvents)
			}
			assertVMOwnerEmpty(t, m)
		})
	}
}

func TestWarmRefillReadyExitReleasesBootContext(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	ctx, cancel := context.WithTimeout(p.ctx, time.Minute)
	defer cancel()
	profile := p.profiles[0]
	boot := &warmBoot{profile: profile, started: time.Now(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	profile.boots[boot] = struct{}{}
	reservation, err := m.reservePoolPhysical(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	p.workers.Add(1)
	p.fillOne(boot, reservation)
	if ctx.Err() != nil || len(profile.ready) != 1 {
		t.Fatal("healthy VM was not retained")
	}
	v := profile.ready[0]
	if err := v.Destroy(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("ready VM exit retained boot context")
	}
	if p.snapshot().RefillFailures != 0 {
		t.Fatal("successful ready lifetime counted as failed refill")
	}
	assertVMOwnerEmpty(t, m)
}
