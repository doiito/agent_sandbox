package sandbox

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func timingSum(timing *StartupTiming) int64 {
	return timing.AdmissionUS + timing.SelectionUS + timing.ReadinessUS + timing.PreparationUS + timing.OwnershipUS + timing.AuditUS + timing.FinalizeUS
}

func TestStartupTimingIncludesRetryWorkAndRounding(t *testing.T) {
	start := time.Unix(123, 0)
	clock := startupClock{started: start, last: start}
	clock.mark(startupAdmission, start.Add(1400*time.Nanosecond))
	clock.mark(startupSelection, start.Add(3800*time.Nanosecond))
	clock.mark(startupReadiness, start.Add(12900*time.Nanosecond))
	// A stale instance is destroyed and selected again; neither probe is lost.
	clock.mark(startupSelection, start.Add(19400*time.Nanosecond))
	clock.mark(startupReadiness, start.Add(23100*time.Nanosecond))
	clock.mark(startupSelection, start.Add(24600*time.Nanosecond))
	clock.mark(startupPreparation, start.Add(32800*time.Nanosecond))
	clock.mark(startupOwnership, start.Add(38600*time.Nanosecond))
	clock.mark(startupAudit, start.Add(43900*time.Nanosecond))
	result := clock.finish(start.Add(44700 * time.Nanosecond))
	if result == nil || result.Schema != "osv-startup-timing/v2" || result.TotalUS != 44 || timingSum(result) != result.TotalUS ||
		result.AdmissionUS != 1 || result.SelectionUS != 10 || result.ReadinessUS != 12 || result.PreparationUS != 8 ||
		result.OwnershipUS != 5 || result.AuditUS != 5 || result.FinalizeUS != 3 {
		t.Fatalf("startup partition lost time or overlapped: %+v", result)
	}
}

func TestStartupTimingInvalidClockIsOmitted(t *testing.T) {
	start := time.Unix(123, 0)
	for _, clock := range []startupClock{{}, {started: start, last: start}} {
		clock.mark(startupAdmission, start.Add(-time.Nanosecond))
		if clock.finish(start.Add(time.Second)) != nil {
			t.Fatal("invalid timing was presented as a valid partition")
		}
	}
	clock := startupClock{started: start, last: start}
	clock.mark(startupAdmission, start)
	if got := clock.finish(start.Add(999 * time.Nanosecond)); got == nil || got.TotalUS != 0 || timingSum(got) != 0 {
		t.Fatalf("sub-microsecond interval misrepresented: %+v", got)
	}
}

func TestVMBootDurationLocksFirstReadinessAndOmitsUnknown(t *testing.T) {
	start := time.Unix(123, 0)
	v := &vmInstance{started: start}
	if v.bootDurationUS() != 0 {
		t.Fatal("boot duration fabricated before readiness")
	}
	v.recordBootReadyAt(start.Add(-time.Second))
	v.recordBootReadyAt(start.Add(12345 * time.Microsecond))
	v.recordBootReadyAt(start.Add(time.Second))
	if v.bootDurationUS() != 12345 {
		t.Fatal("subsequent health check replaced original boot duration")
	}
	short := &vmInstance{started: start}
	short.recordBootReadyAt(start.Add(time.Nanosecond))
	short.recordBootReadyAt(start.Add(time.Second))
	if short.bootDurationUS() != 0 {
		t.Fatal("rounded zero allowed subsequent health to replace first readiness")
	}
	encoded, err := json.Marshal(RunResult{})
	if err != nil || string(encoded) == "" {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if value["vm_boot_duration_us"] != nil || value["startup_timing"] != nil {
		t.Fatal("unmeasured legacy startup was reported as measured zero")
	}
}

func TestWarmPoolTimingCountsActualReadinessAndPreparation(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	check, prepare := p.checkClaim, p.prepare
	p.checkClaim = func(v *vmInstance, id, tenant string) error {
		time.Sleep(5 * time.Millisecond)
		return check(v, id, tenant)
	}
	p.prepare = func(ctx context.Context, v *vmInstance, request pristinePreparation) error {
		time.Sleep(7 * time.Millisecond)
		return prepare(ctx, v, request)
	}
	startFakeWarmPool(t, m)
	lease := acquireFake(t, p, 128, "0123456789abcdef01234567")
	defer lease.close()
	if lease.startupTiming == nil || lease.startupTiming.TotalUS != lease.startupUS || timingSum(lease.startupTiming) != lease.startupUS ||
		lease.startupTiming.ReadinessUS < 5000 || lease.startupTiming.PreparationUS < 7000 || lease.vmBootUS != 0 {
		t.Fatalf("warm stages not assigned to their real work: %+v", lease.startupTiming)
	}
}

func TestSessionInfoReturnsIndependentStartupTiming(t *testing.T) {
	ctx := context.Background()
	s := &Session{ctx: ctx, instance: &vmInstance{ctx: ctx}, info: SessionInfo{StartupTiming: &StartupTiming{TotalUS: 123}}}
	info := s.Info()
	info.StartupTiming.TotalUS = 999
	if s.Info().StartupTiming.TotalUS != 123 {
		t.Fatal("caller mutated internal session timing")
	}
}

func TestColdPoolTimingUsesFirstReadySampleAndWarmOmitsBoot(t *testing.T) {
	m, p := fakeWarmManager(t, 2)
	probe := p.probe
	p.probe = func(ctx context.Context, v *vmInstance) (time.Duration, error) {
		remaining, err := probe(ctx, v)
		if err == nil {
			v.recordBootReadyAt(time.Now())
		}
		return remaining, err
	}
	startFakeWarmPool(t, m)
	warm := acquireFake(t, p, 128, "0123456789abcdef01234567")
	if warm.vmBootUS != 0 || warm.instance.bootDurationUS() <= 0 {
		t.Fatal("warm checkout reported old boot cost as this request's cold boot")
	}
	if err := warm.close(); err != nil {
		t.Fatal(err)
	}
	cold := acquireFake(t, p, 256, "1123456789abcdef01234567")
	defer cold.close()
	if cold.startupMode != "cold" || cold.vmBootUS <= 0 || cold.vmBootUS > cold.startupUS ||
		cold.startupTiming == nil || timingSum(cold.startupTiming) != cold.startupUS {
		t.Fatalf("cold boot and total admission were not independently measured: boot=%d timing=%+v", cold.vmBootUS, cold.startupTiming)
	}
}
