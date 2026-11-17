package sandbox

import "time"

// StartupTiming partitions the existing authenticated-admission startup metric.
// VMM boot duration is reported separately: it overlaps selection/readiness.
type StartupTiming struct {
	Schema        string `json:"schema"`
	AdmissionUS   int64  `json:"admission_us"`
	SelectionUS   int64  `json:"selection_us"`
	ReadinessUS   int64  `json:"readiness_us"`
	PreparationUS int64  `json:"preparation_us"`
	OwnershipUS   int64  `json:"ownership_us"`
	AuditUS       int64  `json:"audit_us"`
	FinalizeUS    int64  `json:"finalize_us"`
	TotalUS       int64  `json:"total_us"`
}

type startupPhase uint8

const (
	startupAdmission startupPhase = iota
	startupSelection
	startupReadiness
	startupPreparation
	startupOwnership
	startupAudit
	startupFinalize
	startupPhaseCount
)

type startupClock struct {
	started, last time.Time
	spent         [startupPhaseCount]time.Duration
	invalid       bool
}

func (c *startupClock) mark(phase startupPhase, now time.Time) {
	if c.invalid {
		return
	}
	if c.started.IsZero() || now.Before(c.last) || phase >= startupPhaseCount {
		c.invalid = true
		return
	}
	c.spent[phase] += now.Sub(c.last)
	c.last = now
}

func (c *startupClock) finish(now time.Time) *StartupTiming {
	c.mark(startupFinalize, now)
	if c.invalid {
		return nil
	}
	// v2 warm readiness validates host ownership/lifetime; atomic preparation
	// supplies the current guest-state proof. Cold still includes its first ping.
	result := &StartupTiming{Schema: "osv-startup-timing/v2", TotalUS: now.Sub(c.started).Microseconds(),
		AdmissionUS: c.spent[startupAdmission].Microseconds(), SelectionUS: c.spent[startupSelection].Microseconds(),
		ReadinessUS: c.spent[startupReadiness].Microseconds(), PreparationUS: c.spent[startupPreparation].Microseconds(),
		OwnershipUS: c.spent[startupOwnership].Microseconds(), AuditUS: c.spent[startupAudit].Microseconds(),
		FinalizeUS: c.spent[startupFinalize].Microseconds()}
	// Floors of disjoint nonnegative intervals cannot exceed their total floor.
	// Keep sub-microsecond conversion residue without dropping measured time.
	result.FinalizeUS += result.TotalUS - result.AdmissionUS - result.SelectionUS - result.ReadinessUS -
		result.PreparationUS - result.OwnershipUS - result.AuditUS - result.FinalizeUS
	return result
}

func (s *StartupTiming) clone() *StartupTiming {
	if s == nil {
		return nil
	}
	copy := *s
	return &copy
}

// Called after the first complete readiness and ownership check. Subsequent
// background/checkout probes must not replace the original VMM boot sample.
func (v *vmInstance) recordBootReadyAt(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.bootReadyRecorded && !v.started.IsZero() && !now.Before(v.started) {
		v.bootReadyUS = now.Sub(v.started).Microseconds()
		v.bootReadyRecorded = true
	}
}

func (v *vmInstance) bootDurationUS() int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.bootReadyUS
}
