package sandbox

import (
	"errors"
	"fmt"
	"sync"
)

// VMCapacityConfig limits all live VMs, including pristine and booting VMs.
// Limits.MaxConcurrent separately bounds work already assigned to tenants.
type VMCapacityConfig struct {
	MaxInstances      int   `json:"max_instances"`
	ReservedMemoryMiB int64 `json:"reserved_memory_mib"`
	ReservedVCPUs     int64 `json:"reserved_vcpus"`
	ReservedPids      int64 `json:"reserved_pids"`
}

type VMCapacitySnapshot struct {
	Active              int   `json:"active"`
	Instances           int   `json:"instances"`
	ReservedMemoryMiB   int64 `json:"reserved_memory_mib"`
	ReservedVCPUs       int64 `json:"reserved_vcpus"`
	ReservedPids        int64 `json:"reserved_pids"`
	AvailableIdentities int   `json:"available_identities"`
	Blocked             bool  `json:"blocked"`
}

func capacityOverhead(c Config) int64 {
	if c.Jailer != nil {
		return int64(c.Jailer.MemoryOverheadMiB)
	}
	return 0
}

func capacityPids(c Config) int64 {
	if c.Jailer != nil {
		return int64(c.Jailer.PidsMax)
	}
	return 1
}

func (c *Config) applyCapacityDefaults() {
	if c.VMCapacity == nil {
		c.VMCapacity = &VMCapacityConfig{}
	}
	v := c.VMCapacity
	if v.MaxInstances == 0 {
		v.MaxInstances = c.Limits.MaxConcurrent
	}
	if v.ReservedMemoryMiB == 0 {
		v.ReservedMemoryMiB = int64(v.MaxInstances) * (int64(c.Limits.MaxMemoryMiB) + capacityOverhead(*c))
	}
	if v.ReservedVCPUs == 0 {
		v.ReservedVCPUs = int64(v.MaxInstances) * int64(c.Limits.MaxVCPUs)
	}
	if v.ReservedPids == 0 {
		v.ReservedPids = int64(v.MaxInstances) * capacityPids(*c)
	}
}

func (c Config) validateCapacity() error {
	v := c.VMCapacity
	if v == nil || v.MaxInstances < c.Limits.MaxConcurrent || v.MaxInstances > 1024 {
		return errors.New("vm_capacity.max_instances must be between max_concurrent and 1024")
	}
	if v.ReservedMemoryMiB < int64(c.Limits.MinMemoryMiB)+capacityOverhead(c) ||
		v.ReservedMemoryMiB > int64(v.MaxInstances)*(int64(c.Limits.MaxMemoryMiB)+capacityOverhead(c)) {
		return errors.New("vm_capacity.reserved_memory_mib must accommodate a VM and not exceed the instance memory ceiling")
	}
	if v.ReservedVCPUs < 1 || v.ReservedVCPUs > int64(v.MaxInstances)*int64(c.Limits.MaxVCPUs) ||
		v.ReservedPids < capacityPids(c) || v.ReservedPids > int64(v.MaxInstances)*capacityPids(c) {
		return errors.New("invalid vm_capacity vCPU or pids budget")
	}
	if c.Jailer != nil && c.Jailer.IdentityPoolSize > 0 && c.Jailer.IdentityPoolSize < v.MaxInstances {
		return errors.New("jailer identity_pool_size must cover all vm_capacity.max_instances")
	}
	return nil
}

type resourceLedger struct {
	mu             sync.Mutex
	limits         Limits
	limit          VMCapacityConfig
	overhead, pids int64
	needsIdentity  bool
	used           VMCapacitySnapshot
	freeIdentities []jailIdentity
}

type vmReservation struct {
	ledger              *resourceLedger
	memory, vcpus, pids int64
	identity            jailIdentity
	hasIdentity         bool
	once                sync.Once
}

type activeReservation struct {
	ledger *resourceLedger
	once   sync.Once
}

func newResourceLedger(config Config) *resourceLedger {
	ledger := &resourceLedger{limits: config.Limits, limit: *config.VMCapacity,
		overhead: capacityOverhead(config), pids: capacityPids(config),
		needsIdentity: config.Jailer != nil && config.Jailer.IdentityPoolSize > 0}
	if config.Jailer != nil {
		for offset := config.Jailer.IdentityPoolSize - 1; offset >= 0; offset-- {
			ledger.freeIdentities = append(ledger.freeIdentities,
				jailIdentity{config.Jailer.UID + offset, config.Jailer.GID + offset})
		}
	}
	return ledger
}

func (l *resourceLedger) snapshot() VMCapacitySnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	value := l.used
	value.AvailableIdentities = len(l.freeIdentities)
	return value
}

func (l *resourceLedger) block() {
	l.mu.Lock()
	l.used.Blocked = true
	l.mu.Unlock()
}

func (l *resourceLedger) reservePhysicalLocked(memoryMiB, vcpus int) (*vmReservation, error) {
	if l.used.Blocked {
		return nil, ErrUnavailable
	}
	if memoryMiB < l.limits.MinMemoryMiB || memoryMiB > l.limits.MaxMemoryMiB ||
		vcpus < 1 || vcpus > l.limits.MaxVCPUs {
		return nil, errors.New("invalid VM reservation size")
	}
	v := l.limit
	memory := int64(memoryMiB) + l.overhead
	pids := l.pids
	needsIdentity := l.needsIdentity
	if l.used.Instances >= v.MaxInstances || memory > v.ReservedMemoryMiB-l.used.ReservedMemoryMiB ||
		int64(vcpus) > v.ReservedVCPUs-l.used.ReservedVCPUs || pids > v.ReservedPids-l.used.ReservedPids ||
		(needsIdentity && len(l.freeIdentities) == 0) {
		return nil, ErrBusy
	}
	r := &vmReservation{ledger: l, memory: memory, vcpus: int64(vcpus), pids: pids, hasIdentity: needsIdentity}
	if needsIdentity {
		r.identity = l.freeIdentities[len(l.freeIdentities)-1]
		l.freeIdentities = l.freeIdentities[:len(l.freeIdentities)-1]
	}
	l.used.Instances++
	l.used.ReservedMemoryMiB += memory
	l.used.ReservedVCPUs += int64(vcpus)
	l.used.ReservedPids += pids
	return r, nil
}

func (l *resourceLedger) reservePhysical(memoryMiB, vcpus int) (*vmReservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reservePhysicalLocked(memoryMiB, vcpus)
}

func (l *resourceLedger) reserveActive() (*activeReservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used.Blocked {
		return nil, ErrUnavailable
	}
	if l.used.Active >= l.limits.MaxConcurrent {
		return nil, ErrBusy
	}
	l.used.Active++
	return &activeReservation{ledger: l}, nil
}

// A cold request obtains both reservations in one transaction. A future pool
// checkout only needs reserveActive: its physical reservation already exists.
func (l *resourceLedger) reserveCold(memoryMiB, vcpus int) (*vmReservation, *activeReservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used.Blocked {
		return nil, nil, ErrUnavailable
	}
	if l.used.Active >= l.limits.MaxConcurrent {
		return nil, nil, ErrBusy
	}
	physical, err := l.reservePhysicalLocked(memoryMiB, vcpus)
	if err != nil {
		return nil, nil, err
	}
	l.used.Active++
	return physical, &activeReservation{ledger: l}, nil
}

func (r *vmReservation) release() {
	r.once.Do(func() {
		l := r.ledger
		l.mu.Lock()
		defer l.mu.Unlock()
		l.used.Instances--
		l.used.ReservedMemoryMiB -= r.memory
		l.used.ReservedVCPUs -= r.vcpus
		l.used.ReservedPids -= r.pids
		if r.hasIdentity {
			l.freeIdentities = append(l.freeIdentities, r.identity)
		}
	})
}

func (r *activeReservation) release() {
	r.once.Do(func() {
		r.ledger.mu.Lock()
		r.ledger.used.Active--
		r.ledger.mu.Unlock()
	})
}

func (m *Manager) markCleanupFailed() {
	m = m.lifecycleOwner()
	m.cleanupFailed.Store(true)
	m.capacity.block()
}

func (m *Manager) Capacity() VMCapacitySnapshot { return m.capacity.snapshot() }

func (v VMCapacitySnapshot) String() string {
	return fmt.Sprintf("active=%d instances=%d memory_mib=%d vcpus=%d pids=%d blocked=%t", v.Active,
		v.Instances, v.ReservedMemoryMiB, v.ReservedVCPUs, v.ReservedPids, v.Blocked)
}
