package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type vmState string

const (
	vmReserved      vmState = "reserved"
	vmBooting       vmState = "booting"
	vmReady         vmState = "ready"
	vmClaiming      vmState = "claiming"
	vmActive        vmState = "active"
	vmDestroying    vmState = "destroying"
	vmDestroyed     vmState = "destroyed"
	vmCleanupFailed vmState = "cleanup_failed"
)

type pristineClaim struct {
	lease     processLease
	requestID string
	tenant    string
}

// vmInstance owns physical resources for its entire lifetime. Tenant handles
// own active reservations separately and may release them only after Destroy
// succeeds. The process context is fixed before boot and is never replaced.
type vmInstance struct {
	manager  *Manager
	id       string
	poolKey  string
	physical *vmReservation
	ctx      context.Context
	cancel   context.CancelFunc

	// bootMu prevents cleanup from returning resources while staging can still
	// start a process. Destroy cancels first, before waiting for this mutex.
	bootMu    sync.Mutex
	workdir   string
	command   *exec.Cmd
	proxy     *vmGuestProxy
	output    *limitedBuffer
	started   time.Time
	exited    chan struct{}
	controlMu sync.Mutex
	// Protocol operations are serialized by controlMu; Destroy may take the
	// idle resource concurrently without waiting for an in-flight operation.
	idleControl   atomic.Pointer[pristineControlConnection]
	guestDeadline time.Time
	checkedAt     time.Time

	mu                sync.Mutex
	state             vmState
	claim             *pristineClaim
	waitErr           error
	bootReadyUS       int64
	bootReadyRecorded bool
	destroyOne        sync.Once
	destroyErr        error
}

func (m *Manager) startVM(ctx context.Context, backend Backend, request RunRequest, physical *vmReservation) (*vmInstance, error) {
	id, err := randomID()
	if err != nil {
		physical.release()
		return nil, err
	}
	processCtx, cancel := context.WithCancel(ctx)
	v := &vmInstance{manager: m, id: id, physical: physical, ctx: processCtx, cancel: cancel,
		poolKey: request.poolKey, state: vmReserved, output: &limitedBuffer{limit: m.config.Limits.MaxOutputByte}}
	owner := m.lifecycleOwner()
	owner.vmMu.Lock()
	if owner.vmClosing {
		owner.vmMu.Unlock()
		cancel()
		physical.release()
		return nil, ErrUnavailable
	}
	if owner.instances == nil {
		owner.instances = make(map[*vmInstance]struct{})
	}
	owner.instances[v] = struct{}{}
	owner.vmMu.Unlock()
	if err := v.start(backend, request); err != nil {
		return v, errors.Join(err, v.Destroy())
	}
	go func() {
		<-processCtx.Done()
		_ = v.Destroy()
	}()
	return v, nil
}

func (v *vmInstance) start(backend Backend, request RunRequest) error {
	v.bootMu.Lock()
	defer v.bootMu.Unlock()
	if err := v.ctx.Err(); err != nil {
		return err
	}
	v.setState(vmBooting)
	workdir, err := os.MkdirTemp(v.manager.config.RunRoot, "job-"+v.id+"-")
	if err != nil {
		return err
	}
	v.workdir = workdir
	request.jailUID, request.jailGID = v.physical.identity.uid, v.physical.identity.gid
	command, err := backend.Command(v.ctx, request, v.manager.artifacts, workdir)
	if err != nil {
		return err
	}
	if jailer := v.manager.config.Jailer; jailer != nil {
		if err := prepareJobCgroup(*jailer, filepath.Base(workdir), workdir); err != nil {
			return fmt.Errorf("prepare VM cgroup: %w", err)
		}
	}
	if err := v.ctx.Err(); err != nil {
		return err
	}
	command.Dir = workdir
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if v.manager.config.Jailer == nil && command.Cancel != nil {
		// exec.CommandContext otherwise kills only the group leader. Keep
		// cancellation of the development QEMU/helper path group-wide too.
		command.Cancel = func() error {
			err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
	}
	command.Stdout, command.Stderr = v.output, v.output
	v.started = time.Now()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start %s: %w", backend.Name(), err)
	}
	v.command = command
	v.exited = make(chan struct{})
	// Persist before Wait can reap a short-lived process: /proc/<pid>/stat
	// remains available for a zombie, but disappears after reaping.
	var leaseErr error
	if v.poolKey == "" {
		leaseErr = writeProcessLease(workdir, command.Process.Pid)
	} else {
		leaseErr = writeProcessLeaseOwned(workdir, command.Process.Pid,
			processLease{VMID: v.id, PoolKey: v.poolKey, Phase: string(vmBooting)})
	}
	go func() {
		err := command.Wait()
		v.mu.Lock()
		v.waitErr = err
		v.mu.Unlock()
		close(v.exited)
		_ = v.Destroy()
	}()
	if leaseErr != nil {
		return fmt.Errorf("persist VM process lease: %w", leaseErr)
	}
	if request.Network == "proxy" {
		if err := v.startGuestProxy(request.tenantID, request.jobID); err != nil {
			return err
		}
	}
	if jailer := v.manager.config.Jailer; jailer != nil {
		path := filepath.Join("/sys/fs/cgroup", jailer.ParentCgroup, filepath.Base(workdir))
		go moveKVMPITThread(v.ctx.Done(), command.Process.Pid, path)
	}
	return nil
}

func (v *vmInstance) setState(state vmState) {
	v.mu.Lock()
	v.state = state
	v.mu.Unlock()
}

func (v *vmInstance) activate() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ctx.Err() != nil || v.state != vmBooting {
		return ErrUnavailable
	}
	v.state = vmActive
	return nil
}

// beginPristineClaim records exclusive in-process ownership. The original
// durable VM identity remains unchanged until the final active commit. Restart
// reconciliation destroys every orphan, including one still marked ready.
// The caller holds controlMu after removing the VM from the ready queue.
func (v *vmInstance) beginPristineClaim(phase vmState, requestID, tenant string) error {
	v.bootMu.Lock()
	defer v.bootMu.Unlock()
	v.mu.Lock()
	valid := v.claim == nil && ((phase == vmReady && v.state == vmClaiming) ||
		(phase == vmBooting && v.state == vmBooting))
	v.mu.Unlock()
	if !valid || v.ctx.Err() != nil {
		return ErrUnavailable
	}
	lease, err := readOwnedPristineLease(v)
	if err != nil || lease.Phase != string(phase) || lease.RequestID != "" || lease.Tenant != "" {
		return errors.Join(ErrUnavailable, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ctx.Err() != nil {
		return ErrUnavailable
	}
	v.claim = &pristineClaim{lease: lease, requestID: requestID, tenant: tenant}
	v.state = vmClaiming
	return nil
}

func (v *vmInstance) ownsPristineClaim(lease processLease, requestID, tenant string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state == vmClaiming && v.claim != nil && v.claim.lease == lease &&
		v.claim.requestID == requestID && v.claim.tenant == tenant
}

// The caller holds controlMu for all pristine protocol and lease transitions.
// bootMu prevents a lease writer from racing directory removal during Destroy.
func (v *vmInstance) transitionPristine(from, to vmState, requestID, tenant string) error {
	v.bootMu.Lock()
	defer v.bootMu.Unlock()
	v.mu.Lock()
	valid := v.state == from && v.ctx.Err() == nil
	v.mu.Unlock()
	if !valid || v.poolKey == "" {
		return ErrUnavailable
	}
	var err error
	if to == vmActive {
		lease, readErr := readOwnedPristineLease(v)
		if readErr != nil || !v.ownsPristineClaim(lease, requestID, tenant) {
			return errors.Join(ErrUnavailable, readErr)
		}
		lease.Phase, lease.RequestID, lease.Tenant = string(vmActive), requestID, tenant
		lease.CreatedAt = time.Now().UTC()
		err = persistProcessLease(v.workdir, lease)
	} else {
		err = writeProcessLeaseOwned(v.workdir, v.command.Process.Pid,
			processLease{VMID: v.id, PoolKey: v.poolKey, Phase: string(to), RequestID: requestID, Tenant: tenant})
	}
	if err != nil {
		return fmt.Errorf("%w: persist pristine VM phase: %v", ErrUnavailable, err)
	}
	if v.ctx.Err() != nil {
		return ErrUnavailable
	}
	v.mu.Lock()
	v.state = to
	if to == vmActive {
		v.claim = nil
	}
	v.mu.Unlock()
	return nil
}

func (m *Manager) reservePoolActive() (*activeReservation, error) {
	m = m.lifecycleOwner()
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	if m.vmClosing {
		return nil, ErrUnavailable
	}
	return m.capacity.reserveActive()
}

func (m *Manager) reservePoolPhysical(memoryMiB, vcpus int) (*vmReservation, error) {
	m = m.lifecycleOwner()
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	if m.vmClosing {
		return nil, ErrUnavailable
	}
	return m.capacity.reservePhysical(memoryMiB, vcpus)
}

func (v *vmInstance) waitError() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.waitErr
}

// Destroy is synchronous and idempotent. Failed cleanup retains both the
// registry entry and reservation; callers must not release tenant capacity.
func (v *vmInstance) Destroy() error {
	v.cancel()
	v.closePristineControl()
	v.destroyOne.Do(func() {
		v.bootMu.Lock()
		defer v.bootMu.Unlock()
		v.setState(vmDestroying)
		if v.proxy != nil {
			v.proxy.Close()
		}
		if v.command != nil {
			select {
			case <-v.exited:
			default:
				if v.manager.config.Jailer != nil {
					_ = v.command.Process.Kill()
				} else {
					_ = syscall.Kill(-v.command.Process.Pid, syscall.SIGKILL)
				}
				select {
				case <-v.exited:
				case <-time.After(5 * time.Second):
					v.destroyErr = errors.New("VM did not exit after kill")
				}
			}
		}
		if v.workdir != "" {
			if err := closeVMInference(v.workdir, v.manager.config.EgressSocket); err != nil {
				v.destroyErr = errors.Join(v.destroyErr, fmt.Errorf("close VM inference bill: %w", err))
			}
			if jailer := v.manager.config.Jailer; jailer != nil {
				if err := cleanupCgroupWithDeadline(jailer.ParentCgroup, filepath.Base(v.workdir), 3*time.Second); err != nil {
					v.destroyErr = errors.Join(v.destroyErr, fmt.Errorf("remove VM cgroup: %w", err))
				}
			}
			if v.destroyErr == nil {
				if err := os.RemoveAll(v.workdir); err != nil {
					v.destroyErr = fmt.Errorf("remove VM workdir: %w", err)
				}
			}
		}
		if v.destroyErr != nil {
			v.setState(vmCleanupFailed)
			v.manager.markCleanupFailed()
			v.destroyErr = fmt.Errorf("%w: %v", ErrUnavailable, v.destroyErr)
			return
		}
		v.physical.release()
		v.setState(vmDestroyed)
		owner := v.manager.lifecycleOwner()
		owner.vmMu.Lock()
		delete(owner.instances, v)
		owner.vmMu.Unlock()
	})
	return v.destroyErr
}

func (m *Manager) isStopping() bool {
	m = m.lifecycleOwner()
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	return m.vmClosing
}

func (m *Manager) reserveCold(memoryMiB, vcpus int, contexts ...context.Context) (*vmReservation, *activeReservation, error) {
	if m.catalog != nil {
		ctx := context.Background()
		if len(contexts) > 0 {
			ctx = contexts[0]
		}
		return m.catalog.reserveCold(ctx, memoryMiB, vcpus)
	}
	m = m.lifecycleOwner()
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	if m.vmClosing {
		return nil, nil, ErrUnavailable
	}
	return m.capacity.reserveCold(memoryMiB, vcpus)
}

type VMInstanceSnapshot struct {
	Stopping bool           `json:"stopping"`
	States   map[string]int `json:"states"`
}

func (m *Manager) VMInstances() VMInstanceSnapshot {
	m = m.lifecycleOwner()
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	snapshot := VMInstanceSnapshot{Stopping: m.vmClosing, States: map[string]int{}}
	for instance := range m.instances {
		instance.mu.Lock()
		snapshot.States[string(instance.state)]++
		instance.mu.Unlock()
	}
	return snapshot
}

// Shutdown closes admission first, then cancels every instance, including
// staging instances. A timeout does not release resources or hide failures.
func (m *Manager) Shutdown(ctx context.Context) error {
	m = m.lifecycleOwner()
	if m.catalog != nil {
		m.catalog.cancel()
	}
	for _, member := range m.templateMembers() {
		if member.pool != nil {
			member.pool.stop()
		}
	}
	m.vmMu.Lock()
	m.vmClosing = true
	instances := make([]*vmInstance, 0, len(m.instances))
	for v := range m.instances {
		instances = append(instances, v)
		v.cancel()
	}
	m.vmMu.Unlock()
	done := make(chan error, 1)
	go func() {
		var workers sync.WaitGroup
		var mu sync.Mutex
		var errs error
		jobs := make(chan *vmInstance)
		for i := 0; i < min(16, len(instances)); i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for v := range jobs {
					if err := v.Destroy(); err != nil {
						mu.Lock()
						errs = errors.Join(errs, err)
						mu.Unlock()
					}
				}
			}()
		}
		for _, v := range instances {
			jobs <- v
		}
		close(jobs)
		workers.Wait()
		for _, member := range m.templateMembers() {
			if member.pool != nil {
				errs = errors.Join(errs, member.pool.wait(ctx))
			}
		}
		if errs == nil {
			// A reservation may have preceded shutdown but not registration.
			// Tenant handles also release active only after owner cleanup.
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				capacity := m.Capacity()
				if capacity.Blocked {
					errs = ErrUnavailable
					break
				}
				if capacity.Active == 0 && capacity.Instances == 0 && len(m.VMInstances().States) == 0 {
					break
				}
				select {
				case <-ticker.C:
				case <-ctx.Done():
					done <- ctx.Err()
					return
				}
			}
		}
		done <- errs
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
