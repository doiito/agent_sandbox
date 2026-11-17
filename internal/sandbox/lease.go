package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type processLease struct {
	Protocol       string    `json:"protocol"`
	InstanceID     string    `json:"instance_id"`
	PID            int       `json:"pid"`
	StartTimeTicks uint64    `json:"start_time_ticks"`
	CreatedAt      time.Time `json:"created_at"`
	VMID           string    `json:"vm_id,omitempty"`
	PoolKey        string    `json:"pool_key,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	RequestID      string    `json:"request_id,omitempty"`
	Tenant         string    `json:"tenant,omitempty"`
}

func acquireRunRootLock(runRoot string) (*os.File, error) {
	path := filepath.Join(runRoot, ".launcher.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another privileged launcher owns run_root")
	}
	return file, nil
}

func (c Config) requiresOwnedRunRoot() bool {
	return c.Production || (c.WarmPool != nil && c.WarmPool.Enabled) ||
		(c.Backend == "firecracker-osv" && c.Jailer != nil && c.ArtifactManifest != nil)
}

// A diagnostic signed/jailered runtime needs the same exclusive ownership
// and orphan accounting as production before any fresh identity is allocated.
func claimManagedRunRoot(c Config) (*os.File, int, error) {
	if !c.requiresOwnedRunRoot() {
		return nil, 0, nil
	}
	file, err := acquireRunRootLock(c.RunRoot)
	if err != nil {
		return nil, 0, err
	}
	parent := ""
	if c.Jailer != nil {
		parent = c.Jailer.ParentCgroup
	}
	count, err := reconcileRunRoot(c.RunRoot, parent, c.EgressSocket)
	if err != nil {
		_ = file.Close()
		return nil, count, err
	}
	return file, count, nil
}

func writeProcessLease(workdir string, pid int) error {
	return writeProcessLeaseOwned(workdir, pid, processLease{})
}

func writeProcessLeaseOwned(workdir string, pid int, lease processLease) error {
	startTime, err := processStartTime(pid)
	if err != nil {
		return err
	}
	lease.Protocol, lease.InstanceID = "osv-sandbox-lease/v1", filepath.Base(workdir)
	lease.PID, lease.StartTimeTicks, lease.CreatedAt = pid, startTime, time.Now().UTC()
	return persistProcessLease(workdir, lease)
}

// The caller supplies an already verified process generation. A claim commit
// keeps that generation instead of adopting a newly reused PID.
func persistProcessLease(workdir string, lease processLease) error {
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	temporary := filepath.Join(workdir, ".lease.tmp")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(workdir, "lease.json")); err != nil {
		return err
	}
	directory, err := os.Open(workdir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func reconcileRunRoot(runRoot, cgroupParent string, egressSocket ...string) (int, error) {
	cgroupRoot := ""
	if cgroupParent != "" {
		if !safeCgroupName(cgroupParent) {
			return 0, errors.New("unsafe cgroup parent")
		}
		cgroupRoot = filepath.Join("/sys/fs/cgroup", cgroupParent)
	}
	socket := ""
	if len(egressSocket) > 0 {
		socket = egressSocket[0]
	}
	return reconcileRunRootAt(runRoot, cgroupRoot, func(path string) error {
		return terminateCgroupPath(path, 3*time.Second)
	}, func(workdir string) error {
		return closeVMInference(workdir, socket)
	})
}

func reconcileRunRootAt(runRoot, cgroupRoot string, terminate func(string) error, finalize ...func(string) error) (int, error) {
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return 0, err
	}
	reconciled := 0
	for _, entry := range entries {
		if !entry.IsDir() || !validJobInstanceID(entry.Name()) {
			continue
		}
		workdir := filepath.Join(runRoot, entry.Name())
		if info, err := os.Lstat(workdir); err != nil {
			return reconciled, err
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return reconciled, fmt.Errorf("unsafe orphan workdir %s", entry.Name())
		}
		lease, _ := readProcessLease(filepath.Join(workdir, "lease.json"))
		leafExists := false
		if cgroupRoot != "" {
			leaf := filepath.Join(cgroupRoot, entry.Name())
			if _, err := os.Lstat(leaf); err == nil {
				leafExists = true
				if err := terminate(leaf); err != nil {
					return reconciled, fmt.Errorf("terminate orphan cgroup %s: %w", entry.Name(), err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return reconciled, err
			}
		}
		if !leafExists && lease.PID > 1 && lease.InstanceID == entry.Name() && processMatchesLease(lease) {
			return reconciled, fmt.Errorf("live orphan lease %s has no dedicated cgroup", entry.Name())
		}
		if len(finalize) > 0 {
			if err := finalize[0](workdir); err != nil {
				return reconciled, fmt.Errorf("finalize orphan inference bill %s: %w", entry.Name(), err)
			}
		}
		if err := os.RemoveAll(workdir); err != nil {
			return reconciled, fmt.Errorf("remove orphan %s: %w", entry.Name(), err)
		}
		reconciled++
	}
	if cgroupRoot == "" {
		return reconciled, nil
	}
	entries, err = os.ReadDir(cgroupRoot)
	if errors.Is(err, os.ErrNotExist) {
		return reconciled, nil
	}
	if err != nil {
		return reconciled, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validJobInstanceID(entry.Name()) {
			continue
		}
		if err := terminate(filepath.Join(cgroupRoot, entry.Name())); err != nil {
			return reconciled, fmt.Errorf("terminate cgroup-only orphan %s: %w", entry.Name(), err)
		}
		reconciled++
	}
	return reconciled, nil
}

func cleanupCgroupWithDeadline(parent, instanceID string, timeout time.Duration) error {
	if !safeCgroupName(parent) || !validJobInstanceID(instanceID) {
		return errors.New("unsafe cgroup path")
	}
	return terminateCgroupPath(filepath.Join("/sys/fs/cgroup", parent, instanceID), timeout)
}

func terminateCgroupPath(path string, timeout time.Duration) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe cgroup leaf %s", path)
	}
	if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	kill, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open cgroup.kill: %w", err)
	}
	_, writeErr := kill.Write([]byte("1"))
	closeErr := kill.Close()
	if writeErr != nil {
		return fmt.Errorf("write cgroup.kill: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	deadline := time.Now().Add(timeout)
	for {
		err = os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func validJobInstanceID(value string) bool {
	if !strings.HasPrefix(value, "job-") {
		return false
	}
	parts := strings.Split(value[4:], "-")
	if len(parts) != 2 || len(parts[0]) != 24 || len(parts[1]) < 1 || len(parts[1]) > 16 {
		return false
	}
	for _, ch := range parts[0] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	for _, ch := range parts[1] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
			return false
		}
	}
	return true
}

func readProcessLease(path string) (processLease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return processLease{}, err
	}
	var lease processLease
	if err := json.Unmarshal(data, &lease); err != nil || lease.Protocol != "osv-sandbox-lease/v1" {
		return processLease{}, errors.New("invalid process lease")
	}
	return lease, nil
}

func processMatchesLease(lease processLease) bool {
	startTime, err := processStartTime(lease.PID)
	return err == nil && startTime == lease.StartTimeTicks
}

func processStartTime(pid int) (uint64, error) {
	ticks, _, err := readProcessStat(pid)
	return ticks, err
}

func readProcessStat(pid int) (uint64, byte, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return 0, 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return 0, 0, errors.New("short process stat")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, fields[0][0], err
}

func moveKVMPITThread(ctxDone <-chan struct{}, firecrackerPID int, cgroupPath string) {
	deadline := time.NewTimer(2 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	needle := fmt.Sprintf("kvm-pit/%d", firecrackerPID)
	for {
		entries, _ := os.ReadDir("/proc")
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err == nil && strings.TrimSpace(string(comm)) == needle {
				_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600)
				return
			}
		}
		select {
		case <-ctxDone:
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

// prepareJobCgroup creates the cgroup before jailer starts. Firecracker's jailer
// parser cannot represent the multi-field value required by cgroup v2 io.max,
// while the kernel interface can. Creating the leaf first also guarantees that
// the I/O ceiling is active before any untrusted guest code can execute; jailer
// subsequently adds the CPU, memory and PID limits and moves the VMM into it.
func prepareJobCgroup(config JailerConfig, instanceID, workdir string) error {
	if !safeCgroupName(config.ParentCgroup) || validateJailerID(instanceID) != nil {
		return errors.New("unsafe cgroup path")
	}
	parent := filepath.Join("/sys/fs/cgroup", config.ParentCgroup)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	available, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read controllers: %w", err)
	}
	required := []string{"cpu", "memory", "pids"}
	if config.IOReadBPS > 0 || config.IOWriteBPS > 0 {
		required = append(required, "io")
	}
	for _, controller := range required {
		if !containsWord(string(available), controller) {
			return fmt.Errorf("controller %s is unavailable", controller)
		}
	}
	enabled, err := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read subtree control: %w", err)
	}
	var additions []string
	for _, controller := range required {
		if !containsWord(string(enabled), controller) {
			additions = append(additions, "+"+controller)
		}
	}
	if len(additions) > 0 {
		if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte(strings.Join(additions, " ")), 0o600); err != nil {
			return fmt.Errorf("enable controllers: %w", err)
		}
	}
	leaf := filepath.Join(parent, instanceID)
	if err := os.Mkdir(leaf, 0o755); err != nil {
		return fmt.Errorf("create leaf: %w", err)
	}
	if config.IOReadBPS == 0 && config.IOWriteBPS == 0 {
		return nil
	}
	device, err := filesystemDevice(workdir)
	if err != nil {
		return fmt.Errorf("resolve backing device: %w", err)
	}
	value := ioMaxValue(device, config.IOReadBPS, config.IOWriteBPS)
	if err := os.WriteFile(filepath.Join(leaf, "io.max"), []byte(value), 0o600); err != nil {
		return fmt.Errorf("write io.max: %w", err)
	}
	return nil
}

func ioMaxValue(device string, readBPS, writeBPS int64) string {
	parts := []string{device}
	if readBPS > 0 {
		parts = append(parts, fmt.Sprintf("rbps=%d", readBPS))
	}
	if writeBPS > 0 {
		parts = append(parts, fmt.Sprintf("wbps=%d", writeBPS))
	}
	return strings.Join(parts, " ")
}
