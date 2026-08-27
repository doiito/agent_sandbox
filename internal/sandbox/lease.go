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

func writeProcessLease(workdir string, pid int) error {
	startTime, err := processStartTime(pid)
	if err != nil {
		return err
	}
	lease := processLease{
		Protocol: "osv-sandbox-lease/v1", InstanceID: filepath.Base(workdir),
		PID: pid, StartTimeTicks: startTime, CreatedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	temporary := filepath.Join(workdir, ".lease.tmp")
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(workdir, "lease.json"))
}

func reconcileRunRoot(runRoot, cgroupParent string) (int, error) {
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return 0, err
	}
	reconciled := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "job-") || validateJailerID(entry.Name()) != nil {
			continue
		}
		workdir := filepath.Join(runRoot, entry.Name())
		if info, err := os.Lstat(workdir); err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		lease, _ := readProcessLease(filepath.Join(workdir, "lease.json"))
		if lease.PID > 1 && lease.InstanceID == entry.Name() && processMatchesLease(lease) {
			_ = syscall.Kill(-lease.PID, syscall.SIGKILL)
			_ = syscall.Kill(lease.PID, syscall.SIGKILL)
		}
		if err := os.RemoveAll(workdir); err != nil {
			return reconciled, fmt.Errorf("remove orphan %s: %w", entry.Name(), err)
		}
		if cgroupParent != "" {
			if err := cleanupCgroupWithDeadline(cgroupParent, entry.Name(), 2*time.Second); err != nil {
				return reconciled, fmt.Errorf("remove orphan cgroup %s: %w", entry.Name(), err)
			}
		}
		reconciled++
	}
	return reconciled, nil
}

func cleanupCgroupWithDeadline(parent, instanceID string, timeout time.Duration) error {
	if !safeCgroupName(parent) || validateJailerID(instanceID) != nil {
		return errors.New("unsafe cgroup path")
	}
	path := filepath.Join("/sys/fs/cgroup", parent, instanceID)
	deadline := time.Now().Add(timeout)
	for {
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	if err != nil || startTime != lease.StartTimeTicks {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(lease.PID), "cmdline"))
	return err == nil && strings.Contains(string(cmdline), lease.InstanceID)
}

func processStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) <= 19 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
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

func cleanupCgroup(parent, instanceID string) {
	if !safeCgroupName(parent) || validateJailerID(instanceID) != nil {
		return
	}
	_ = os.Remove(filepath.Join("/sys/fs/cgroup", parent, instanceID))
}
