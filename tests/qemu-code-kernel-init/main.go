// Validation-only PID 1. Tests real kernels and namespace cleanup under TCG.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const pulseProgram = `
import os,sys,time
from pathlib import Path
root=Path(sys.argv[1])
child=os.fork()
if child == 0:
    os.setsid()
    while True:
        temporary=root/'pulse.tmp'
        temporary.write_text(str(time.monotonic_ns()))
        os.replace(temporary,root/'pulse')
        time.sleep(0.02)
else:
    (root/'ready').write_text('ready')
    if sys.argv[2] == 'oneshot':
        time.sleep(1)
    else:
        while True: time.sleep(1)
`

func main() {
	if len(os.Args) == 4 && os.Args[1] == "--namespace" {
		namespaceInit(os.Args[2], os.Args[3])
		return
	}
	if os.Getpid() != 1 {
		panic("QEMU validation init must be PID 1")
	}
	if err := run(); err != nil {
		fmt.Println("ARM64_CODE_KERNEL_FAIL", err)
	} else {
		fmt.Println("ARM64_CODE_KERNEL_PASS")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

func environment() []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=/workspace", "LANG=C.UTF-8",
		"PYTHONDONTWRITEBYTECODE=1", "OPENBLAS_NUM_THREADS=1", "OMP_NUM_THREADS=1"}
}

func namespaceInit(directory, mode string) {
	if os.Getpid() != 1 || os.Geteuid() != 0 || !strings.HasPrefix(directory, "/workspace/ns-") {
		os.Exit(2)
	}
	command := exec.Command("/opt/python/bin/python3.12", "-B", "-c", pulseProgram, directory, mode)
	command.Env = environment()
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10000, Gid: 10000}}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		fmt.Println("namespace workload failed:", err)
		os.Exit(1)
	}
	// Exiting namespace PID 1 makes Linux reap every remaining namespace
	// descendant, including double-forks/new sessions. No guest-wide kill(-1).
}

type workload struct {
	command   *exec.Cmd
	namespace string
	directory string
	waited    bool
}

func (work *workload) close() {
	if !work.waited {
		_ = work.command.Process.Kill()
		_ = work.command.Wait()
		work.waited = true
	}
}

func namespaceCount(name string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if actual, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns/pid")); err == nil && actual == name {
			count++
		}
	}
	return count, nil
}

func startWorkload(label, mode string) (*workload, error) {
	directory := "/workspace/ns-" + label
	if err := os.Mkdir(directory, 0o770); err != nil {
		return nil, err
	}
	if err := os.Chown(directory, 10000, 10000); err != nil {
		return nil, err
	}
	command := exec.Command("/init", "--namespace", directory, mode)
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	work := &workload{command: command, directory: directory}
	var err error
	work.namespace, err = os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", command.Process.Pid))
	if err != nil {
		work.close()
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.ReadFile(filepath.Join(directory, "pulse")); err == nil {
			return work, nil
		}
		if time.Now().After(deadline) {
			work.close()
			return nil, fmt.Errorf("namespace %s workload not ready", label)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func namespacePrototype() error {
	first, err := startWorkload("first", "persistent")
	if err != nil {
		return err
	}
	defer first.close()
	second, err := startWorkload("second", "persistent")
	if err != nil {
		return err
	}
	defer second.close()
	if first.namespace == second.namespace {
		return fmt.Errorf("workloads share a PID namespace")
	}
	for _, work := range []*workload{first, second} {
		count, err := namespaceCount(work.namespace)
		if err != nil || count < 3 {
			return fmt.Errorf("expected supervisor, interpreter and detached descendant: %s count=%d err=%v", work.namespace, count, err)
		}
	}
	before, err := os.ReadFile(filepath.Join(second.directory, "pulse"))
	if err != nil {
		return err
	}
	first.close()
	if count, err := namespaceCount(first.namespace); err != nil || count != 0 {
		return fmt.Errorf("stopped first namespace has %d remaining processes: %v", count, err)
	}
	time.Sleep(100 * time.Millisecond)
	after, err := os.ReadFile(filepath.Join(second.directory, "pulse"))
	if err != nil || string(before) == string(after) {
		return fmt.Errorf("stopping first namespace affected the second: %v", err)
	}
	fmt.Println("PASS namespace-stop-includes-setsid-descendant-keeps-other-workload")
	job, err := startWorkload("job", "oneshot")
	if err != nil {
		return err
	}
	defer job.close()
	if err := job.command.Wait(); err != nil {
		return err
	}
	job.waited = true
	if count, err := namespaceCount(job.namespace); err != nil || count != 0 {
		return fmt.Errorf("one-shot namespace has %d remaining processes: %v", count, err)
	}
	if count, err := namespaceCount(second.namespace); err != nil || count < 3 {
		return fmt.Errorf("one-shot completion affected persistent namespace: %d %v", count, err)
	}
	fmt.Println("PASS namespace-command-completion-reaps-detached-descendant")
	second.close()
	if count, err := namespaceCount(second.namespace); err != nil || count != 0 {
		return fmt.Errorf("second namespace cleanup failed: %d %v", count, err)
	}
	fmt.Println("PASS namespace-prototype-zero-owned-processes")
	return nil
}

func run() error {
	for _, path := range []string{"/dev", "/proc", "/tmp", "/workspace"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	for _, mount := range [][4]string{
		{"devtmpfs", "/dev", "devtmpfs", ""}, {"proc", "/proc", "proc", ""},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777,size=128m"},
		{"tmpfs", "/workspace", "tmpfs", "mode=0770,uid=10000,gid=10000,size=128m"},
	} {
		if err := syscall.Mount(mount[0], mount[1], mount[2], 0, mount[3]); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/dev/shm", 0o1777); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777,size=32m"); err != nil {
		return err
	}
	if err := namespacePrototype(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/opt/python/bin/python3.12", "-B", "/validation/kernels-reference.py")
	command.Env = environment()
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10000, Gid: 10000}}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	started := time.Now()
	if err := command.Run(); err != nil {
		return fmt.Errorf("kernel reference: %w", err)
	}
	fmt.Println("ARM64_CODE_KERNEL_DURATION_MS", time.Since(started).Milliseconds())
	return nil
}
