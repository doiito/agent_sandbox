// This validation PID 1 exercises actual ARM64 language runtimes with no NIC.
// It is neither a production guest agent nor ARM64 KVM acceptance.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
	if os.Getpid() != 1 {
		panic("QEMU validation init must be PID 1")
	}
	passed := run()
	if passed {
		fmt.Println("ARM64_CODE_RUNTIME_PASS")
	} else {
		fmt.Println("ARM64_CODE_RUNTIME_FAIL")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

func run() bool {
	for _, path := range []string{"/dev", "/dev/shm", "/proc", "/tmp", "/workspace"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			fmt.Println(err)
			return false
		}
	}
	for _, mount := range [][4]string{
		{"devtmpfs", "/dev", "devtmpfs", ""}, {"proc", "/proc", "proc", ""},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777,size=128m"},
		{"tmpfs", "/workspace", "tmpfs", "mode=0770,uid=10000,gid=10000,size=128m"},
	} {
		if err := syscall.Mount(mount[0], mount[1], mount[2], 0, mount[3]); err != nil {
			fmt.Println(err)
			return false
		}
	}
	if err := os.MkdirAll("/dev/shm", 0o1777); err != nil {
		fmt.Println(err)
		return false
	}
	if err := syscall.Mount("tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777,size=32m"); err != nil {
		fmt.Println(err)
		return false
	}
	command := exec.Command("/opt/python/bin/python3.12", "-B", "/validation/runtime.py")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/workspace", "LANG=C.UTF-8",
		"PYTHONDONTWRITEBYTECODE=1", "OPENBLAS_NUM_THREADS=1", "OMP_NUM_THREADS=1"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10000, Gid: 10000}}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	started := time.Now()
	if err := command.Run(); err != nil {
		fmt.Println("runtime reference failed:", err)
		return false
	}
	fmt.Println("ARM64_CODE_RUNTIME_DURATION_MS", time.Since(started).Milliseconds())
	return true
}
