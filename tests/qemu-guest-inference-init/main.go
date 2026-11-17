// Verification-only PID1: actual ARM Python/Node SDK functions, no NIC or VM grant.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func run() error {
	for _, directory := range []string{"/proc", "/sys", "/dev", "/tmp", "/workspace"} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
	}
	for _, mount := range [][3]string{{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"}} {
		if err := syscall.Mount(mount[0], mount[1], mount[2], 0, ""); err != nil {
			return err
		}
	}
	env := []string{"PATH=/opt/python/bin:/opt/node/bin:/bin:/usr/bin", "HOME=/workspace", "LANG=C.UTF-8",
		"PYTHONDONTWRITEBYTECODE=1", "PYTHONHOME=/opt/python", "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY="}
	for _, arguments := range [][]string{
		{"/bin/busybox", "ifconfig", "lo", "127.0.0.1", "up"},
		{"/opt/python/bin/python3.12", "-B", "-m", "unittest", "discover", "-s", "/validation/tests", "-p", "test_guest_inference.py", "-v"},
		{"/opt/node/bin/node", "--test", "--test-reporter=tap", "/validation/tests/test_guest_inference_node.cjs"},
		{"/opt/python/bin/python3.12", "-B", "/validation/tests/reference_guest_inference_arm.py"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		command.Env, command.Dir, command.Stdout, command.Stderr = env, "/validation", os.Stdout, os.Stderr
		err := command.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", arguments[0], err)
		}
	}
	return nil
}

func main() {
	if os.Getpid() != 1 {
		panic("verification init must be PID1")
	}
	if err := run(); err != nil {
		fmt.Println("ARM64_GUEST_INFERENCE_FAIL", err)
	} else {
		fmt.Println("ARM64_GUEST_INFERENCE_PASS")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
