// This PID 1 runs host proxy functional tests under ARM64 system emulation.
// It does not represent a deployed guest agent or a KVM acceptance run.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "QEMU functional init must be PID 1")
		os.Exit(2)
	}
	passed := run()
	if passed {
		fmt.Println("ARM64_GUEST_PROXY_CORE_PASS")
	} else {
		fmt.Println("ARM64_GUEST_PROXY_CORE_FAIL")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

func run() bool {
	for _, path := range []string{"/dev", "/proc", "/tmp"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			fmt.Println(err)
			return false
		}
	}
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		fmt.Println(err)
		return false
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		fmt.Println(err)
		return false
	}
	if err := syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777,size=128m"); err != nil {
		fmt.Println(err)
		return false
	}
	_ = os.Setenv("TMPDIR", "/tmp")
	for _, argv := range [][]string{
		{"/bin/busybox", "ip", "link", "set", "dev", "lo", "up"},
		{"/bin/proxy-tests", "-test.run=^Test(Egress|GuestProxy)", "-test.count=1", "-test.v", "-test.timeout=45s"},
	} {
		command := exec.Command(argv[0], argv[1:]...)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			fmt.Println("functional command failed:", err)
			return false
		}
	}
	return true
}
