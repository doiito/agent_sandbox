// Runs the public artifact adapters under ARM64 system emulation with no NIC.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func main() {
	if os.Getpid() != 1 {
		os.Exit(2)
	}
	if run() {
		fmt.Println("ARM64_ARTIFACT_API_PASS")
	} else {
		fmt.Println("ARM64_ARTIFACT_API_FAIL")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

func run() bool {
	if runtime.GOARCH != "arm64" {
		return false
	}
	for _, path := range []string{"/dev", "/proc", "/tmp"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			fmt.Println(err)
			return false
		}
	}
	for _, m := range [][4]string{{"devtmpfs", "/dev", "devtmpfs", ""}, {"proc", "/proc", "proc", ""}, {"tmpfs", "/tmp", "tmpfs", "mode=1777,size=256m"}} {
		if err := syscall.Mount(m[0], m[1], m[2], 0, m[3]); err != nil {
			fmt.Println(err)
			return false
		}
	}
	_ = os.Setenv("TMPDIR", "/tmp")
	for _, argv := range [][]string{
		{"/bin/busybox", "ip", "link", "set", "dev", "lo", "up"},
		{"/bin/artifact-host-tests", "-test.run=^TestSessionArtifact", "-test.count=1", "-test.v", "-test.timeout=90s"},
		{"/bin/artifact-grpc-tests", "-test.run=^TestBridgeArtifact", "-test.count=1", "-test.v", "-test.timeout=30s"},
		{"/bin/artifact-mcp-tests", "-test.run=^TestArtifact", "-test.count=1", "-test.v", "-test.timeout=30s"},
	} {
		command := exec.Command(argv[0], argv[1:]...)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			fmt.Println("ARM64 artifact API command failed:", err)
			return false
		}
	}
	return true
}
