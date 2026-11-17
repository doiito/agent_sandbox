// Functional core acceptance in an ARM64 VM with no network device.
// Release installation and Firecracker/KVM acceptance are separate gates.
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
		fmt.Fprintln(os.Stderr, "artifact QEMU init must be PID 1")
		os.Exit(2)
	}
	passed := run()
	if passed {
		fmt.Println("ARM64_ARTIFACT_CORE_PASS")
	} else {
		fmt.Println("ARM64_ARTIFACT_CORE_FAIL")
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
	for _, mount := range [][4]string{{"devtmpfs", "/dev", "devtmpfs", ""}, {"proc", "/proc", "proc", ""}, {"tmpfs", "/tmp", "tmpfs", "mode=1777,size=192m"}} {
		if err := syscall.Mount(mount[0], mount[1], mount[2], 0, mount[3]); err != nil {
			fmt.Println(err)
			return false
		}
	}
	_ = os.Setenv("TMPDIR", "/tmp")
	_ = os.Setenv("OSV_ARTIFACT_VM", "1")
	for _, argv := range [][]string{
		{"/bin/artifact-host-tests", "-test.run=^TestSessionArtifact", "-test.count=1", "-test.v", "-test.timeout=60s"},
		{"/bin/artifact-guest-tests", "artifacts::", "--test-threads=1", "--nocapture"},
		{"/bin/artifact-guest-tests", "--exact", "artifacts::tests::actual_vm_prepare_ack_one_shot_cross_filesystem_and_shutdown", "--ignored", "--test-threads=1", "--nocapture"},
	} {
		command := exec.Command(argv[0], argv[1:]...)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			fmt.Println("artifact core failed:", err)
			return false
		}
	}
	return true
}
