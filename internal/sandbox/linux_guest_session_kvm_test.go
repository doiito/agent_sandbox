package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This gated test is compiled into a standalone binary for the isolated x64
// validation host. It boots the signed release's guest without exposing a
// session endpoint before tenant, quota and lease handling exist.
func TestLinuxGuestSessionProtocolOnKVM(t *testing.T) {
	configPath := os.Getenv("OSV_SESSION_KVM_CONFIG")
	if configPath == "" {
		t.Skip("set OSV_SESSION_KVM_CONFIG to an isolated validation fixture")
	}
	if os.Geteuid() != 0 || !strings.Contains(configPath, "/osv-offline-validation-") {
		t.Fatal("session KVM test requires root and an isolated validation fixture")
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Backend != "firecracker-linux" || config.Jailer == nil || config.LinuxGuest == nil {
		t.Fatal("expected a jailed Linux validation backend")
	}
	artifacts, err := ResolveArtifacts(config.ArtifactRoot, config.Kernel, config.Image)
	if err != nil {
		t.Fatal(err)
	}
	backend := FirecrackerLinuxBackend{
		Path: config.HypervisorPath, Jailer: config.Jailer,
		Guest: *config.LinuxGuest, OutputLimit: config.Limits.MaxOutputByte,
	}
	root := filepath.Dir(configPath)
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	workdir, err := os.MkdirTemp(root, "job-"+id+"-")
	if err != nil {
		t.Fatal(err)
	}
	instanceID := filepath.Base(workdir)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var command *exec.Cmd
	var done chan error
	t.Cleanup(func() {
		cancel()
		if done != nil && command != nil {
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("VMM did not exit after kill")
			}
		}
		if err := cleanupCgroupWithDeadline(config.Jailer.ParentCgroup, instanceID, 3*time.Second); err != nil {
			t.Errorf("cleanup session cgroup: %v", err)
		}
		if err := os.RemoveAll(workdir); err != nil {
			t.Errorf("cleanup session workdir: %v", err)
		}
	})
	request := RunRequest{Entrypoint: "/bin/sh", MemoryMiB: 256, VCPUs: 1, TimeoutMS: 30_000}
	command, err = backend.Command(ctx, request, artifacts, workdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareJobCgroup(*config.Jailer, instanceID, workdir); err != nil {
		t.Fatal(err)
	}
	var output limitedBuffer
	output.limit = 32 << 10
	command.Dir = workdir
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatalf("start jailed VM: %v", err)
	}
	done = make(chan error, 1)
	go func() { done <- command.Wait() }()
	cgroupPath := filepath.Join("/sys/fs/cgroup", config.Jailer.ParentCgroup, instanceID)
	go moveKVMPITThread(ctx.Done(), command.Process.Pid, cgroupPath)

	invoke := func(operation string, argv []string) (map[string]any, bool) {
		t.Helper()
		callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		jobID, err := randomID()
		if err != nil {
			t.Fatal(err)
		}
		socket, err := backend.vsockPath(workdir)
		if err != nil {
			t.Fatal(err)
		}
		conn, reader, stopClosing, err := dialFirecrackerVsock(callCtx, socket, config.LinuxGuest.VsockPort)
		if err != nil {
			t.Fatalf("dial session vsock: %v; VMM=%s", err, output.String())
		}
		defer stopClosing()
		defer conn.Close()
		payload := map[string]any{"protocol": "fc-agent/v2", "operation": operation, "job_id": jobID}
		if operation == "run" {
			payload["argv"] = argv
			payload["timeout_ms"] = 5000
			payload["max_output_bytes"] = 4096
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(io.LimitReader(reader, 16<<10)).ReadString('\n')
		if err != nil {
			t.Fatalf("read session result: %v; VMM=%s", err, output.String())
		}
		result, protocolOK, guestOK := extractGuestResultFor(line, jobID, linuxResultPrefix, "fc-agent/v2")
		if !protocolOK {
			t.Fatalf("session result binding failed: %q", line)
		}
		var fields map[string]any
		if err := json.Unmarshal(result, &fields); err != nil {
			t.Fatal(err)
		}
		return fields, guestOK
	}

	if _, ok := invoke("ping", nil); !ok {
		t.Fatal("session ping failed")
	}
	first, ok := invoke("run", []string{"/bin/sh", "-c", "printf retained > /workspace/session-state"})
	if !ok {
		t.Fatalf("first command failed: %v", first)
	}
	second, ok := invoke("run", []string{"/bin/sh", "-c", "cat /workspace/session-state"})
	if !ok || second["stdout"] != "retained" {
		t.Fatalf("session workspace was not retained: %v", second)
	}
	third, ok := invoke("run", []string{"/bin/sh", "-c", "sleep 20 & printf cleaned"})
	if !ok || third["stdout"] != "cleaned" {
		t.Fatalf("background cleanup failed: %v", third)
	}
	if _, ok := invoke("unsupported", nil); ok {
		t.Fatal("unsupported session operation was accepted")
	}
	if _, ok := invoke("shutdown", nil); !ok {
		t.Fatal("session shutdown failed")
	}
	select {
	case <-done:
		done = nil
	case <-time.After(5 * time.Second):
		t.Fatalf("guest shutdown did not stop VMM; output=%s", output.String())
	}
	t.Logf("session KVM protocol passed; instance=%s", instanceID)
}
