package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Protocol acceptance only: this diagnostic test does not enable the pool or
// substitute for API/launcher ownership and startup performance acceptance.
func TestLinuxPristinePreparationOnKVM(t *testing.T) {
	path := os.Getenv("OSV_PRISTINE_KVM_CONFIG")
	if path == "" {
		t.Skip("set OSV_PRISTINE_KVM_CONFIG to an isolated signed KVM fixture")
	}
	if os.Geteuid() != 0 || !strings.Contains(path, "/osv-offline-validation-") {
		t.Fatal("requires root and isolated fixture")
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Backend != "firecracker-linux" || config.Jailer == nil || config.LinuxGuest == nil {
		t.Fatal("requires jailed Linux backend")
	}
	artifacts, err := ResolveArtifacts(config.ArtifactRoot, config.Kernel, config.Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArtifactManifest(config, artifacts); err != nil {
		t.Fatal(err)
	}
	index := 0
	boot := func(t *testing.T) (FirecrackerLinuxBackend, string, <-chan struct{}) {
		t.Helper()
		index++
		jailer := *config.Jailer
		jailer.UID += 512 + index
		jailer.GID += 512 + index
		if _, err := user.LookupId(strconv.Itoa(jailer.UID)); err == nil {
			t.Fatal("diagnostic UID already assigned")
		}
		if _, err := user.LookupGroupId(strconv.Itoa(jailer.GID)); err == nil {
			t.Fatal("diagnostic GID already assigned")
		}
		backend := FirecrackerLinuxBackend{Path: config.HypervisorPath, Jailer: &jailer, Guest: *config.LinuxGuest,
			OutputLimit: config.Limits.MaxOutputByte, Pristine: true}
		id, err := randomID()
		if err != nil {
			t.Fatal(err)
		}
		workdir, err := os.MkdirTemp(config.RunRoot, "job-"+id+"-")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var command *exec.Cmd
		var exited chan struct{}
		t.Cleanup(func() {
			cancel()
			if command != nil && command.Process != nil {
				_ = command.Process.Kill()
			}
			if exited != nil {
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
					t.Error("diagnostic VMM failed to exit")
				}
			}
			if err := cleanupCgroupWithDeadline(jailer.ParentCgroup, filepath.Base(workdir), 3*time.Second); err != nil {
				t.Error(err)
			}
			if err := os.RemoveAll(workdir); err != nil {
				t.Error(err)
			}
		})
		request := RunRequest{Entrypoint: "/bin/sh", MemoryMiB: 128, VCPUs: 1, TimeoutMS: 10000, jailUID: jailer.UID, jailGID: jailer.GID}
		command, err = backend.Command(ctx, request, artifacts, workdir)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareJobCgroup(jailer, filepath.Base(workdir), workdir); err != nil {
			t.Fatal(err)
		}
		output := &limitedBuffer{limit: 32768}
		command.Dir = workdir
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		exited = make(chan struct{})
		go func() { _ = command.Wait(); close(exited) }()
		if err := writeProcessLease(workdir, command.Process.Pid); err != nil {
			t.Fatal(err)
		}
		go moveKVMPITThread(ctx.Done(), command.Process.Pid, filepath.Join("/sys/fs/cgroup", jailer.ParentCgroup, filepath.Base(workdir)))
		pingID, _ := randomID()
		pingCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		if _, ok, err := backend.ExchangeSession(pingCtx, linuxJobRequest{JobID: pingID, Operation: "ping"}, workdir); err != nil || !ok {
			t.Fatalf("pristine readiness: %v %t; guest=%s", err, ok, output.String())
		}
		return backend, workdir, exited
	}
	call := func(b FirecrackerLinuxBackend, root string, r linuxJobRequest) (json.RawMessage, bool, error) {
		if r.JobID == "" {
			r.JobID, _ = randomID()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return b.ExchangeSession(ctx, r, root)
	}
	exit := func(t *testing.T, exited <-chan struct{}) {
		t.Helper()
		select {
		case <-exited:
		case <-time.After(4 * time.Second):
			t.Fatal("guest did not terminate after terminal operation")
		}
	}
	prepare := func(t *testing.T, b FirecrackerLinuxBackend, root, mode string, ttl int, files []InputFile) linuxGuestBinding {
		t.Helper()
		id, _ := randomID()
		binding, err := newLinuxGuestBinding(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, err := call(b, root, linuxJobRequest{Operation: "prepare", Prepare: &linuxPrepareRequest{Binding: binding, Mode: mode, TTLMS: ttl, InputFiles: files}}); err != nil || !ok {
			t.Fatalf("prepare: %v %t", err, ok)
		}
		return binding
	}
	t.Run("session-input-readonly-and-repeated-prepare", func(t *testing.T) {
		b, root, exited := boot(t)
		binding := prepare(t, b, root, "session", 10000, []InputFile{{Path: "nested/prompt", Data: []byte("pristine-input")}, {Path: "script", Data: []byte("#!/bin/sh\nprintf escaped")}})
		r, ok, err := call(b, root, linuxJobRequest{Operation: "run", Binding: &binding, Argv: []string{"/bin/sh", "-c",
			"cat /input/nested/prompt; /bin/busybox id -u; /bin/busybox grep ' /input ' /proc/mounts; if printf changed > /input/nested/prompt; then exit 31; fi; if /input/script; then exit 32; fi; printf same-vm > /workspace/marker"}, TimeoutMS: 3000})
		if err != nil || !ok {
			t.Fatalf("bound run: %s %v", r, err)
		}
		var result struct {
			Stdout string `json:"stdout"`
		}
		if json.Unmarshal(r, &result) != nil || !strings.Contains(result.Stdout, "pristine-input10000") || !strings.Contains(result.Stdout, "ro,nosuid,nodev,noexec") {
			t.Fatalf("input/uid/mount flags: %s", r)
		}
		r, ok, err = call(b, root, linuxJobRequest{Operation: "run", Binding: &binding, Argv: []string{"/bin/sh", "-c", "cat /workspace/marker"}, TimeoutMS: 3000})
		if err != nil || !ok || !strings.Contains(string(r), "same-vm") {
			t.Fatalf("session persistence: %s %v", r, err)
		}
		_, _, err = call(b, root, linuxJobRequest{Operation: "prepare", Prepare: &linuxPrepareRequest{Binding: binding, Mode: "session", TTLMS: 1000}})
		if err == nil {
			t.Fatal("repeated preparation accepted")
		}
		exit(t, exited)
	})
	t.Run("run-before-prepare", func(t *testing.T) {
		b, root, exited := boot(t)
		if _, _, err := call(b, root, linuxJobRequest{Operation: "run", Argv: []string{"/bin/sh", "-c", "printf should-not-run"}, TimeoutMS: 1000}); err == nil {
			t.Fatal("early execution accepted")
		}
		exit(t, exited)
	})
	t.Run("legacy-downgrade", func(t *testing.T) {
		b, root, exited := boot(t)
		b.Pristine = false
		if _, _, err := call(b, root, linuxJobRequest{Operation: "ping"}); err == nil {
			t.Fatal("legacy protocol accepted")
		}
		exit(t, exited)
	})
	t.Run("wrong-nonce", func(t *testing.T) {
		b, root, exited := boot(t)
		binding := prepare(t, b, root, "session", 10000, nil)
		if binding.Nonce[0] == 'a' {
			binding.Nonce = "b" + binding.Nonce[1:]
		} else {
			binding.Nonce = "a" + binding.Nonce[1:]
		}
		if _, _, err := call(b, root, linuxJobRequest{Operation: "ping", Binding: &binding}); err == nil {
			t.Fatal("wrong nonce accepted")
		}
		exit(t, exited)
	})
	t.Run("one-shot-job", func(t *testing.T) {
		b, root, exited := boot(t)
		binding := prepare(t, b, root, "job", 10000, nil)
		r, ok, err := call(b, root, linuxJobRequest{Operation: "run", Binding: &binding, Argv: []string{"/bin/sh", "-c", "printf one-shot"}, TimeoutMS: 1000})
		if err != nil || !ok || !strings.Contains(string(r), "one-shot") {
			t.Fatalf("one-shot: %s %v", r, err)
		}
		exit(t, exited)
	})
	t.Run("idle-lease-expiry", func(t *testing.T) {
		b, root, exited := boot(t)
		prepare(t, b, root, "session", 1000, nil)
		exit(t, exited)
	})
	t.Run("guest-rejects-parent-conflict", func(t *testing.T) {
		b, root, exited := boot(t)
		id, _ := randomID()
		binding, _ := newLinuxGuestBinding(id)
		request := linuxJobRequest{Protocol: linuxPristineProtocol, JobID: id, Operation: "prepare", Prepare: &linuxPrepareRequest{Binding: binding, Mode: "session", TTLMS: 10000, InputFiles: []InputFile{{Path: "a", Data: []byte{}}, {Path: "a-", Data: []byte{}}, {Path: "a/b", Data: []byte{}}}}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		socket, _ := b.vsockPath(root)
		conn, reader, stop, err := dialFirecrackerVsock(ctx, socket, b.Guest.VsockPort)
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		defer conn.Close()
		if err := json.NewEncoder(conn).Encode(request); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(io.LimitReader(reader, 16384)).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		result, valid, ok := extractGuestResultFor(line, id, linuxResultPrefix, linuxPristineProtocol)
		if !valid || ok || !strings.Contains(string(result), "conflict") {
			t.Fatalf("guest input validation: %s", line)
		}
		exit(t, exited)
	})
}
