package sandbox

import (
	"context"
	"encoding/json"
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

// This opt-in probe attributes cold boot initialization. Verbose boot output
// changes timing; its duration must never become performance-gate evidence.
func TestLinuxColdBootInitializationOnKVM(t *testing.T) {
	path := os.Getenv("OSV_COLD_BOOT_KVM_CONFIG")
	if path == "" {
		t.Skip("set OSV_COLD_BOOT_KVM_CONFIG to an idle isolated signed fixture")
	}
	if os.Geteuid() != 0 || !strings.Contains(path, "/osv-offline-validation-") {
		t.Fatal("requires root and isolated fixture")
	}
	mode := os.Getenv("OSV_COLD_BOOT_PROBE_MODE")
	if mode == "" {
		mode = "baseline-verbose"
	}
	switch mode {
	case "baseline-verbose", "no-ps2-verbose", "no-ps2-quiet", "baseline-quiet":
	default:
		t.Fatal("unsupported cold boot diagnostic mode")
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend != "firecracker-linux" || c.Jailer == nil || c.LinuxGuest == nil {
		t.Fatal("requires jailed Linux backend")
	}
	if jobs, err := filepath.Glob(filepath.Join(c.RunRoot, "job-*")); err != nil || len(jobs) != 0 {
		t.Fatal("fixture must have no active pool or job")
	}
	a, err := ResolveArtifacts(c.ArtifactRoot, c.Kernel, c.Image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArtifactManifest(c, a); err != nil {
		t.Fatal(err)
	}
	jailer := *c.Jailer
	jailer.UID += 900
	jailer.GID += 900
	if _, err := user.LookupId(strconv.Itoa(jailer.UID)); err == nil {
		t.Fatal("diagnostic UID already assigned")
	}
	if _, err := user.LookupGroupId(strconv.Itoa(jailer.GID)); err == nil {
		t.Fatal("diagnostic GID already assigned")
	}
	b := FirecrackerLinuxBackend{Path: c.HypervisorPath, Jailer: &jailer, Guest: *c.LinuxGuest,
		OutputLimit: 512 * 1024, Pristine: true}
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	workdir, err := os.MkdirTemp(c.RunRoot, "job-"+id+"-")
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
				t.Error("diagnostic VMM did not exit")
			}
		}
		if err := cleanupCgroupWithDeadline(jailer.ParentCgroup, filepath.Base(workdir), 3*time.Second); err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(workdir); err != nil {
			t.Error(err)
		}
	})
	request := RunRequest{Entrypoint: "/bin/sh", MemoryMiB: 128, VCPUs: 1, TimeoutMS: 5000,
		jailUID: jailer.UID, jailGID: jailer.GID}
	command, err = b.Command(ctx, request, a, workdir)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := b.vsockPath(workdir)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(filepath.Dir(socket), "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var bootConfig map[string]any
	if err := json.Unmarshal(data, &bootConfig); err != nil {
		t.Fatal(err)
	}
	boot := bootConfig["boot-source"].(map[string]any)
	args := strings.Fields(boot["boot_args"].(string))
	selected := make([]string, 0, len(args)+2)
	for _, arg := range args {
		if strings.HasPrefix(mode, "baseline-") && (arg == "i8042.nokbd=1" || arg == "i8042.noaux=1") {
			continue
		}
		if strings.HasSuffix(mode, "-verbose") && (arg == "quiet" || strings.HasPrefix(arg, "loglevel=")) {
			continue
		}
		selected = append(selected, arg)
	}
	if strings.HasSuffix(mode, "-verbose") {
		selected = append(selected, "loglevel=7", "printk.time=1", "initcall_debug")
	}
	boot["boot_args"] = strings.Join(selected, " ")
	data, err = json.Marshal(bootConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := prepareJobCgroup(jailer, filepath.Base(workdir), workdir); err != nil {
		t.Fatal(err)
	}
	output := &limitedBuffer{limit: 512 * 1024}
	command.Dir = workdir
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = output, output
	started := time.Now()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited = make(chan struct{})
	go func() { _ = command.Wait(); close(exited) }()
	if err := writeProcessLease(workdir, command.Process.Pid); err != nil {
		t.Fatal(err)
	}
	go moveKVMPITThread(ctx.Done(), command.Process.Pid,
		filepath.Join("/sys/fs/cgroup", jailer.ParentCgroup, filepath.Base(workdir)))
	resultParent := filepath.Join(filepath.Dir(path), "results", "cold-boot")
	if err := os.MkdirAll(resultParent, 0o700); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(resultParent, mode)
	if err := os.Mkdir(resultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Preserve bounded console output even when guest readiness or execution fails.
	t.Cleanup(func() {
		if err := writeFileExact(filepath.Join(resultDir, "console.log"), []byte(output.String()), 0o600); err != nil {
			t.Error(err)
		}
	})
	driver := linuxPristineVMBackend{b}
	if _, err := driver.probeVM(ctx, workdir); err != nil {
		t.Fatal(err)
	}
	readyUS := time.Since(started).Microseconds()
	if err := verifyPristineCgroup(&jailer, command.Process.Pid, workdir); err != nil {
		t.Fatal(err)
	}
	binding, err := newPristineBinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.prepareVM(ctx, pristinePreparation{Binding: binding, Mode: "session", TTLMS: 10000}, workdir); err != nil {
		t.Fatal(err)
	}
	request.jobID = id
	request.Args = []string{"-c", "printf COLD_BOOT_PROBE_OK"}
	raw, ok, err := driver.runVM(ctx, request, binding, workdir)
	var result struct {
		Stdout string `json:"stdout"`
	}
	output.mu.Lock()
	truncated := output.truncated
	output.mu.Unlock()
	if err != nil || !ok || json.Unmarshal(raw, &result) != nil || result.Stdout != "COLD_BOOT_PROBE_OK" || truncated {
		t.Fatalf("bound diagnostic command: ok=%t err=%v truncated=%t", ok, err, truncated)
	}
	receipt, err := json.MarshalIndent(map[string]any{
		"passed": true, "diagnostic": true, "formal_performance_evidence": false,
		"vm_id": id, "pid": command.Process.Pid, "boot_args": boot["boot_args"],
		"mode": mode, "readiness_us": readyUS, "pristine_ping_prepare_command_verified": true,
		"kernel_sha256": c.Kernel.SHA256, "image_sha256": c.Image.SHA256,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileExact(filepath.Join(resultDir, "receipt.json"), receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("verified fresh pristine VM; mode=%s readiness_us=%d (diagnostic only)", mode, readyUS)
}
