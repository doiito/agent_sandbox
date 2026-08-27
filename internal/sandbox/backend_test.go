package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOSvCommandLineQuotesSeparators(t *testing.T) {
	got, err := OSvCommandLine("/agent", []string{"hello world", `a;b&c!d`, `quote"slash\`})
	if err != nil {
		t.Fatal(err)
	}
	want := `"/agent" "hello world" "a;b&c!d" "quote\"slash\\"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestQEMUHardeningAndNoNetwork(t *testing.T) {
	req := RunRequest{Entrypoint: "/agent", MemoryMiB: 128, VCPUs: 1}
	args, err := BuildQEMUArgs(req, ResolvedArtifacts{KernelPath: "/a/kernel", ImagePath: "/a/image", Format: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"-nic none", "readonly=on", "-nodefaults", "-no-user-config", "-display none", "-monitor none", "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny", "-enable-kvm"} {
		if !strings.Contains(joined, required) {
			t.Errorf("missing hardening option %q in %s", required, joined)
		}
	}
	if strings.Contains(joined, "-nographic") {
		t.Fatal("-nographic conflicts with the explicit serial backend on QEMU 6.2")
	}
}

func TestQEMURejectsDriveOptionInjection(t *testing.T) {
	req := RunRequest{Entrypoint: "/agent", MemoryMiB: 128, VCPUs: 1}
	_, err := BuildQEMUArgs(req, ResolvedArtifacts{KernelPath: "/a/kernel", ImagePath: "/a/image,cache=unsafe", Format: "raw"})
	if err == nil {
		t.Fatal("expected comma-bearing image path to be rejected")
	}
}

func TestRejectsOSvEnvironmentExpansion(t *testing.T) {
	c := testConfig()
	r := RunRequest{Entrypoint: "/agent", Args: []string{"$SECRET"}, MemoryMiB: 128, VCPUs: 1, TimeoutMS: 1000, Network: "none"}
	if err := r.Validate(c); err == nil {
		t.Fatal("expected '$' to be rejected")
	}
}

func TestFirecrackerJailerStagesReadOnlyGuestAndLimits(t *testing.T) {
	artifactDir := t.TempDir()
	kernel := filepath.Join(artifactDir, "kernel")
	image := filepath.Join(artifactDir, "rootfs.raw")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(t.TempDir(), "job-a1b2")
	if err := os.Mkdir(workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := FirecrackerBackend{
		Path: "/usr/local/bin/firecracker",
		Jailer: &JailerConfig{Path: "/usr/local/bin/jailer", UID: 65534, GID: 65534,
			CgroupVersion: 2, MemoryOverheadMiB: 128, NoFileLimit: 128},
	}
	req := RunRequest{Entrypoint: "/agent", MemoryMiB: 128, VCPUs: 1}
	cmd, err := b.Command(context.Background(), req, ResolvedArtifacts{KernelPath: kernel, ImagePath: image, Format: "raw"}, workdir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmd.Args, " ")
	for _, required := range []string{
		"--uid 65534", "--gid 65534", "--cgroup-version 2",
		"--cgroup memory.max=268435456", "--resource-limit no-file=128",
		"-- --no-api --config-file /config.json",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("missing jailer option %q in %s", required, joined)
		}
	}
	root := filepath.Join(workdir, "jailer", "firecracker", "job-a1b2", "root")
	for _, name := range []string{"kernel", "rootfs", "config.json"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("staged %s: %v", name, err)
		}
		if info.Mode().Perm()&0o222 != 0 {
			t.Errorf("staged %s is writable: mode %o", name, info.Mode().Perm())
		}
	}
	config, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), artifactDir) || !strings.Contains(string(config), `"kernel_image_path":"/kernel"`) {
		t.Fatalf("jailed config leaks host paths or lacks jailed path: %s", config)
	}
}

func TestJailerConfigurationRequiresFirecracker(t *testing.T) {
	c := testConfig()
	c.Jailer = &JailerConfig{}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected jailer with qemu backend to be rejected")
	}
}

func TestFirecrackerLinuxStagesRootfsScratchAndVsock(t *testing.T) {
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)
	artifactDir := t.TempDir()
	kernel := filepath.Join(artifactDir, "vmlinux")
	rootfs := filepath.Join(artifactDir, "rootfs.ext4")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(t.TempDir(), "job-linux-a1b2")
	if err := os.Mkdir(workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := FirecrackerLinuxBackend{
		Path: "/usr/local/bin/firecracker",
		Jailer: &JailerConfig{Path: "/usr/local/bin/jailer", UID: os.Getuid(), GID: os.Getgid(),
			CgroupVersion: 2, MemoryOverheadMiB: 128, NoFileLimit: 128},
		Guest: LinuxGuestConfig{ScratchMiB: 32, InputMiB: 16, VsockPort: 5000, MkfsPath: "/bin/true"},
	}
	req := RunRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "echo $HOME"}, InputFiles: []InputFile{{Path: "prompt.txt", Data: []byte("hello")}}, MemoryMiB: 256, VCPUs: 1}
	cmd, err := b.Command(context.Background(), req, ResolvedArtifacts{KernelPath: kernel, ImagePath: rootfs, Format: "raw"}, workdir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "memory.max=402653184") {
		t.Fatalf("missing Linux cgroup memory limit: %v", cmd.Args)
	}
	root := filepath.Join(workdir, "jailer", "firecracker", "job-linux-a1b2", "root")
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("jail root mode is not independent of service umask: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(root, "config.json")); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("config mode is not independent of service umask: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(workdir, "input-root", "prompt.txt")); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("input mode is not independent of service umask: info=%v err=%v", info, err)
	}
	config, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"path_on_host":"/rootfs.ext4"`, `"path_on_host":"/scratch.ext4"`, `"path_on_host":"/input.ext4"`, `"is_read_only":true`, `"uds_path":"/agent.vsock"`, `init=/sbin/agent-init`} {
		if !strings.Contains(string(config), required) {
			t.Errorf("Linux config missing %s: %s", required, config)
		}
	}
	if info, err := os.Stat(filepath.Join(root, "scratch.ext4")); err != nil || info.Size() != 32*1024*1024 {
		t.Fatalf("unexpected scratch image: info=%v err=%v", info, err)
	}
}

func TestLinuxInputValidationRejectsTraversal(t *testing.T) {
	c := Config{ArtifactRoot: "/tmp", Backend: "firecracker-linux", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{"/bin/cat"}}
	c.ApplyDefaults()
	r := RunRequest{Entrypoint: "/bin/cat", InputFiles: []InputFile{{Path: "../secret", Data: []byte("x")}}, MemoryMiB: 128, VCPUs: 1, TimeoutMS: 1000, Network: "none"}
	if err := r.Validate(c); err == nil {
		t.Fatal("expected input path traversal to be rejected")
	}
}

func TestLinuxBackendAllowsShellExpansionAsData(t *testing.T) {
	c := Config{ArtifactRoot: "/tmp", Backend: "firecracker-linux", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{"/bin/sh"}}
	c.ApplyDefaults()
	r := RunRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "echo $HOME"}, MemoryMiB: 128, VCPUs: 1, TimeoutMS: 1000, Network: "none"}
	if err := r.Validate(c); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxBackendRequiresProtocolEnvelopeBudget(t *testing.T) {
	c := Config{ArtifactRoot: "/tmp", Backend: "firecracker-linux", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{"/bin/true"}}
	c.ApplyDefaults()
	c.Limits.MaxOutputByte = 8 * 1024
	if err := c.Validate(); err == nil {
		t.Fatal("expected undersized Linux output envelope budget to be rejected")
	}
}

func TestLinuxResultRequiresLinuxProtocol(t *testing.T) {
	line := `FC_AGENT_RESULT {"protocol":"fc-agent/v1","job_id":"0123456789abcdef01234567","ok":true}` + "\n"
	if _, ok, guestOK := extractGuestResultFor(line, "0123456789abcdef01234567", linuxResultPrefix, linuxGuestProtocol); !ok || !guestOK {
		t.Fatal("valid Linux result was rejected")
	}
	if _, ok, _ := extractGuestResult(line, "0123456789abcdef01234567"); ok {
		t.Fatal("Linux result must not be accepted as an OSv result")
	}
}

func testConfig() Config {
	c := Config{ArtifactRoot: "/tmp", AllowedEntrypoints: []string{"/agent"}}
	c.ApplyDefaults()
	return c
}
