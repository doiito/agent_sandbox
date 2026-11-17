package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSignedDiagnosticAndWarmPoolOwnAndReconcileRunRoot(t *testing.T) {
	for _, mode := range []string{"production", "signed-osv", "warm-pool"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			orphan := filepath.Join(root, "job-0123456789abcdef01234567-1")
			if err := os.Mkdir(orphan, 0o700); err != nil {
				t.Fatal(err)
			}
			unrelated := filepath.Join(root, "operator-data")
			if err := os.WriteFile(unrelated, []byte("retain"), 0o600); err != nil {
				t.Fatal(err)
			}
			c := Config{RunRoot: root}
			switch mode {
			case "production":
				c.Production = true
			case "signed-osv":
				c.Backend, c.Jailer, c.ArtifactManifest = "firecracker-osv", &JailerConfig{}, &ArtifactManifestConfig{}
			case "warm-pool":
				c.WarmPool = &WarmPoolConfig{Enabled: true}
			}
			lock, count, err := claimManagedRunRoot(c)
			if err != nil || lock == nil || count != 1 {
				t.Fatalf("runtime skipped exclusive reconciliation: count=%d error=%v", count, err)
			}
			defer lock.Close()
			if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("orphan retained")
			}
			if contents, err := os.ReadFile(unrelated); err != nil || string(contents) != "retain" {
				t.Fatal("reconciliation touched unrelated data")
			}
			second, _, err := claimManagedRunRoot(c)
			if second != nil || err == nil {
				t.Fatal("concurrent manager could reuse the same identities")
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			replacement, count, err := claimManagedRunRoot(c)
			if err != nil || replacement == nil || count != 0 {
				t.Fatalf("ownership not recoverable after close: %v", err)
			}
			_ = replacement.Close()
		})
	}
}

func TestManagedRunRootReleasesLockWhenReconciliationFails(t *testing.T) {
	c := Config{RunRoot: t.TempDir(), WarmPool: &WarmPoolConfig{Enabled: true}, Jailer: &JailerConfig{ParentCgroup: "../unsafe"}}
	if lock, _, err := claimManagedRunRoot(c); err == nil || lock != nil {
		t.Fatal("invalid recovery parent accepted")
	}
	c.Jailer.ParentCgroup = ""
	lock, _, err := claimManagedRunRoot(c)
	if err != nil || lock == nil {
		t.Fatalf("failed initialization leaked exclusive lock: %v", err)
	}
	_ = lock.Close()
}

func TestReconcileRunRootRemovesOnlyJobDirectories(t *testing.T) {
	root := t.TempDir()
	job := filepath.Join(root, "job-0123456789abcdef01234567-1")
	if err := os.Mkdir(job, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "lease.json"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "operator-data")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	count, err := reconcileRunRoot(root, "")
	if err != nil || count != 1 {
		t.Fatalf("unexpected reconciliation: count=%d err=%v", count, err)
	}
	if _, err := os.Stat(job); !os.IsNotExist(err) {
		t.Fatal("orphan job directory remains")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("reconciliation removed unrelated data")
	}
}

func TestProcessStartTimeReadsCurrentProcess(t *testing.T) {
	if value, err := processStartTime(os.Getpid()); err != nil || value == 0 {
		t.Fatalf("invalid process start time %d: %v", value, err)
	}
}

func TestReconcileRunRootUsesCgroupAndNeverSignalsLeasePID(t *testing.T) {
	runRoot, cgroupRoot := t.TempDir(), t.TempDir()
	jobID := "job-0123456789abcdef01234567-a1b2c3"
	job := filepath.Join(runRoot, jobID)
	leaf := filepath.Join(cgroupRoot, jobID)
	for _, path := range []string{job, leaf} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A forged but structurally valid lease must not cause a PID or PGID kill.
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	if err := writeProcessLease(job, child.Process.Pid); err != nil {
		t.Fatal(err)
	}
	terminated := 0
	count, err := reconcileRunRootAt(runRoot, cgroupRoot, func(path string) error {
		if path != leaf {
			t.Fatalf("unexpected cgroup: %s", path)
		}
		terminated++
		return os.Remove(path)
	})
	if err != nil || count != 1 || terminated != 1 {
		t.Fatalf("unexpected reconciliation count=%d terminated=%d err=%v", count, terminated, err)
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated lease PID was signalled: %v", err)
	}
	if _, err := os.Stat(job); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan workdir remains: %v", err)
	}
}

func TestReconcileRunRootHandlesCgroupOnlyAndPreservesUnrelatedEntries(t *testing.T) {
	runRoot, cgroupRoot := t.TempDir(), t.TempDir()
	jobID := "job-fedcba9876543210fedcba98-1"
	for _, name := range []string{jobID, "operator-data", "job-invalid"} {
		if err := os.Mkdir(filepath.Join(cgroupRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	count, err := reconcileRunRootAt(runRoot, cgroupRoot, os.Remove)
	if err != nil || count != 1 {
		t.Fatalf("unexpected reconciliation count=%d err=%v", count, err)
	}
	for _, name := range []string{"operator-data", "job-invalid"} {
		if _, err := os.Stat(filepath.Join(cgroupRoot, name)); err != nil {
			t.Fatalf("removed unrelated cgroup %s: %v", name, err)
		}
	}
}

func TestReconcileRunRootFailsClosedOnCgroupFailureOrMissingLeaf(t *testing.T) {
	for _, tc := range []struct {
		name, lease string
		leaf        bool
	}{
		{name: "kill-failure", lease: "invalid", leaf: true},
		{name: "live-lease-without-leaf", lease: "live", leaf: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runRoot, cgroupRoot := t.TempDir(), t.TempDir()
			jobID := "job-0123456789abcdef01234567-z9"
			job := filepath.Join(runRoot, jobID)
			if err := os.Mkdir(job, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.lease == "live" {
				if err := writeProcessLease(job, os.Getpid()); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(job, "lease.json"), []byte("invalid"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.leaf {
				if err := os.Mkdir(filepath.Join(cgroupRoot, jobID), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			count, err := reconcileRunRootAt(runRoot, cgroupRoot, func(string) error { return errors.New("injected kill failure") })
			if err == nil || count != 0 {
				t.Fatalf("unsafe recovery succeeded: count=%d err=%v", count, err)
			}
			if _, err := os.Stat(job); err != nil {
				t.Fatalf("recovery discarded evidence: %v", err)
			}
		})
	}
}

// Run only in an isolated Linux host validation session as root. This checks
// the kernel cgroup.kill path rather than a mocked terminator.
func TestCgroupRecoveryOnHost(t *testing.T) {
	if os.Getenv("OSV_CGROUP_RECOVERY_E2E") != "1" {
		t.Skip("requires isolated host cgroup validation")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	runRoot := t.TempDir()
	parentName := fmt.Sprintf("osv-sandbox-recovery-e2e-%d", os.Getpid())
	cgroupRoot := filepath.Join("/sys/fs/cgroup", parentName)
	if err := os.Mkdir(cgroupRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		entries, _ := os.ReadDir(cgroupRoot)
		for _, entry := range entries {
			if validJobInstanceID(entry.Name()) {
				_ = terminateCgroupPath(filepath.Join(cgroupRoot, entry.Name()), 3*time.Second)
			}
		}
		_ = os.Remove(cgroupRoot)
	})
	startSleep := func() *exec.Cmd {
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	sentinel := startSleep()
	jobs := []string{"job-0123456789abcdef01234567-a", "job-fedcba9876543210fedcba98-b"}
	for index, jobID := range jobs {
		leaf := filepath.Join(cgroupRoot, jobID)
		if err := os.Mkdir(leaf, 0o755); err != nil {
			t.Fatal(err)
		}
		member := startSleep()
		if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(strconv.Itoa(member.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		membership, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(member.Process.Pid), "cgroup"))
		if err != nil || !strings.Contains(string(membership), parentName+"/"+jobID) {
			t.Fatalf("member not in isolated leaf: %q %v", membership, err)
		}
		if index == 0 {
			workdir := filepath.Join(runRoot, jobID)
			if err := os.Mkdir(workdir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := writeProcessLease(workdir, sentinel.Process.Pid); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Mkdir(filepath.Join(cgroupRoot, "operator-data"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(cgroupRoot, "operator-data")) })
	count, err := reconcileRunRoot(runRoot, parentName)
	if err != nil || count != 2 {
		t.Fatalf("kernel cgroup recovery failed: count=%d err=%v", count, err)
	}
	if err := sentinel.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was killed: %v", err)
	}
	for _, jobID := range jobs {
		if _, err := os.Stat(filepath.Join(cgroupRoot, jobID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan cgroup remains: %s: %v", jobID, err)
		}
	}
	if _, err := os.Stat(filepath.Join(runRoot, jobs[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan workdir remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, "operator-data")); err != nil {
		t.Fatalf("unrelated cgroup was removed: %v", err)
	}
}
