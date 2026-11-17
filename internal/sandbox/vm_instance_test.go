package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Deliberately ignores cancellation while staging and returns a command with
// an unrelated context. The owner must still prevent a post-cleanup launch.
type stagingVMBackend struct {
	entered, proceed chan struct{}
	marker           string
}

func (b stagingVMBackend) Name() string { return "staging-helper" }
func (b stagingVMBackend) Command(context.Context, RunRequest, ResolvedArtifacts, string) (*exec.Cmd, error) {
	close(b.entered)
	<-b.proceed
	return exec.Command("/bin/sh", "-c", "printf launched > \"$1\"", "sh", b.marker), nil
}

func TestVMOwnerShutdownDuringStagingDoesNotLaunchAfterCleanup(t *testing.T) {
	m := testManager(t, "output")
	backend := stagingVMBackend{entered: make(chan struct{}), proceed: make(chan struct{}),
		marker: filepath.Join(t.TempDir(), "unexpected-launch")}
	m.backend = backend
	var once sync.Once
	unblock := func() { once.Do(func() { close(backend.proceed) }) }
	defer unblock()
	runDone := make(chan error, 1)
	go func() { _, err := m.Run(context.Background(), RunRequest{}); runDone <- err }()
	select {
	case <-backend.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not enter staging")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked staging was reported clean: %v", err)
	}
	if c := m.Capacity(); c.Active != 1 || c.Instances != 1 {
		t.Fatalf("shutdown returned reservation before staging stopped: %+v", c)
	}
	if snapshot := m.VMInstances(); !snapshot.Stopping || snapshot.States[string(vmBooting)] != 1 {
		t.Fatalf("staging ownership was lost: %+v", snapshot)
	}
	if _, err := m.Run(context.Background(), RunRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("shutdown admitted another request: %v", err)
	}
	unblock()
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("staging cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("staging did not finish after release")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.Shutdown(ctx2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backend.marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a process launched after shutdown: %v", err)
	}
	assertVMOwnerEmpty(t, m)
}

func TestVMOwnerConcurrentDestroyCancelAndShutdown(t *testing.T) {
	m := testManager(t, "sleep")
	physical, active, err := m.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, err := m.startVM(ctx, m.backend, RunRequest{Args: []string{"--sandbox-job-id", "0123456789abcdef01234567"}}, physical)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.activate(); err != nil {
		t.Fatal(err)
	}
	lease, err := readProcessLease(filepath.Join(v.workdir, "lease.json"))
	if err != nil || !processMatchesLease(lease) {
		t.Fatalf("started process did not retain its durable identity: %+v %v", lease, err)
	}
	var workers sync.WaitGroup
	for range 24 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := v.Destroy(); err != nil {
				t.Error(err)
				return
			}
			active.release()
		}()
	}
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := m.Shutdown(shutdownCtx); err != nil {
		t.Error(err)
	}
	workers.Wait()
	select {
	case <-v.exited:
	default:
		t.Fatal("destroy returned before Wait completed")
	}
	if v.activate() == nil {
		t.Fatal("a destroyed instance became active again")
	}
	assertVMOwnerEmpty(t, m)
}

func TestVMOwnerShortJobsPersistLeaseBeforeReaping(t *testing.T) {
	m := testManager(t, "output")
	for range 16 {
		result, err := m.Run(context.Background(), RunRequest{})
		if err != nil || result.State != "succeeded" || !result.ProtocolOK {
			t.Fatalf("short-lived process result lost: %+v %v", result, err)
		}
	}
	assertVMOwnerEmpty(t, m)
}

func TestVMOwnerFailedCleanupRetainsRegistryAndBudget(t *testing.T) {
	m := testManager(t, "output")
	// An invalid cgroup parent prevents cleanup before any VMM is launched.
	m.config.Jailer = &JailerConfig{ParentCgroup: "../unsafe"}
	if _, err := m.Run(context.Background(), RunRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsafe cleanup did not fail closed: %v", err)
	}
	snapshot := m.VMInstances()
	if snapshot.States[string(vmCleanupFailed)] != 1 || m.Capacity().Active != 1 ||
		m.Capacity().Instances != 1 || !m.Capacity().Blocked {
		t.Fatalf("failed owner was forgotten: %+v %+v", snapshot, m.Capacity())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("shutdown hid failed cleanup: %v", err)
	}
	if m.Doctor().VMInstances.States[string(vmCleanupFailed)] != 1 {
		t.Fatal("doctor omitted retained ownership")
	}
}

type groupVMBackend struct{ marker string }

func (b groupVMBackend) Name() string { return "process-group-helper" }
func (b groupVMBackend) Command(ctx context.Context, _ RunRequest, _ ResolvedArtifacts, _ string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & printf %s \"$!\" > \"$1\"; wait", "sh", b.marker), nil
}

func TestVMProcessGroupCancellationIncludesChild(t *testing.T) {
	m := testManager(t, "output")
	marker := filepath.Join(t.TempDir(), "child.pid")
	physical, active, err := m.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	v, err := m.startVM(context.Background(), groupVMBackend{marker}, RunRequest{}, physical)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v.Destroy(); active.release() }()
	var child int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(marker)
		if pid, err := strconv.Atoi(string(data)); err == nil && pid > 1 {
			child = pid
			break
		}
		time.Sleep(time.Millisecond)
	}
	if child == 0 {
		t.Fatal("helper did not create a child")
	}
	defer syscall.Kill(child, syscall.SIGKILL)
	if err := v.Destroy(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child), "stat"))
		// A killed orphan can await reaping by the container's init process.
		if errors.Is(err, os.ErrNotExist) || (err == nil && strings.Contains(string(stat), ") Z ")) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("cancellation left a running child process")
}

func assertVMOwnerEmpty(t *testing.T, m *Manager) {
	t.Helper()
	c := m.Capacity()
	if c.Active != 0 || c.Instances != 0 || c.ReservedMemoryMiB != 0 || c.ReservedVCPUs != 0 || c.ReservedPids != 0 ||
		len(m.VMInstances().States) != 0 {
		t.Fatalf("owner leaked capacity: %+v %+v", c, m.VMInstances())
	}
	entries, err := os.ReadDir(m.config.RunRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owner leaked workdirs: %v %v", entries, err)
	}
}
