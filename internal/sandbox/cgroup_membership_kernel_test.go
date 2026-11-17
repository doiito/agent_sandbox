package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a real cgroup v2 test, explicitly provisioned under the external host
// validation flock. Default CI/QEMU must not claim kernel coverage by skipping it.
func TestPristineMemberKernelMigrationAndThreadedDomain(t *testing.T) {
	parent := os.Getenv("OSV_CGROUP_TEST_PARENT")
	if parent == "" {
		t.Skip("requires isolated root-owned cgroup fixture and host validation lock")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(parent, "osv-offline-validation-20261030-") || strings.Contains(parent, "/") || !safeCgroupName(parent) {
		t.Fatal("invalid provisioned cgroup fixture")
	}
	root := filepath.Join("/sys/fs/cgroup", parent)
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(root); err != nil {
			t.Error("parent cleanup:", err)
		}
	})
	mkdir := func(path string) string {
		t.Helper()
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error("leaf cleanup:", err)
			}
		})
		return path
	}
	expected := mkdir(filepath.Join(root, "job-0123456789abcdef01234567-1"))
	foreign := mkdir(filepath.Join(root, "job-0123456789abcdef01234567-2"))
	descendant := mkdir(filepath.Join(expected, "child"))
	threadRoot := mkdir(filepath.Join(root, "job-0123456789abcdef01234567-3"))
	threadLeaf := mkdir(filepath.Join(threadRoot, "thread"))
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	pid := command.Process.Pid
	move := func(path string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600); err != nil {
			t.Fatal("migrate own child:", err)
		}
	}
	verify := func(path string, accepted bool) {
		t.Helper()
		err := verifyPristineCgroup(&JailerConfig{ParentCgroup: parent}, pid, path)
		if (err == nil) != accepted {
			t.Fatalf("membership accepted=%v want=%v for %s: %v", err == nil, accepted, filepath.Base(path), err)
		}
	}
	verify(expected, false)
	move(expected)
	verify(expected, true)
	other := exec.Command("/bin/sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	otherWaited := false
	t.Cleanup(func() {
		if !otherWaited {
			_ = other.Process.Kill()
			_ = other.Wait()
		}
	})
	if err := os.WriteFile(filepath.Join(expected, "cgroup.procs"), []byte(strconv.Itoa(other.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	verify(expected, false)
	_ = other.Process.Kill()
	_ = other.Wait()
	otherWaited = true
	move(foreign)
	verify(expected, false)
	move(descendant)
	verify(expected, false)
	if err := os.WriteFile(filepath.Join(threadLeaf, "cgroup.type"), []byte("threaded"), 0600); err != nil {
		t.Fatal("create threaded fixture:", err)
	}
	move(threadLeaf)
	data, err := os.ReadFile(filepath.Join(threadRoot, "cgroup.procs"))
	if err != nil || !strings.Contains("\n"+string(data), "\n"+strconv.Itoa(pid)+"\n") {
		t.Fatal("threaded root does not demonstrate descendant aggregation", err)
	}
	verify(threadRoot, false)
	move(expected)
	verify(expected, true)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		_, state, err := readProcessStat(pid)
		if err != nil {
			t.Fatal("lost unreaped own child:", err)
		}
		if state == 'Z' {
			break
		}
		if time.Now().After(until) {
			t.Fatal("own child did not become zombie")
		}
		time.Sleep(time.Millisecond)
	}
	verify(expected, false)
	_ = command.Wait()
	waited = true
}

func TestPristineMemberProvisionedFirecracker(t *testing.T) {
	runRoot := os.Getenv("OSV_CGROUP_VM_RUN_ROOT")
	if runRoot == "" {
		t.Skip("requires signed pristine Firecracker fixture under host validation lock")
	}
	fixture := filepath.Dir(runRoot)
	parent := filepath.Base(fixture)
	if os.Geteuid() != 0 || filepath.Dir(fixture) != "/var/lib" || filepath.Base(runRoot) != "run" ||
		!strings.HasPrefix(parent, "osv-offline-validation-20261030-") || !safeCgroupName(parent) {
		t.Fatal("invalid provisioned Firecracker fixture")
	}
	paths, err := filepath.Glob(filepath.Join(runRoot, "job-*", "lease.json"))
	if err != nil {
		t.Fatal(err)
	}
	checked, workers := 0, 0
	for _, path := range paths {
		lease, err := readProcessLease(path)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Phase != string(vmReady) {
			continue
		}
		ticks, state, err := readProcessStat(lease.PID)
		if err != nil || ticks != lease.StartTimeTicks || state == 'Z' || state == 'X' {
			t.Fatal("provisioned VMM identity is not live", err)
		}
		if err := verifyPristineCgroup(&JailerConfig{ParentCgroup: parent}, lease.PID, filepath.Dir(path)); err != nil {
			t.Fatal("real KVM cgroup rejected:", err)
		}
		members, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", parent, filepath.Base(filepath.Dir(path)), "cgroup.procs"))
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range strings.Fields(string(members)) {
			if member != strconv.Itoa(lease.PID) {
				workers++
			}
		}
		ticks, _, err = readProcessStat(lease.PID)
		if err != nil || ticks != lease.StartTimeTicks {
			t.Fatal("VMM generation changed after membership proof", err)
		}
		checked++
	}
	if checked < 2 || workers < 2 {
		t.Fatalf("real KVM worker coverage missing: vms=%d workers=%d", checked, workers)
	}
	t.Logf("verified %d real pristine Firecracker instances with %d kernel worker members", checked, workers)
}
