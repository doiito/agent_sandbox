package offlinebundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestSwitchVerifiesInstalledBytesAndRollsBack(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux release switch")
	}
	source, pub, priv := fixture(t)
	root := filepath.Join(t.TempDir(), "osv-offline-validation-unit")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runRoot := filepath.Join(root, "run")
	cgroupRoot := filepath.Join(root, "cgroup")
	for _, dir := range []string{runRoot, cgroupRoot} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	makeArchive := func(version, commit string) string {
		t.Helper()
		var out bytes.Buffer
		if err := Pack(source, &out, version, runtime.GOARCH, commit, time.Now().Add(24*time.Hour), priv); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(root, version+".tar")
		if err := os.WriteFile(archive, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(archive, pub, filepath.Join(root, "releases")); err != nil {
			t.Fatal(err)
		}
		return archive
	}
	first, second := makeArchive("v1", "abc123"), makeArchive("v2", "abc123")
	options := SwitchOptions{Archive: first, PublicKey: pub, Root: root, RunRoot: runRoot,
		CgroupRoot: cgroupRoot, CheckServices: func() error { return nil }}
	wantFirst := filepath.Join("releases", "v1-linux-"+runtime.GOARCH)
	wantSecond := filepath.Join("releases", "v2-linux-"+runtime.GOARCH)
	result, err := Switch(options)
	if err != nil || result.Active != wantFirst || result.Previous != "" || !result.Changed {
		t.Fatalf("first switch: %+v %v", result, err)
	}
	options.Archive = second
	result, err = Switch(options)
	if err != nil || result.Active != wantSecond || result.Previous != wantFirst || !result.Changed {
		t.Fatalf("upgrade: %+v %v", result, err)
	}
	options.Archive = first
	result, err = Switch(options)
	if err != nil || result.Active != wantFirst || result.Previous != wantSecond || !result.Changed {
		t.Fatalf("rollback: %+v %v", result, err)
	}
	dirty := makeArchive("v3", "abc123-dirty-test")
	options.Archive = dirty
	if _, err := Switch(options); err == nil {
		t.Fatal("dirty test candidate allowed without explicit flag")
	}
	options.AllowTestCandidate = true
	if _, err := Switch(options); err != nil {
		t.Fatalf("isolated dirty test switch: %v", err)
	}
	options.AllowTestCandidate = false
	options.Archive = first
	if _, err := Switch(options); err != nil {
		t.Fatalf("return from isolated test candidate: %v", err)
	}
	current := filepath.Join(root, "current")
	assertCurrent := func() {
		t.Helper()
		got, err := os.Readlink(current)
		if err != nil || got != wantFirst {
			t.Fatalf("current changed after refusal: %q %v", got, err)
		}
	}
	assertCurrent()
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", current); err != nil {
		t.Fatal(err)
	}
	if _, err := Switch(options); err == nil {
		t.Fatal("external current target accepted")
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(wantFirst, current); err != nil {
		t.Fatal(err)
	}
	options.CheckServices = func() error { return errors.New("service active") }
	if _, err := Switch(options); err == nil {
		t.Fatal("active service allowed switch")
	}
	options.CheckServices = func() error { return nil }
	assertCurrent()
	job := filepath.Join(runRoot, "job-active")
	if err := os.Mkdir(job, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Switch(options); err == nil {
		t.Fatal("run_root job allowed switch")
	}
	if err := os.Remove(job); err != nil {
		t.Fatal(err)
	}
	job = filepath.Join(cgroupRoot, "job-active")
	if err := os.Mkdir(job, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Switch(options); err == nil {
		t.Fatal("cgroup job allowed switch")
	}
	if err := os.Remove(job); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(runRoot, ".launcher.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := Switch(options); err == nil {
		t.Fatal("launcher lock holder allowed switch")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertCurrent()

	// A signed archive does not make a subsequently altered installed tree safe.
	secondKernel := filepath.Join(root, wantSecond, "artifacts/kernel")
	if err := os.Chmod(secondKernel, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondKernel, []byte("altered"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secondKernel, 0o444); err != nil {
		t.Fatal(err)
	}
	options.Archive = second
	if _, err := Switch(options); err == nil {
		t.Fatal("modified installed release accepted")
	}
	assertCurrent()
	if err := os.WriteFile(filepath.Join(root, wantFirst, "extra-file"), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	options.Archive = first
	if _, err := Switch(options); err == nil {
		t.Fatal("unexpected installed file accepted")
	}
	assertCurrent()
	if err := os.Remove(filepath.Join(root, wantFirst, "extra-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, wantFirst, "extra-directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Switch(options); err == nil {
		t.Fatal("unexpected installed directory accepted")
	}
	assertCurrent()
}
