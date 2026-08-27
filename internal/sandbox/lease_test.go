package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

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
