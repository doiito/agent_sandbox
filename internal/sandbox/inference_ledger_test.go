package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func inferenceTestBinding() inferenceBinding {
	return inferenceBinding{Tenant: "tenant-a", TaskID: "111111111111111111111111", VMID: "222222222222222222222222", LeaseID: "333333333333333333333333"}
}
func inferencePrivateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
func inferenceTestLedger(t *testing.T, maximum int) (*InferenceLedger, string) {
	t.Helper()
	directory := inferencePrivateTestDirectory(t)
	ledger, err := OpenInferenceLedger(directory, maximum)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger, directory
}
func inferenceTestPermit(t *testing.T) inferencePermit {
	t.Helper()
	permit, err := inferenceTestRules(t).permit("local-model")
	if err != nil {
		t.Fatal(err)
	}
	return permit
}

func TestInferenceLedgerConcurrentReservationsCannotOverspend(t *testing.T) {
	ledger, _ := inferenceTestLedger(t, 10)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var mu sync.Mutex
	ids := []string{}
	for n := 1; n <= 40; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("%024x", n)
			if _, err := ledger.reserve(binding, id, permit, 10); err == nil {
				accepted.Add(1)
				mu.Lock()
				ids = append(ids, id)
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	if accepted.Load() != 2 {
		t.Fatal("budget was exceeded or reserved inaccurately", accepted.Load())
	}
	bill, err := ledger.bill(binding.Tenant, binding.TaskID)
	if err != nil || bill.HeldUnits != 242 || bill.SettledUnits != 0 || len(bill.Invocations) != 2 {
		t.Fatal("reservation was not persisted", bill, err)
	}
	bill, err = ledger.finish(binding, ids[0], inferenceOutcome{state: "succeeded", status: 200, dispatched: true, outputBytes: 4, durationMS: 2})
	if err != nil || bill.SettledUnits != 37 || bill.HeldUnits != 121 {
		t.Fatal("incorrect settlement", bill, err)
	}
	if _, err := ledger.reserve(binding, "aaaaaaaaaaaaaaaaaaaaaaaa", permit, 10); err != nil {
		t.Fatal("unused reservation was not released", err)
	}
	if _, err := ledger.reserve(binding, "bbbbbbbbbbbbbbbbbbbbbbbb", permit, 10); err == nil {
		t.Fatal("parallel budget overrun")
	}
	if _, err := ledger.reserve(binding, ids[0], permit, 10); err == nil {
		t.Fatal("settled ID replayed")
	}
}

func TestInferenceLedgerRestartKeepsUnknownBudgetAndRejectsOtherOwner(t *testing.T) {
	ledger, directory := inferenceTestLedger(t, 1)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	id := "aaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := ledger.reserve(binding, id, permit, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInferenceLedger(directory, 1); err == nil {
		t.Fatal("second process could obtain writer lock")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenInferenceLedger(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	path := filepath.Join(directory, binding.TaskID+".json")
	before, _ := os.ReadFile(path)
	if _, err := ledger.bill("tenant-b", binding.TaskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign task bill disclosed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("foreign query mutated another task")
	}
	other := binding
	other.LeaseID = "444444444444444444444444"
	if _, err := ledger.reserve(other, id, permit, 10); err == nil {
		t.Fatal("lease binding changed")
	}
	bill, err := ledger.bill(binding.Tenant, binding.TaskID)
	if err != nil || bill.HeldUnits != 121 || bill.SettledUnits != 0 || bill.Invocations[0].State != "uncertain" || bill.Invocations[0].Code != "inference_restarted" {
		t.Fatal("restart invented completion or released budget", bill, err)
	}
	if _, err := ledger.reserve(binding, id, permit, 10); err == nil {
		t.Fatal("unknown invocation replayed")
	}
	if _, err := ledger.finish(binding, id, inferenceOutcome{state: "succeeded", status: 200, dispatched: true}); err == nil {
		t.Fatal("old process invocation silently completed")
	}
}

func TestInferenceLedgerUnknownOutcomeHoldsFullReservation(t *testing.T) {
	ledger, _ := inferenceTestLedger(t, 1)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	id := "aaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := ledger.reserve(binding, id, permit, 10); err != nil {
		t.Fatal(err)
	}
	bill, err := ledger.finish(binding, id, inferenceOutcome{state: "uncertain", code: "inference_timeout", dispatched: true, outputBytes: 2, durationMS: 100})
	if err != nil || bill.HeldUnits != 121 || bill.SettledUnits != 0 || bill.Invocations[0].OutputBytes != 2 {
		t.Fatal("uncertain provider attempt became free or settled", bill, err)
	}
	if _, err := ledger.finish(binding, id, inferenceOutcome{state: "failed", code: "inference_cancelled"}); err == nil {
		t.Fatal("uncertain result rewritten")
	}
}

func TestInferenceLedgerConfirmedFailureAndPreDispatchCancellation(t *testing.T) {
	ledger, _ := inferenceTestLedger(t, 1)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	for n, outcome := range []inferenceOutcome{{state: "failed", code: "inference_cancelled"}, {state: "failed", code: "inference_upstream_status", dispatched: true, status: 429, outputBytes: 3}} {
		id := fmt.Sprintf("%024x", n)
		if _, err := ledger.reserve(binding, id, permit, 10); err != nil {
			t.Fatal(err)
		}
		bill, err := ledger.finish(binding, id, outcome)
		if err != nil || bill.HeldUnits != 0 || bill.SettledUnits != InferenceUnits(n*34) {
			t.Fatal("failure settlement incorrect", bill, err)
		}
	}
}

func TestInferenceLedgerFailureCommitBoundariesLatchAndRecover(t *testing.T) {
	for _, phase := range []string{"before_write", "before_rename", "after_rename"} {
		t.Run(phase, func(t *testing.T) {
			ledger, directory := inferenceTestLedger(t, 1)
			binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
			id := "aaaaaaaaaaaaaaaaaaaaaaaa"
			if _, err := ledger.reserve(binding, id, permit, 10); err != nil {
				t.Fatal(err)
			}
			ledger.mu.Lock()
			ledger.fault = func(stage string) error {
				if stage == phase {
					return errors.New("simulated durable storage failure")
				}
				return nil
			}
			ledger.mu.Unlock()
			if _, err := ledger.finish(binding, id, inferenceOutcome{state: "succeeded", status: 200, dispatched: true, outputBytes: 4}); err == nil || ledger.Err() == nil {
				t.Fatal("unconfirmed write acknowledged")
			}
			if _, err := ledger.reserve(binding, "bbbbbbbbbbbbbbbbbbbbbbbb", permit, 10); err == nil {
				t.Fatal("latched store accepted another spend")
			}
			_ = ledger.Close()
			recovered, err := OpenInferenceLedger(directory, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = recovered.Close() })
			bill, err := recovered.bill(binding.Tenant, binding.TaskID)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "after_rename" {
				if bill.SettledUnits != 37 || bill.Invocations[0].State != "succeeded" {
					t.Fatal("already stored completion lost")
				}
			} else if bill.HeldUnits != 121 || bill.Invocations[0].State != "uncertain" {
				t.Fatal("uncommitted completion released its reservation")
			}
			if _, err := recovered.reserve(binding, id, permit, 10); err == nil {
				t.Fatal("restart replayed an existing invocation")
			}
		})
	}
}

func TestInferenceLedgerAdmissionWriteFailureNeverAuthorizesDispatch(t *testing.T) {
	ledger, directory := inferenceTestLedger(t, 1)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	ledger.fault = func(string) error { return errors.New("disk full") }
	dispatched := false
	if _, err := ledger.reserve(binding, "aaaaaaaaaaaaaaaaaaaaaaaa", permit, 10); err == nil {
		dispatched = true
	}
	if dispatched || ledger.Err() == nil {
		t.Fatal("failed reservation permitted a provider attempt")
	}
	if _, err := os.Stat(filepath.Join(directory, binding.TaskID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed first write created a committed task")
	}
	_ = ledger.Close()
	recovered, err := OpenInferenceLedger(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	if _, err := recovered.reserve(binding, "aaaaaaaaaaaaaaaaaaaaaaaa", permit, 10); err != nil {
		t.Fatal("pre-dispatch failure was not safely recoverable", err)
	}
}

func TestInferenceLedgerCloseExportAndExactRetirement(t *testing.T) {
	ledger, _ := inferenceTestLedger(t, 1)
	binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
	id := "aaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := ledger.reserve(binding, id, permit, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.closeTask(binding); err == nil {
		t.Fatal("active operation ignored during task close")
	}
	if _, _, err := ledger.exportTask(binding); err == nil {
		t.Fatal("active bill exported for retirement")
	}
	if _, err := ledger.finish(binding, id, inferenceOutcome{state: "failed", code: "inference_cancelled"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.closeTask(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.reserve(binding, "bbbbbbbbbbbbbbbbbbbbbbbb", permit, 10); err == nil {
		t.Fatal("closed task reopened")
	}
	data, digest, err := ledger.exportTask(binding)
	if err != nil || inferenceDigest(data) != digest {
		t.Fatal("export not reproducible", err)
	}
	if err := ledger.retireTask(binding, "incorrect"); err == nil {
		t.Fatal("wrong export acknowledged")
	}
	other := binding
	other.TaskID = "444444444444444444444444"
	if _, err := ledger.reserve(other, id, permit, 10); err == nil {
		t.Fatal("history storage limit ignored")
	}
	if err := ledger.retireTask(binding, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.bill(binding.Tenant, binding.TaskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired bill invented an empty balance")
	}
	if _, err := ledger.reserve(other, id, permit, 10); err != nil {
		t.Fatal("retired capacity not reclaimed", err)
	}
}

func TestInferenceLedgerCorruptStateAndUntrustedFilesReject(t *testing.T) {
	t.Run("corrupt-record", func(t *testing.T) {
		ledger, directory := inferenceTestLedger(t, 1)
		binding, permit := inferenceTestBinding(), inferenceTestPermit(t)
		if _, err := ledger.reserve(binding, "aaaaaaaaaaaaaaaaaaaaaaaa", permit, 10); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, binding.TaskID+".json"), []byte(`{"version":1,"binding":`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.bill(binding.Tenant, binding.TaskID); err == nil || ledger.Err() == nil {
			t.Fatal("corrupt state accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := inferencePrivateTestDirectory(t)
		outside := filepath.Join(t.TempDir(), "other")
		if err := os.WriteFile(outside, []byte("retain"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(directory, ".lock")); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenInferenceLedger(directory, 1); err == nil {
			t.Fatal("symlink lock followed")
		}
		data, _ := os.ReadFile(outside)
		if string(data) != "retain" {
			t.Fatal("external file modified")
		}
	})
	t.Run("orphan-pending", func(t *testing.T) {
		directory := inferencePrivateTestDirectory(t)
		pending := filepath.Join(directory, ".pending-aaaaaaaaaaaaaaaaaaaaaaaa")
		if err := os.WriteFile(pending, []byte(`{"version":`), 0o600); err != nil {
			t.Fatal(err)
		}
		ledger, err := OpenInferenceLedger(directory, 1)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ledger.Close() })
		if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("orphan uncommitted temporary not retired")
		}
	})
}
