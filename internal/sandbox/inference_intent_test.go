package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestInferenceIntentManagerRequiresNewProfileAndTenantGrant(t *testing.T) {
	s, _, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	// These directly constructed manager fixtures test root attachment only.
	// These are not signed-image proofs; v7 signature/BOM and actual file
	// acceptance are tested separately.
	for _, item := range []struct {
		version int
		allowed bool
	}{{1, true}, {2, true}, {3, true}, {4, true}, {5, true}, {6, true}, {7, false}, {7, true}} {
		t.Run(fmt.Sprintf("v%d-tenant-%t", item.version, item.allowed), func(t *testing.T) {
			workdir := inferenceIntentWorkdir(t, inferencePrivateTestDirectory(t))
			m := &Manager{config: Config{Backend: "firecracker-linux", HypervisorPath: "/fixture/firecracker", Jailer: &JailerConfig{}, EgressSocket: main},
				manifest:         &SignedArtifactManifest{Protocol: fmt.Sprintf("osv-sandbox-artifacts/v%d", item.version), AgentFeatures: []string{"remote-infer-v1", "vsock-proxy-v1"}},
				inferenceTenants: map[string]bool{"tenant-a": item.allowed}, inferenceAuth: s.auth}
			if item.version == 7 {
				m.manifest.Backend = m.config.Backend
				m.manifest.GuestInference = inferenceTestGuestProfile(m.config.Backend)
			}
			socket, err := jailedFirecrackerVsockPath(m.config.HypervisorPath, workdir)
			if err != nil || os.MkdirAll(filepath.Dir(socket), 0o755) != nil {
				t.Fatal("cannot stage root attachment fixture")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v := &vmInstance{manager: m, id: inferenceTestBinding().VMID, ctx: ctx, cancel: cancel, workdir: workdir, physical: &vmReservation{identity: jailIdentity{uid: 65530, gid: 65530}}}
			if err := v.bindGuestProxy("tenant-a", inferenceTestBinding().LeaseID); err != nil {
				t.Fatal(err)
			}
			defer v.proxy.Close()
			wanted := item.version == 7 && item.allowed
			if (v.proxy.inference != nil) != wanted {
				t.Fatal("root proxy did not enforce new-profile and tenant authorization")
			}
			if wanted {
				binding := inferenceTestBinding()
				binding.TaskID = binding.LeaseID
				if *v.proxy.inference != binding {
					t.Fatal("root attached the wrong logical task")
				}
				if v.proxy.inferencePolicySHA256 != m.inferencePolicyDigest("tenant-a") || !validSHA256Hex(v.proxy.inferencePolicySHA256) {
					t.Fatal("root proxy omitted its startup policy snapshot")
				}
				if bill, err := s.inference.ledger.boundTask(binding, true); err != nil || bill.Closed {
					t.Fatal("root attached before durable grant", err)
				}
			} else if _, err := os.Stat(filepath.Join(workdir, inferenceIntentName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old/unauthorized profile created an inference intent")
			}
			v.proxy.Close()
			if err := closeVMInference(workdir, main); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func inferenceIntentWorkdir(t *testing.T, runRoot string) string {
	t.Helper()
	path := filepath.Join(runRoot, "job-"+inferenceTestBinding().VMID+"-fixture")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInferenceIntentPrecedesFailedBindAndSurvivesRecoveryFailure(t *testing.T) {
	requireGuestProxyRoot(t)
	runRoot := inferencePrivateTestDirectory(t)
	workdir := inferenceIntentWorkdir(t, runRoot)
	missing := filepath.Join(inferencePrivateTestDirectory(t), "missing.sock")
	err := bindVMInference(context.Background(), workdir, missing, inferenceTestBinding())
	if err == nil {
		t.Fatal("unavailable service acknowledged a bind")
	}
	directory, err := openInferenceIntentDirectory(workdir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := readInferenceIntentAt(directory)
	_ = directory.Close()
	if err != nil || stored != inferenceTestBinding() {
		t.Fatal("bind was attempted before its root recovery intent", err)
	}
	if count, err := reconcileRunRoot(runRoot, "", missing); err == nil || count != 0 {
		t.Fatal("orphan reconciliation hid unconfirmed bill closure")
	}
	if _, err := os.Stat(filepath.Join(workdir, inferenceIntentName)); err != nil {
		t.Fatal("failed recovery deleted its only binding intent")
	}
	other := inferenceTestBinding()
	other.TaskID = "444444444444444444444444"
	if bindVMInference(context.Background(), workdir, missing, other) == nil {
		t.Fatal("binding intent was silently reassigned")
	}
}

func TestInferenceIntentRecoveryClosesBeforeRemovingWorkdir(t *testing.T) {
	s, _, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	runRoot := inferencePrivateTestDirectory(t)
	workdir := inferenceIntentWorkdir(t, runRoot)
	if err := bindVMInference(context.Background(), workdir, main, inferenceTestBinding()); err != nil {
		t.Fatal(err)
	}
	count, err := reconcileRunRoot(runRoot, "", main)
	if err != nil || count != 1 {
		t.Fatal("orphan bill closure was not reconciled", count, err)
	}
	if _, err := os.Stat(workdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("acknowledged orphan workdir was not removed")
	}
	bill, err := s.inference.ledger.boundTask(inferenceTestBinding(), false)
	if err != nil || !bill.Closed || len(bill.Invocations) != 0 {
		t.Fatal("recovery deleted ownership before durable close acknowledgement", err)
	}
}

func TestInferenceIntentAbsentBindStillSealsOnRecovery(t *testing.T) {
	s, _, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	runRoot := inferencePrivateTestDirectory(t)
	workdir := inferenceIntentWorkdir(t, runRoot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if bindVMInference(ctx, workdir, main, inferenceTestBinding()) == nil {
		t.Fatal("pre-cancelled bind was acknowledged")
	}
	if _, err := s.inference.ledger.boundTask(inferenceTestBinding(), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled RPC unexpectedly created a grant")
	}
	if count, err := reconcileRunRoot(runRoot, "", main); err != nil || count != 1 {
		t.Fatal("recovery did not seal an unacknowledged binding intent", count, err)
	}
	bill, err := s.inference.ledger.boundTask(inferenceTestBinding(), false)
	if err != nil || !bill.Closed {
		t.Fatal("late bind could reopen a recovered intent")
	}
}

func TestInferenceIntentDestroyRetainsPhysicalBudgetOnCloseFailure(t *testing.T) {
	requireGuestProxyRoot(t)
	m := testManager(t, "output")
	m.config.EgressSocket = filepath.Join(inferencePrivateTestDirectory(t), "missing.sock")
	workdir := inferenceIntentWorkdir(t, m.config.RunRoot)
	if bindVMInference(context.Background(), workdir, m.config.EgressSocket, inferenceTestBinding()) == nil {
		t.Fatal("missing service acknowledged binding")
	}
	physical, _, err := m.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := &vmInstance{manager: m, id: inferenceTestBinding().VMID, physical: physical, workdir: workdir, ctx: ctx, cancel: cancel, state: vmActive}
	m.instances = map[*vmInstance]struct{}{v: {}}
	if err := v.Destroy(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("destroy discarded an unconfirmed inference intent", err)
	}
	capacity := m.Capacity()
	if capacity.Active != 1 || capacity.Instances != 1 || !capacity.Blocked || m.VMInstances().States[string(vmCleanupFailed)] != 1 {
		t.Fatal("failed bill close released physical identity/accounting", capacity)
	}
	if _, err := os.Stat(workdir); err != nil {
		t.Fatal("failed destroy removed recovery data")
	}
}

func TestInferenceIntentRejectsForeignWorkdirAndUnsafeFile(t *testing.T) {
	requireGuestProxyRoot(t)
	workdir := inferenceIntentWorkdir(t, inferencePrivateTestDirectory(t))
	missing := filepath.Join(inferencePrivateTestDirectory(t), "missing.sock")
	binding := inferenceTestBinding()
	other := binding
	other.VMID = "444444444444444444444444"
	if bindVMInference(context.Background(), workdir, missing, other) == nil {
		t.Fatal("binding was persisted under another physical VM")
	}
	if bindVMInference(context.Background(), workdir, missing, binding) == nil {
		t.Fatal("missing service unexpectedly acknowledged bind")
	}
	if err := os.Chmod(filepath.Join(workdir, inferenceIntentName), 0o644); err != nil {
		t.Fatal(err)
	}
	if closeVMInference(workdir, missing) == nil {
		t.Fatal("root accepted an exposed or tampered recovery intent")
	}
}
