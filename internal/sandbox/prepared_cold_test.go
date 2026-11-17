package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type coldInputTestBackend struct {
	prepared, ran int
	prepare       func(pristinePreparation, string) error
	run           func(context.Context) (json.RawMessage, bool, error)
}

func (*coldInputTestBackend) Name() string { return "firecracker-osv" }
func (*coldInputTestBackend) ResultProtocol() (string, string) {
	return (FirecrackerOSvBackend{}).ResultProtocol()
}
func (*coldInputTestBackend) Command(ctx context.Context, _ RunRequest, a ResolvedArtifacts, work string) (*exec.Cmd, error) {
	return (helperBackend{mode: "pool-wait"}).Command(ctx, RunRequest{Args: []string{"--sandbox-job-id", "0123456789abcdef01234567"}}, a, work)
}
func (*coldInputTestBackend) probeVM(context.Context, string) (time.Duration, error) {
	return 600 * time.Second, nil
}
func (b *coldInputTestBackend) prepareVM(_ context.Context, r pristinePreparation, work string) error {
	b.prepared++
	if b.prepare != nil {
		return b.prepare(r, work)
	}
	return r.validate()
}
func (b *coldInputTestBackend) runVM(ctx context.Context, r RunRequest, binding pristineBinding, work string) (json.RawMessage, bool, error) {
	b.ran++
	lease, err := readProcessLease(filepath.Join(work, "lease.json"))
	if err != nil || lease.Phase != "active" || lease.RequestID != binding.ID || lease.Tenant != r.tenantID || r.jobID != binding.ID {
		return nil, false, errors.New("unowned cold execution")
	}
	if b.run != nil {
		return b.run(ctx)
	}
	return json.RawMessage(`{"ok":true,"exit_code":0}`), true, nil
}

func coldInputManager(t *testing.T) (*Manager, *coldInputTestBackend) {
	t.Helper()
	m, p := fakeOSvPool(t)
	p.stop()
	m.pool, m.config.WarmPool = nil, nil
	m.manifest.AgentFeatures = []string{"environment", "input-files-v1", "pristine-v1", "stdin"}
	b := &coldInputTestBackend{}
	m.preparedCold = &preparedColdRuntime{manager: m, backend: b}
	if err := m.StartWarmPool(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestOSvPreparedColdWithoutPoolCopiesInputAndReleasesAllResources(t *testing.T) {
	m, b := coldInputManager(t)
	b.prepare = func(r pristinePreparation, _ string) error {
		if r.Mode != "job" || len(r.InputFiles) != 1 || r.InputFiles[0].Path != "nested/file" || string(r.InputFiles[0].Data) != "A\x00\xff" || !r.Binding.valid() {
			return errors.New("cold input or binding lost")
		}
		return nil
	}
	if m.Capacity().Instances != 0 {
		t.Fatal("disabled pool speculatively booted a VM")
	}
	for range 2 {
		result, err := m.Run(context.Background(), RunRequest{Entrypoint: "/task-probe.so", tenantID: "tenant-a",
			InputFiles: []InputFile{{Path: "nested/file", Data: []byte{'A', 0, 255}}}})
		if err != nil || result.State != "succeeded" || result.StartupMode != "cold" || result.StartupTiming == nil || result.VMBootDurationUS <= 0 {
			t.Fatalf("cold prepared job: %+v %v", result, err)
		}
		if m.pool != nil || m.Capacity().Active != 0 || m.Capacity().Instances != 0 || len(m.VMInstances().States) != 0 {
			t.Fatal("disabled pool or cold job retained resources", m.Capacity(), m.VMInstances())
		}
	}
	if b.prepared != 2 || b.ran != 2 {
		t.Fatal("cold prepare/run was replayed or omitted")
	}
}

func TestOSvPreparedColdUncertainPrepareOrChangedOwnerNeverRuns(t *testing.T) {
	for _, failure := range []string{"lost-ack", "lease-change", "expired-template", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			m, b := coldInputManager(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.prepare = func(_ pristinePreparation, work string) error {
				switch failure {
				case "lost-ack":
					return errors.New("response lost after mount")
				case "lease-change":
					lease, err := readProcessLease(filepath.Join(work, "lease.json"))
					if err != nil {
						return err
					}
					lease.Tenant = "foreign"
					return persistProcessLease(work, lease)
				case "expired-template":
					m.manifest.ExpiresAt = time.Now().Add(-time.Second)
				case "cancelled":
					cancel()
				}
				return nil
			}
			result, err := m.Run(ctx, RunRequest{Entrypoint: "/task-probe.so", tenantID: "tenant-a", InputFiles: []InputFile{{Path: "a"}}})
			if err == nil && result.State != "cancelled" || b.prepared != 1 || b.ran != 0 || m.Capacity().Active != 0 || m.Capacity().Instances != 0 {
				t.Fatalf("uncertain preparation executed or leaked: %+v %v %d/%d %+v", result, err, b.prepared, b.ran, m.Capacity())
			}
		})
	}
}
