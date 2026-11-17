package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPristineBindingKeepsBackendWireStrength(t *testing.T) {
	binding, err := newPristineBinding("0123456789abcdef01234567")
	if err != nil || !binding.valid() {
		t.Fatal(err)
	}
	for i := range binding.nonce {
		binding.nonce[i] = byte(i + 1)
	}
	linux, osv := binding.linux(), binding.osv()
	if linux.SessionID != binding.ID || !linux.valid() || len(linux.Nonce) != 64 || osv.ID != binding.ID || !bytes.Equal(osv.Nonce[:], binding.nonce[:16]) {
		t.Fatal("binding conversion lost ID or nonce")
	}
	oldLinux := linux.Nonce
	binding.nonce[31] ^= 1
	if binding.linux().Nonce == oldLinux || binding.osv() != osv {
		t.Fatal("Linux full-width nonce or OSv fixed-width contract changed")
	}
	clear(binding.nonce[:16])
	if binding.valid() {
		t.Fatal("zero OSv nonce prefix accepted")
	}
	if _, err := newPristineBinding("not-an-id"); err == nil {
		t.Fatal("invalid request ID accepted")
	}
}

func TestPristineBackendFeatureFenceAndHonestCapabilities(t *testing.T) {
	m := &Manager{config: Config{Backend: "firecracker-osv", AllowedEntrypoints: []string{"/task-probe.so"}},
		backend: FirecrackerOSvBackend{}, manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v2", Backend: "firecracker-osv", digestSHA256: strings.Repeat("a", 64)}}
	if _, err := newPristineVMBackend(m); err == nil {
		t.Fatal("old OSv template entered pool")
	}
	m.manifest.AgentFeatures = []string{"pristine-v1"}
	b, err := newPristineVMBackend(m)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := b.(osvPristineVMBackend); !ok || !value.Pristine {
		t.Fatal("OSv pool did not choose explicit pristine mode")
	}
	m.pool = &warmPool{backend: b}
	caps, err := m.Capabilities()
	if err != nil || !caps.Features.WarmPool || caps.Features.Sessions || caps.Features.InputFiles || caps.Features.PersistentWorkspace || caps.GuestResultProtocol != "osv-agent/v1" || caps.Stage != "diagnostic" {
		t.Fatalf("OSv capability substitution: %+v %v", caps, err)
	}
	for _, mode := range []string{"session", "files"} {
		binding, err := newPristineBinding("0123456789abcdef01234567")
		if err != nil {
			t.Fatal(err)
		}
		request := pristinePreparation{Binding: binding, Mode: "job", TTLMS: 1000}
		if mode == "session" {
			request.Mode = "session"
		} else {
			request.InputFiles = []InputFile{{Path: "input", Data: []byte("denied")}}
		}
		if err := b.prepareVM(context.Background(), request, "/nonexistent"); err == nil || !strings.Contains(err.Error(), "one-shot") {
			t.Fatalf("unsupported OSv operation reached transport: %v", err)
		}
	}
	key := m.warmProfileKey(128, 1)
	m.config.Backend = "firecracker-linux"
	if key == m.warmProfileKey(128, 1) {
		t.Fatal("different backends share a pool key")
	}
	if _, err := newPristineVMBackend(m); err == nil {
		t.Fatal("mismatched configured backend accepted")
	}
	c := warmConfigForTest()
	c.Backend = "firecracker-osv"
	if err := c.validateWarmPool(); err != nil {
		t.Fatal(err)
	}
	c.Production = true
	c.LinuxGuest = nil
	c.Image.Format = "raw"
	c.Limits.MaxOutputByte = 16384
	c.Jailer.Path, c.Jailer.ParentCgroup, c.HypervisorPath = "/jailer", "test", "/firecracker"
	c.AllowedEntrypoints = []string{"/task-probe.so"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "production mode requires") {
		t.Fatalf("OSv production policy bypassed: %v", err)
	}
}

type scriptedPristineBackend struct {
	pristineVMBackend
	run func(context.Context, RunRequest, pristineBinding, string) (json.RawMessage, bool, error)
}

func (b scriptedPristineBackend) runVM(ctx context.Context, request RunRequest, binding pristineBinding, workdir string) (json.RawMessage, bool, error) {
	return b.run(ctx, request, binding, workdir)
}

func fakeOSvPool(t *testing.T) (*Manager, *warmPool) {
	t.Helper()
	m, old := fakeWarmManager(t, 1)
	old.stop()
	m.config.Backend, m.config.AllowedEntrypoints, m.config.LinuxGuest = "firecracker-osv", []string{"/task-probe.so"}, nil
	m.config.Limits.MaxOutputByte = 16384
	m.backend = FirecrackerOSvBackend{}
	m.manifest.Protocol, m.manifest.Backend = "osv-sandbox-artifacts/v2", "firecracker-osv"
	m.manifest.AgentFeatures = []string{"environment", "pristine-v1", "stdin"}
	p, err := newWarmPool(m)
	if err != nil {
		t.Fatal(err)
	}
	p.boot, p.probe, p.prepare, p.availableMemory = old.boot, old.probe, old.prepare, old.availableMemory
	m.pool = p
	return m, p
}

func TestOSvPoolUsesBoundDriverAndGuestExitCode(t *testing.T) {
	m, p := fakeOSvPool(t)
	p.backend = scriptedPristineBackend{pristineVMBackend: p.backend, run: func(_ context.Context, request RunRequest, binding pristineBinding, _ string) (json.RawMessage, bool, error) {
		if request.jobID != binding.ID || request.Entrypoint != "/task-probe.so" || request.Environment["MARKER"] != "value" || !bytes.Equal(request.Stdin, []byte{0, 255}) {
			return nil, false, errors.New("request or binding lost in pool")
		}
		raw := json.RawMessage(fmt.Sprintf(`{"protocol":"osv-agent/v1","job_id":%q,"ok":false,"exit_code":7}`, binding.ID))
		return raw, false, nil
	}}
	startFakeWarmPool(t, m)
	result, err := m.Run(context.Background(), RunRequest{Entrypoint: "/task-probe.so", MemoryMiB: 128, VCPUs: 1, TimeoutMS: 3000,
		Environment: map[string]string{"MARKER": "value"}, Stdin: []byte{0, 255}})
	if err != nil || result.State != "guest_error" || result.ExitCode != 7 || !result.ProtocolOK || result.StartupMode != "warm" || !strings.HasPrefix(result.Output, guestResultPrefix) || strings.Contains(result.Output, linuxResultPrefix) {
		t.Fatalf("prepared OSv result changed meaning: %+v %v", result, err)
	}
	if m.Capacity().Active != 0 || p.snapshot().Hits != 1 {
		t.Fatal("job did not release active or count actual warm path")
	}
}

func TestPreparedJobDrainsResultAfterExitAndBoundsDeadVMWait(t *testing.T) {
	for _, delayedResult := range []bool{false, true} {
		t.Run(fmt.Sprint(delayedResult), func(t *testing.T) {
			m, p := fakeOSvPool(t)
			p.backend = scriptedPristineBackend{pristineVMBackend: p.backend, run: func(ctx context.Context, _ RunRequest, binding pristineBinding, workdir string) (json.RawMessage, bool, error) {
				m.vmMu.Lock()
				var owned *vmInstance
				for value := range m.instances {
					if value.workdir == workdir {
						owned = value
					}
				}
				m.vmMu.Unlock()
				if owned == nil {
					return nil, false, errors.New("VM owner missing")
				}
				_ = owned.command.Process.Kill()
				if delayedResult {
					select {
					case <-time.After(20 * time.Millisecond):
						return json.RawMessage(fmt.Sprintf(`{"protocol":"osv-agent/v1","job_id":%q,"ok":true,"exit_code":0}`, binding.ID)), true, nil
					case <-ctx.Done():
						return nil, false, ctx.Err()
					}
				}
				<-ctx.Done()
				return nil, false, ctx.Err()
			}}
			startFakeWarmPool(t, m)
			started := time.Now()
			result, err := m.Run(context.Background(), RunRequest{Entrypoint: "/task-probe.so", MemoryMiB: 128, VCPUs: 1, TimeoutMS: 5000})
			if err != nil || time.Since(started) > time.Second || (delayedResult && (result.State != "succeeded" || !result.ProtocolOK)) || (!delayedResult && (result.State != "protocol_error" || result.ProtocolOK)) {
				t.Fatalf("result drain lost completion or waited TTL: %+v %v duration=%v", result, err, time.Since(started))
			}
		})
	}
}

type exitCodeControlBackend struct {
	controlHelperBackend
	code int
}

func (b exitCodeControlBackend) Exchange(_ context.Context, request RunRequest, _ string) (string, error) {
	return fmt.Sprintf(`%s{"protocol":"osv-agent/v1","job_id":%q,"ok":false,"exit_code":%d}`, guestResultPrefix, request.jobID, b.code), nil
}

func TestColdJobPreservesGuestFailureExitCode(t *testing.T) {
	for _, code := range []int{7, -9, 0} {
		m := testManager(t, "output")
		m.backend = exitCodeControlBackend{controlHelperBackend: controlHelperBackend{mode: "output"}, code: code}
		result, err := m.Run(context.Background(), RunRequest{TimeoutMS: 3000})
		expected := code
		if expected == 0 {
			expected = 1
		}
		if err != nil || result.State != "guest_error" || result.ExitCode != expected || !result.ProtocolOK {
			t.Fatalf("cold guest failure lost exit code: %+v %v", result, err)
		}
	}
}
