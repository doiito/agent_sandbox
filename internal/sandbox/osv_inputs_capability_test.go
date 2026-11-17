package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOSvInputCapabilityRequiresItsSignedPreparationFeature(t *testing.T) {
	m := &Manager{config: Config{Backend: "firecracker-osv", AllowedEntrypoints: []string{"/task-probe.so"}},
		backend: FirecrackerOSvBackend{}, manifest: &SignedArtifactManifest{
			Protocol: "osv-sandbox-artifacts/v2", Backend: "firecracker-osv", digestSHA256: strings.Repeat("a", 64),
			OSvUpstreamCommit: "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b", Entrypoints: []string{"/task-probe.so"}}}
	legacyKey := m.warmProfileKey(128, 1)
	for _, features := range [][]string{nil, {"pristine-v1"}, {"input-files-v1"}, {"input-files-v1", "pristine-v1"}} {
		m.manifest.AgentFeatures = features
		caps, err := m.Capabilities()
		if err != nil {
			t.Fatal(err)
		}
		supported := len(features) == 2
		if caps.Features.InputFiles != supported || caps.Features.WarmPool || caps.Features.Sessions {
			t.Fatalf("capabilities overstate signed features %v: %+v", features, caps.Features)
		}
		if supported {
			if caps.Limits.MaxInputFiles != 64 || caps.Limits.MaxInputBytes != 512*1024 {
				t.Fatal("OSv input limits differ from the public contract")
			}
			b, err := newPristineVMBackend(m)
			if err != nil || !b.(osvPristineVMBackend).ReadonlyInputs || m.warmProfileKey(128, 1) == legacyKey {
				t.Fatal("signed input feature did not select OSP2 and a separate queue key", err)
			}
		} else if caps.Limits.MaxInputFiles != 0 || caps.Limits.MaxInputBytes != 0 {
			t.Fatal("unsupported template advertises input budgets")
		}
		profileErr := m.manifest.ValidateProfile(m.config.Backend, m.config.AllowedEntrypoints)
		if (len(features) == 1 && features[0] == "input-files-v1") != (profileErr != nil) {
			t.Fatalf("feature dependency validation: %v %v", features, profileErr)
		}
	}
}

func TestOSvInputV7PreservesInferenceAndRequiresPristine(t *testing.T) {
	manifest := inferenceV7Manifest("firecracker-osv")
	manifest.AgentFeatures = append(manifest.AgentFeatures, "input-files-v1")
	slices.Sort(manifest.AgentFeatures)
	if err := manifest.ValidateProfile("firecracker-osv", manifest.Entrypoints); err != nil {
		t.Fatal("valid input/inference combination rejected", err)
	}
	manifest.AgentFeatures = slices.DeleteFunc(manifest.AgentFeatures, func(s string) bool { return s == "pristine-v1" })
	if err := manifest.ValidateProfile("firecracker-osv", manifest.Entrypoints); err == nil {
		t.Fatal("v7 input support accepted without preparation")
	}
}

func TestOSvInputWarmAndPoolMissCarryInputsAndStayOneShot(t *testing.T) {
	m, p := fakeOSvPool(t)
	m.manifest.AgentFeatures = []string{"environment", "input-files-v1", "pristine-v1", "stdin"}
	backend, err := newPristineVMBackend(m)
	if err != nil {
		t.Fatal(err)
	}
	p.backend = scriptedPristineBackend{pristineVMBackend: backend, run: func(_ context.Context, r RunRequest, binding pristineBinding, work string) (json.RawMessage, bool, error) {
		if r.jobID != binding.ID {
			return nil, false, errors.New("unbound run")
		}
		return json.RawMessage(`{"ok":true,"exit_code":0}`), true, nil
	}}
	p.profiles[0].key = m.warmProfileKey(128, 1)
	preparations := 0
	p.prepare = func(_ context.Context, v *vmInstance, r pristinePreparation) error {
		preparations++
		if r.Mode != "job" || !r.Binding.valid() || len(r.InputFiles) != 1 || r.InputFiles[0].Path != "data" || string(r.InputFiles[0].Data) != "\x00\xff" {
			return errors.New("input or binding lost at pool checkout")
		}
		return nil
	}
	startFakeWarmPool(t, m)
	for _, row := range []struct {
		memory int
		mode   string
	}{{128, "warm"}, {256, "cold"}} {
		result, err := m.Run(context.Background(), RunRequest{Entrypoint: "/task-probe.so", MemoryMiB: row.memory,
			InputFiles: []InputFile{{Path: "data", Data: []byte{0, 255}}}, startupStarted: time.Now()})
		if err != nil || result.State != "succeeded" || result.StartupMode != row.mode || m.Capacity().Active != 0 {
			t.Fatalf("input route %s: %+v %v", row.mode, result, err)
		}
	}
	if preparations != 2 {
		t.Fatal("input preparation repeated or omitted", preparations)
	}
}

func TestOSvLegacyTemplateRejectsInputsBeforeAdmission(t *testing.T) {
	m, p := fakeOSvPool(t)
	p.stop()
	m.pool = nil
	_, err := m.Run(context.Background(), RunRequest{Entrypoint: "/task-probe.so", InputFiles: []InputFile{{Path: "a", Data: []byte("x")}}})
	if err == nil || !strings.Contains(err.Error(), "input-files-v1") || m.Capacity().Instances != 0 || m.Capacity().Active != 0 {
		t.Fatal("legacy input reached VM admission", err, m.Capacity())
	}
}
