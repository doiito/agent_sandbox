package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerBindsSelectedBackendAndSignedManifestBeforeVMAllocation(t *testing.T) {
	m := testManager(t, "output")
	calls := &atomic.Int32{}
	m.backend = countedBackend{calls: calls}
	now := time.Now()
	digest := strings.Repeat("a", 64)
	m.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), digestSHA256: digest}
	request := RunRequest{Entrypoint: "/agent", Backend: m.config.Backend,
		ArtifactManifestSHA256: digest}
	for name, mutate := range map[string]func(*RunRequest){
		"wrong-backend": func(r *RunRequest) { r.Backend = "firecracker-linux" },
		"wrong-digest":  func(r *RunRequest) { r.ArtifactManifestSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			mutate(&invalid)
			if _, err := m.Run(context.Background(), invalid); !errors.Is(err, ErrTemplateMismatch) {
				t.Fatalf("selection mismatch was accepted: %v", err)
			}
		})
	}
	partial := request
	partial.ArtifactManifestSHA256 = ""
	if _, err := m.Run(context.Background(), partial); !errors.Is(err, ErrInvalidSelector) {
		t.Fatalf("partial selection was accepted: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("selection rejection started a VM")
	}
	result, err := m.Run(context.Background(), request)
	if err != nil || result.State != "succeeded" || calls.Load() != 1 {
		t.Fatalf("matching selector did not execute: %+v %v calls=%d", result, err, calls.Load())
	}
}

func TestOSvEnvironmentRequiresSignedAgentFeatureBeforeVMAllocation(t *testing.T) {
	m := testManager(t, "output")
	m.config.Backend = "firecracker-osv"
	m.config.AllowedEntrypoints = []string{"/task-probe.so"}
	calls := &atomic.Int32{}
	m.backend = countedBackend{calls: calls}
	now := time.Now()
	m.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour)}
	request := RunRequest{Entrypoint: "/task-probe.so",
		Environment: map[string]string{"SANDBOX_TEST_MARKER": "native-env-ok"}}
	if _, err := m.Run(context.Background(), request); err == nil || calls.Load() != 0 {
		t.Fatalf("unsigned environment reached VM: %v calls=%d", err, calls.Load())
	}
	report, err := m.Capabilities()
	if err != nil || report.Features.Environment {
		t.Fatalf("unsigned environment capability advertised: %+v %v", report.Features, err)
	}
	m.manifest.AgentFeatures = []string{"environment"}
	report, err = m.Capabilities()
	if err != nil || !report.Features.Environment || report.Limits.MaxEnvEntries != 32 ||
		report.Limits.MaxEnvBytes != 8192 {
		t.Fatalf("signed environment capability missing: %+v %v", report, err)
	}
	result, err := m.Run(context.Background(), request)
	if err != nil || result.State != "succeeded" || calls.Load() != 1 {
		t.Fatalf("signed environment was not admitted: %+v %v calls=%d", result, err, calls.Load())
	}
}

func TestOSvStdinRequiresSignedAgentFeatureBeforeVMAllocation(t *testing.T) {
	m := testManager(t, "output")
	m.config.Backend = "firecracker-osv"
	m.config.AllowedEntrypoints = []string{"/task-probe.so"}
	calls := &atomic.Int32{}
	m.backend = countedBackend{calls: calls}
	now := time.Now()
	m.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), AgentFeatures: []string{"environment"}}
	req := RunRequest{Entrypoint: "/task-probe.so", Stdin: []byte{}}
	if _, err := m.Run(context.Background(), req); err == nil || calls.Load() != 0 {
		t.Fatalf("unsigned stdin reached VM: %v calls=%d", err, calls.Load())
	}
	report, err := m.Capabilities()
	if err != nil || report.Features.Stdin {
		t.Fatalf("unsigned stdin capability advertised: %+v %v", report.Features, err)
	}
	m.manifest.AgentFeatures = []string{"environment", "stdin"}
	report, err = m.Capabilities()
	if err != nil || !report.Features.Stdin || report.Limits.MaxStdinBytes != osvJobStdinMaxBytes {
		t.Fatalf("signed stdin capability missing: %+v %v", report, err)
	}
	result, err := m.Run(context.Background(), req)
	if err != nil || result.State != "succeeded" || calls.Load() != 1 {
		t.Fatalf("signed stdin was not admitted: %+v %v calls=%d", result, err, calls.Load())
	}
}

func TestRunningManagerRejectsInvalidArtifactWindow(t *testing.T) {
	for _, future := range []bool{false, true} {
		m := testManager(t, "output")
		calls := &atomic.Int32{}
		m.backend = countedBackend{calls: calls}
		now := time.Now()
		m.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)}
		if future {
			m.manifest.CreatedAt = now.Add(10 * time.Minute)
			m.manifest.ExpiresAt = now.Add(time.Hour)
		}
		if _, err := m.Run(context.Background(), RunRequest{}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid active window admitted: %v", err)
		}
		if calls.Load() != 0 {
			t.Fatal("expired artifact launched backend")
		}
		found := false
		for _, check := range m.Doctor().Checks {
			if check.Name == "signed-artifact-validity" {
				found = true
				if check.OK {
					t.Fatal("expired manifest reported ready")
				}
			}
		}
		if !found {
			t.Fatal("missing runtime validity check")
		}
		api := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
		req := httptest.NewRequest(http.MethodPost, "/v1/jobs", strings.NewReader(`{"entrypoint":"/agent"}`))
		req.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		api.ServeHTTP(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("unavailable artifacts returned %d", response.Code)
		}
	}
}

func TestCleanupFailureStopsAdmissionAndDoctorReadiness(t *testing.T) {
	m := testManager(t, "output")
	m.config.Production = true
	calls := &atomic.Int32{}
	m.backend = countedBackend{calls: calls}
	m.cleanupFailed.Store(true)
	if _, err := m.Run(context.Background(), RunRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("job admitted after cleanup failure: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("backend called after cleanup failure")
	}
	found := false
	for _, check := range m.Doctor().Checks {
		if check.Name == "job-cleanup" {
			found = true
			if check.OK {
				t.Fatal("cleanup failure reported healthy")
			}
		}
	}
	if !found || m.Doctor().Ready {
		t.Fatal("doctor did not fail closed after cleanup failure")
	}
}

type helperBackend struct{ mode string }

func (h helperBackend) Name() string { return "helper" }
func (h helperBackend) Command(ctx context.Context, req RunRequest, _ ResolvedArtifacts, _ string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--", h.mode, req.Args[1]), nil
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-2]
	jobID := os.Args[len(os.Args)-1]
	if mode == "sleep" {
		time.Sleep(2 * time.Second)
	}
	if mode == "pool-wait" {
		time.Sleep(30 * time.Second)
	}
	if mode == "flood" {
		_, _ = os.Stdout.Write(make([]byte, 32*1024))
	}
	_, _ = os.Stdout.WriteString("guest-output\nOSV_AGENT_RESULT {\"protocol\":\"osv-agent/v1\",\"job_id\":\"" + jobID + "\",\"ok\":true}\n")
	if mode == "exit1" {
		os.Exit(1)
	}
	os.Exit(0)
}

type controlHelperBackend struct{ mode, result string }

func (b controlHelperBackend) Name() string             { return "control-helper" }
func (b controlHelperBackend) UsesControlChannel() bool { return true }
func (b controlHelperBackend) Command(ctx context.Context, req RunRequest, _ ResolvedArtifacts, _ string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--", b.mode, req.jobID), nil
}
func (b controlHelperBackend) Exchange(ctx context.Context, req RunRequest, _ string) (string, error) {
	if b.result == "error" {
		return "", errors.New("guest disconnected")
	}
	if b.result == "hang" {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return fmt.Sprintf("%s{\"protocol\":\"osv-agent/v1\",\"job_id\":%q,\"ok\":%s}", guestResultPrefix, req.jobID, b.result), nil
}

func TestControlChannelIsCompletionAuthority(t *testing.T) {
	for _, tc := range []struct {
		mode, reply, state string
		protocol           bool
	}{
		{"output", "error", "protocol_error", false},
		{"output", "false", "guest_error", true},
		{"flood", "true", "succeeded", true},
		{"output", "hang", "protocol_error", false},
	} {
		t.Run(tc.mode+"-"+tc.reply, func(t *testing.T) {
			m := testManager(t, "output")
			m.config.Limits.MaxOutputByte = 1024
			m.backend = controlHelperBackend{mode: tc.mode, result: tc.reply}
			result, err := m.Run(context.Background(), RunRequest{TimeoutMS: 5000})
			if err != nil || result.State != tc.state || result.ProtocolOK != tc.protocol {
				t.Fatalf("serial changed completion authority: %+v %v", result, err)
			}
			if len(result.Output) > 1024 {
				t.Fatalf("output exceeded budget: %d", len(result.Output))
			}
			if tc.mode == "flood" && !result.OutputTruncated {
				t.Fatal("serial flood not marked truncated")
			}
		})
	}
}

func TestManagerAcceptsBoundResultBeforeExpectedVMMShutdown(t *testing.T) {
	m := testManager(t, "exit1")
	result, err := m.Run(context.Background(), RunRequest{TimeoutMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "succeeded" || result.ExitCode != 0 || !result.ProtocolOK {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestManagerRunsAndCapturesOutput(t *testing.T) {
	m := testManager(t, "output")
	result, err := m.Run(context.Background(), RunRequest{TimeoutMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "succeeded" || !result.ProtocolOK {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.StartupMode != "cold" {
		t.Fatalf("fresh non-pooled execution omitted its trusted cold mode: %q", result.StartupMode)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(data, &wire) != nil || string(wire["startup_mode"]) != `"cold"` {
		t.Fatal("public result lost its cold execution mode", string(data))
	}
	if result.StartupDurationUS != 0 || wire["startup_duration_us"] != nil {
		t.Fatal("legacy execution invented an unmeasured readiness duration")
	}
}

func TestManagerKillsTimedOutVM(t *testing.T) {
	m := testManager(t, "sleep")
	result, err := m.Run(context.Background(), RunRequest{TimeoutMS: 20})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "timed_out" || !result.TimedOut {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestGuestResultMustBeBoundAndDeclareOutcome(t *testing.T) {
	valid := "OSV_AGENT_RESULT {\"protocol\":\"osv-agent/v1\",\"job_id\":\"0123456789abcdef01234567\",\"ok\":false}\n"
	_, protocolOK, guestOK := extractGuestResult(valid, "0123456789abcdef01234567")
	if !protocolOK || guestOK {
		t.Fatal("expected a valid negative guest result")
	}
	missingOutcome := "OSV_AGENT_RESULT {\"protocol\":\"osv-agent/v1\",\"job_id\":\"0123456789abcdef01234567\"}\n"
	if _, protocolOK, _ := extractGuestResult(missingOutcome, "0123456789abcdef01234567"); protocolOK {
		t.Fatal("result without an explicit outcome must be rejected")
	}
	if _, protocolOK, _ := extractGuestResult(valid, "ffffffffffffffffffffffff"); protocolOK {
		t.Fatal("result for a different job must be rejected")
	}
}

func testManager(t *testing.T, mode string) *Manager {
	t.Helper()
	c := testConfig()
	c.RunRoot = t.TempDir()
	c.Defaults.TimeoutMS = 5000
	c.Limits.MaxConcurrent = 1
	return &Manager{
		config: c, artifacts: ResolvedArtifacts{}, backend: helperBackend{mode: mode}, capacity: newResourceLedger(c),
	}
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "-test.run=TestHelperProcess" {
		_ = os.Setenv("GO_WANT_HELPER_PROCESS", "1")
	}
	os.Exit(m.Run())
}

func BenchmarkBuildQEMUArgs(b *testing.B) {
	req := RunRequest{Entrypoint: "/agent", Args: []string{"task"}, MemoryMiB: 128, VCPUs: 1}
	a := ResolvedArtifacts{KernelPath: "/a/kernel", ImagePath: "/a/image", Format: "raw"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = BuildQEMUArgs(req, a)
	}
}
