package sandbox

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

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
	_, _ = os.Stdout.WriteString("guest-output\nOSV_AGENT_RESULT {\"protocol\":\"osv-agent/v1\",\"job_id\":\"" + jobID + "\",\"ok\":true}\n")
	if mode == "exit1" {
		os.Exit(1)
	}
	os.Exit(0)
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
	c.Defaults.TimeoutMS = 1000
	return &Manager{
		config: c, artifacts: ResolvedArtifacts{}, backend: helperBackend{mode: mode}, sem: make(chan struct{}, 1),
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
