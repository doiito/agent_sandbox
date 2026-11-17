package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestInferenceCrashProcessHelper(t *testing.T) {
	directory := os.Getenv("OSV_INFERENCE_CRASH_TEST_LEDGER")
	if directory == "" {
		t.Skip("subprocess-only inference crash helper")
	}
	auth, err := LoadAuthenticator(os.Getenv("OSV_INFERENCE_CRASH_TEST_AUTH"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenInferenceLedger(directory, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	audit, err := OpenEgressAudit(os.Getenv("OSV_INFERENCE_CRASH_TEST_AUDIT"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	server, err := NewEgressServer(auth, audit, "", 16)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newInferenceEngine(server, ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	_, _ = engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	t.Fatal("parent must SIGKILL this helper while its provider request is pending")
}

func TestInferenceActualProcessDeathRecoversHoldWithoutReplayingHTTP(t *testing.T) {
	arrived := make(chan struct{}, 1)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		calls.Add(1)
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(provider.Close)
	engine, ledger, tenant, directory := inferenceEngineFixture(t, provider.URL, func(n *EgressPolicy, _ *InferencePolicy) { n.TimeoutMS = 30000 }, nil)
	engine.Close()
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []TenantPolicy{tenant.policy}})
	managed := inferencePrivateTestDirectory(t)
	authPath, auditPath := filepath.Join(managed, "auth.json"), filepath.Join(managed, "audit.jsonl")
	if err := os.WriteFile(authPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestInferenceCrashProcessHelper$", "-test.timeout=40s")
	command.Env = append(os.Environ(), "OSV_INFERENCE_CRASH_TEST_LEDGER="+directory,
		"OSV_INFERENCE_CRASH_TEST_AUTH="+authPath, "OSV_INFERENCE_CRASH_TEST_AUDIT="+auditPath)
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not reach provider before crash")
	}
	if other, err := OpenInferenceLedger(directory, 16); err == nil {
		_ = other.Close()
		t.Fatal("second process acquired the child's live writer lock")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := command.Wait(); !errors.As(err, &exit) {
		t.Fatal("helper did not terminate by a signal", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("helper did not receive the intended abrupt process death")
	}
	reopened, err := OpenInferenceLedger(directory, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	bill, receipt := inferenceOneReceipt(t, reopened)
	if receipt.State != "uncertain" || receipt.Code != "inference_restarted" || bill.HeldUnits != receipt.ReservedUnits || bill.SettledUnits != 0 {
		t.Fatal("actual process death lost the durable reservation", bill)
	}
	restarted, err := newInferenceEngine(engine.egress, reopened)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	_, err = restarted.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	expectInferenceFailure(t, err, "inference_replay")
	if calls.Load() != 1 {
		t.Fatal("post-crash query or retry repeated the model execution")
	}
	persisted, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(persisted)), "\n")
	if len(lines) != 2 {
		t.Fatal("admission/dial audit was not persisted before external execution")
	}
	for index, name := range []string{"infer.admit", "infer.allow"} {
		var event EgressAuditEvent
		if json.Unmarshal([]byte(lines[index]), &event) != nil || event.Event != name || event.TaskID != inferenceTestBinding().TaskID || event.Protocol != "osv-sandbox-egress-audit/v1" {
			t.Fatal("abrupt exit lost or corrupted its durable audit identity")
		}
	}
}

func TestInferenceCredentialRejectsUnsafeFilesAndHeaderContent(t *testing.T) {
	for _, name := range []string{"empty", "injection", "binary", "large", "mode", "hardlink", "symlink", "parent-mode", "parent-symlink"} {
		t.Run(name, func(t *testing.T) {
			directory := inferencePrivateTestDirectory(t)
			path := filepath.Join(directory, "token")
			data := []byte("valid-token\n")
			switch name {
			case "empty":
				data = []byte("\n")
			case "injection":
				data = []byte("valid\r\nInjected: value\n")
			case "binary":
				data = []byte{0, 255}
			case "large":
				data = bytes.Repeat([]byte("x"), 4097)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "parent-mode":
				if err := os.Chmod(directory, 0o777); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(directory, "linked")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(directory, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "parent-symlink":
				link := filepath.Join(inferencePrivateTestDirectory(t), "link")
				if err := os.Symlink(directory, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "token")
			}
			if _, err := readInferenceCredential(InferenceCredential{File: path, Header: "Authorization", Prefix: "Bearer "}); err == nil || strings.Contains(err.Error(), path) {
				t.Fatal("unsafe credential accepted or path leaked")
			}
		})
	}
	directory := inferencePrivateTestDirectory(t)
	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4089)+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readInferenceCredential(InferenceCredential{File: path, Header: "Authorization", Prefix: "Bearer "})
	if err != nil || len(value) != 4096 {
		t.Fatal("canonical trailing CRLF or exact header bound rejected")
	}
}
