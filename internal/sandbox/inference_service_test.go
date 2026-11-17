package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func inferenceServiceFixture(t *testing.T, provider string, configure func(*EgressPolicy, *InferencePolicy)) (*EgressServer, *inferenceRootClient, string, context.CancelFunc, <-chan error) {
	t.Helper()
	requireGuestProxyRoot(t)
	base, ledger, tenant, directory := inferenceEngineFixture(t, provider, configure, nil)
	base.Close()
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("inference-other-token"))
	input := AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []TenantPolicy{tenant.policy, {
		ID: "tenant-b", TokenSHA256: hex.EncodeToString(digest[:]), AllowedEntrypoints: []string{"/agent"},
		RequestsPerSecond: 100, Burst: 100, MaxConcurrent: 1}}}
	data, _ := json.Marshal(input)
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(authPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewConfiguredEgressServer(auth, &egressMemoryAudit{}, EgressServiceConfig{GuestProxy: true,
		Inference: &InferenceServiceConfig{LedgerDirectory: directory, MaxTasks: 16}, MaxConcurrent: 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	main, cancel, done := startEgressTestSocket(t, server)
	root := newInferenceRootClient(main)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if info, err := os.Lstat(inferenceControlSocketPath(main)); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm()&0o077 == 0 {
			// A published pathname is not readiness: listen precedes chmod and
			// Serve. Probe metadata only; never bind or invoke a model here.
			probe, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := root.exchange(probe, "inspect", inferenceRootRequest{Binding: inferenceBinding{Tenant: "tenant-a", TaskID: inferenceTestBinding().TaskID}})
			stop()
			var failure *InferenceError
			if errors.As(err, &failure) && failure.Status == 404 && failure.Code == "inference_not_found" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("inference control socket did not appear")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("inference service shutdown did not join")
		}
	})
	return server, root, main, cancel, done
}

func TestInferenceServiceRootGrantAndTenantHistory(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"ok"}`))
	}))
	t.Cleanup(provider.Close)
	s, root, main, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	binding, request := inferenceTestBinding(), inferenceRequest(1)
	_, err := root.invoke(context.Background(), binding, request)
	expectInferenceFailure(t, err, "inference_not_found")
	if calls.Load() != 0 {
		t.Fatal("unbound task reached provider")
	}
	bill, err := root.task(context.Background(), "bind", binding)
	if err != nil || bill.Closed || len(bill.Invocations) != 0 || validateInferenceBill(bill, binding) != nil {
		t.Fatal("root grant was not persisted", err)
	}
	for _, name := range []string{"tenant", "vm", "lease"} {
		other := binding
		switch name {
		case "tenant":
			other.Tenant = "tenant-b"
		case "vm":
			other.VMID = "444444444444444444444444"
		case "lease":
			other.LeaseID = "444444444444444444444444"
		}
		_, err := root.invoke(context.Background(), other, request)
		expectInferenceFailure(t, err, "inference_binding")
		_, err = root.task(context.Background(), "close", other)
		expectInferenceFailure(t, err, "inference_binding")
	}
	result, err := root.invoke(context.Background(), binding, request)
	if err != nil || result.Invocation.State != "succeeded" || calls.Load() != 1 {
		t.Fatal("root model channel failed", err)
	}
	client := NewEgressClient(main)
	status, data, err := client.exchange(context.Background(), "GET", "/v1/inference/bills/"+binding.TaskID, "Bearer inference-test-token", nil)
	if err != nil || status != 200 || decodeInferenceJSON(data, &bill) != nil || validateInferenceBill(bill, binding) != nil || bill.SettledUnits == 0 {
		t.Fatal("authenticated tenant history unavailable", status, err)
	}
	status, data, err = client.exchange(context.Background(), "GET", "/v1/inference/bills/"+binding.TaskID, "Bearer inference-other-token", nil)
	if err != nil || status != 404 || bytes.Contains(data, []byte(binding.TaskID)) {
		t.Fatal("other tenant observed a bill", status, err)
	}
	for n := 0; n < 2; n++ {
		bill, err = root.task(context.Background(), "close", binding)
		if err != nil || !bill.Closed || len(bill.Invocations) != 1 {
			t.Fatal("close was not durable and idempotent", err)
		}
	}
	_, err = root.task(context.Background(), "bind", binding)
	expectInferenceFailure(t, err, "inference_task_closed")
	_, err = root.invoke(context.Background(), binding, inferenceRequest(2))
	expectInferenceFailure(t, err, "inference_task_closed")
	if calls.Load() != 1 || len(s.slots) != 0 {
		t.Fatal("closed task consumed provider or leaked a slot")
	}
}

func TestInferenceServiceKernelPeerAndChannelBoundaries(t *testing.T) {
	s, root, _, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	body, _ := marshalInferenceJSON(inferenceRootRequest{Protocol: inferenceRootProtocol, Binding: inferenceTestBinding()})
	for _, known := range []bool{false, true} {
		request := httptest.NewRequest("POST", "/v1/inference/root/bind", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer inference-test-token")
		request.Header.Set("X-OSV-UID", "0")
		if known {
			request = request.WithContext(context.WithValue(request.Context(), egressPeerKey{}, uint32(65530)))
		}
		writer := httptest.NewRecorder()
		s.serveInferenceRoot(writer, request, true)
		if writer.Code != 403 || !bytes.Contains(writer.Body.Bytes(), []byte("inference_root_required")) {
			t.Fatal("Bearer/header supplied a root grant")
		}
	}
	// The control socket rejects all model requests, regardless of root UID.
	invocation := inferenceRequest(1)
	request := inferenceRootRequest{Protocol: inferenceRootProtocol, Binding: inferenceTestBinding(), Invocation: &invocation}
	data, _ := marshalInferenceJSON(request)
	httpRequest, _ := http.NewRequest("POST", "http://egress.invalid/v1/inference/root/invoke", bytes.NewReader(data))
	response, err := root.control.Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("model occupied a control channel")
	}
	if _, err := s.inference.ledger.bill("tenant-a", inferenceTestBinding().TaskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("untrusted or wrong-channel request created a grant")
	}
}

func TestInferenceServiceCloseWinsBeforeLateBind(t *testing.T) {
	s, root, _, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	bill, err := root.task(context.Background(), "close", inferenceTestBinding())
	if err != nil || !bill.Closed || len(bill.Invocations) != 0 {
		t.Fatal("early close did not create a durable closed tombstone", err)
	}
	_, err = root.task(context.Background(), "bind", inferenceTestBinding())
	expectInferenceFailure(t, err, "inference_task_closed")
	stored, err := s.inference.ledger.boundTask(inferenceTestBinding(), false)
	if err != nil || !stored.Closed || len(stored.Invocations) != 0 {
		t.Fatal("late bind reopened an already closed task")
	}
}

func TestInferenceServiceCloseJoinsPendingModel(t *testing.T) {
	arrived := make(chan struct{}, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(provider.Close)
	s, root, _, _, _ := inferenceServiceFixture(t, provider.URL, func(n *EgressPolicy, _ *InferencePolicy) { n.MaxConcurrent = 1 })
	binding := inferenceTestBinding()
	if _, err := root.task(context.Background(), "bind", binding); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := root.invoke(context.Background(), binding, inferenceRequest(1)); done <- err }()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not receive active model request")
	}
	bill, err := root.task(context.Background(), "close", binding)
	if err != nil || !bill.Closed || len(bill.Invocations) != 1 || bill.Invocations[0].State != "uncertain" || bill.HeldUnits == 0 {
		t.Fatal("task close released unknown spend or failed to join", bill, err)
	}
	select {
	case err := <-done:
		expectInferenceFailure(t, err, "inference_cancelled")
	case <-time.After(3 * time.Second):
		t.Fatal("model HTTP channel remained active after task close")
	}
	if len(s.slots) != 0 {
		t.Fatal("closing left a model network slot occupied")
	}
}

func TestInferenceServiceControlIndependentOfFullMain(t *testing.T) {
	_, root, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	if _, err := root.task(context.Background(), "bind", inferenceTestBinding()); err != nil {
		t.Fatal(err)
	}
	var idle []net.Conn
	defer func() {
		for _, conn := range idle {
			_ = conn.Close()
		}
	}()
	for n := 0; n < 64; n++ {
		conn, err := net.DialTimeout("unix", main, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, conn)
		_, _ = io.WriteString(conn, "POST /")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bill, err := root.task(ctx, "close", inferenceTestBinding())
	if err != nil || !bill.Closed {
		t.Fatal("full model HTTP connections starved durable task closure", err)
	}
}

func TestInferenceServiceConfigurationAndPersistentPath(t *testing.T) {
	for _, path := range []string{"/tmp/state", "/var/tmp/state", "/run/state", "/var/run/state", "/dev/shm/state"} {
		if validateInferenceServiceConfig(&InferenceServiceConfig{LedgerDirectory: path}, true, true) == nil {
			t.Fatal("production ledger accepted volatile storage")
		}
	}
	for _, configure := range []InferenceServiceConfig{{LedgerDirectory: "relative"}, {LedgerDirectory: "/managed/../state"},
		{LedgerDirectory: "/managed/state", MaxTasks: -1}, {LedgerDirectory: "/managed/state", MaxTasks: 65537}} {
		if validateInferenceServiceConfig(&configure, false, true) == nil {
			t.Fatal("invalid ledger configuration accepted")
		}
	}
	if validateInferenceServiceConfig(&InferenceServiceConfig{LedgerDirectory: "/managed/state"}, false, false) == nil {
		t.Fatal("inference bypassed explicit guest-proxy authorization")
	}
	config := InferenceServiceConfig{LedgerDirectory: filepath.Join(inferencePrivateTestDirectory(t), "state")}
	if err := validateInferenceServiceConfig(&config, false, true); err != nil || config.MaxTasks != 4096 {
		t.Fatal("offline verification state/default bound rejected", err)
	}
	if _, err := os.Stat("/dev/shm"); err == nil {
		// Exercise filesystem/symlink inspection separately from the already
		// covered pathname-prefix guard, so that guard cannot mask a regression.
		alias := filepath.Join(inferencePrivateTestDirectory(t), "alias")
		if err := os.Symlink("/dev/shm", alias); err != nil {
			t.Fatal(err)
		}
		if validateInferencePersistentDirectory(filepath.Join(alias, "state")) == nil {
			t.Fatal("symbolic alias into volatile storage accepted")
		}
		var fs syscall.Statfs_t
		if syscall.Statfs("/dev/shm", &fs) == nil && uint64(fs.Type) == 0x1021994 && validateInferencePersistentDirectory("/dev/shm/inference-fixture-state") == nil {
			t.Fatal("actual tmpfs was accepted as persistent storage")
		}
	}
}
