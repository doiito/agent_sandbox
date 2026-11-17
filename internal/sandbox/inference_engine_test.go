package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func inferenceEngineFixture(t *testing.T, endpoint string, configure func(*EgressPolicy, *InferencePolicy), audit *egressMemoryAudit) (*inferenceEngine, *InferenceLedger, *tenantRuntime, string) {
	t.Helper()
	_, origin, err := egressURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	network := EgressPolicy{AllowedOrigins: []string{origin}, AllowedCIDRs: []string{"127.0.0.0/8"}, MaxConcurrent: 16,
		MaxRequestBytes: 128, MaxResponseBytes: 128, TimeoutMS: 1000}
	budget := InferenceUnits(100000)
	policy := InferencePolicy{Endpoints: []InferenceEndpoint{{Name: "model", URL: endpoint,
		Price: InferencePrice{RequestUnits: 5, InputByteUnits: 2, OutputByteUnits: 3}}}, MaxInvocations: 64, BudgetUnits: &budget}
	if configure != nil {
		configure(&network, &policy)
	}
	digest := sha256.Sum256([]byte("inference-test-token"))
	input := AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []TenantPolicy{{ID: "tenant-a", TokenSHA256: hex.EncodeToString(digest[:]),
		AllowedEntrypoints: []string{"/agent"}, RequestsPerSecond: 1000, Burst: 1000, MaxConcurrent: 1, Egress: &network, Inference: &policy}}}
	path := filepath.Join(t.TempDir(), "auth.json")
	data, err := json.Marshal(input)
	if err != nil || os.WriteFile(path, data, 0o600) != nil {
		t.Fatal("cannot write inference test policy")
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	if audit == nil {
		audit = &egressMemoryAudit{}
	}
	server, err := NewEgressServer(auth, audit, "", 16)
	if err != nil {
		t.Fatal(err)
	}
	ledger, directory := inferenceTestLedger(t, 16)
	engine, err := newInferenceEngine(server, ledger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	tenant, _ := auth.Authenticate("Bearer inference-test-token")
	return engine, ledger, tenant, directory
}

func inferenceRequest(n int) InferenceInvokeRequest {
	return InferenceInvokeRequest{ID: fmt.Sprintf("%024x", n), Endpoint: "model", Payload: json.RawMessage(`{"input":"hello"}`)}
}
func expectInferenceFailure(t *testing.T, err error, code string) *InferenceError {
	t.Helper()
	var failure *InferenceError
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
	return failure
}
func inferenceOneReceipt(t *testing.T, ledger *InferenceLedger) (InferenceBill, InferenceInvocationReceipt) {
	t.Helper()
	binding := inferenceTestBinding()
	bill, err := ledger.bill(binding.Tenant, binding.TaskID)
	if err != nil || len(bill.Invocations) != 1 {
		t.Fatal("expected exactly one persisted invocation", bill, err)
	}
	return bill, bill.Invocations[0]
}

func TestInferenceEngineActualTLSCredentialsMeteringAndRedaction(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	secret := "fixture-model-secret"
	secretPath := filepath.Join(inferencePrivateTestDirectory(t), "model.token")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := inferenceRequest(1)
	response := []byte(" {\"answer\":\"ok\"} \n")
	var calls atomic.Int32
	server, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.Path != "/invoke" || r.TLS.ServerName != "allowed.test" ||
			r.Header.Get("Authorization") != "Bearer "+secret || r.Header.Get("Content-Type") != "application/json" || !bytes.Equal(body, request.Payload) {
			t.Error("fixed endpoint, credential injection, TLS identity, or payload changed")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(response)
	}))
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	audit := &egressMemoryAudit{}
	engine, ledger, tenant, directory := inferenceEngineFixture(t, "https://allowed.test:"+port+"/invoke", func(_ *EgressPolicy, p *InferencePolicy) {
		p.Endpoints[0].Credential = &InferenceCredential{File: secretPath, Header: "Authorization", Prefix: "Bearer "}
	}, audit)
	engine.egress.engine.roots = roots
	var lookups atomic.Int32
	engine.egress.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	result, err := engine.invoke(context.Background(), inferenceTestBinding(), request)
	if err != nil || !bytes.Equal(result.Data, response) || result.Invocation.State != "succeeded" || !result.Invocation.Dispatched {
		t.Fatal("actual TLS invocation failed", result, err)
	}
	price := tenant.inference.policy.Endpoints[0].Price
	expected, _ := price.cost(uint64(len(request.Payload)), uint64(len(response)))
	bill, receipt := inferenceOneReceipt(t, ledger)
	if receipt.InputBytes != uint64(len(request.Payload)) || receipt.OutputBytes != uint64(len(response)) || receipt.SettledUnits != expected ||
		bill.SettledUnits != expected || bill.HeldUnits != 0 || calls.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("host byte accounting or request count changed", bill)
	}
	_, err = engine.invoke(context.Background(), inferenceTestBinding(), request)
	if expectInferenceFailure(t, err, "inference_replay").InvocationID != request.ID || calls.Load() != 1 {
		t.Fatal("known ID was replayed or omitted")
	}
	capabilities, _ := json.Marshal(tenant.inference.capabilities())
	stored, _ := os.ReadFile(filepath.Join(directory, inferenceTestBinding().TaskID+".json"))
	audit.mu.Lock()
	events, _ := json.Marshal(audit.events)
	if len(audit.events) != 4 || audit.events[0].Event != "infer.admit" || audit.events[1].Event != "infer.allow" ||
		audit.events[2].Event != "infer.complete" || audit.events[2].TaskID != inferenceTestBinding().TaskID ||
		audit.events[2].Inference.SettledUnits != expected || audit.events[3].Event != "infer.deny" {
		t.Error("missing admission, dial, committed completion, or replay denial audit")
	}
	audit.mu.Unlock()
	for _, content := range [][]byte{capabilities, stored, events} {
		for _, forbidden := range []string{secret, secretPath, "hello", "answer"} {
			if bytes.Contains(content, []byte(forbidden)) {
				t.Fatal("private material escaped into discovery or durable metering")
			}
		}
	}
	if bytes.Contains(capabilities, []byte("allowed.test")) {
		t.Fatal("endpoint address exposed by discovery")
	}
}

func TestInferenceEngineDenialsNeverReachProvider(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	t.Cleanup(server.Close)
	for _, name := range []string{"budget", "endpoint", "json", "utf8", "size", "timeout", "identity"} {
		t.Run(name, func(t *testing.T) {
			engine, ledger, _, _ := inferenceEngineFixture(t, server.URL, func(_ *EgressPolicy, p *InferencePolicy) {
				if name == "budget" {
					*p.BudgetUnits = 0
				}
			}, nil)
			request := inferenceRequest(1)
			code := "inference_request"
			switch name {
			case "budget":
				code = "inference_budget"
			case "endpoint":
				request.Endpoint, code = "unknown", "inference_endpoint"
			case "json":
				request.Payload = []byte("NaN")
			case "utf8":
				request.Payload = []byte{'"', 255, '"'}
			case "size":
				request.Payload = []byte(`"` + strings.Repeat("x", 129) + `"`)
			case "timeout":
				request.TimeoutMS = 1001
			case "identity":
				request.ID = "not-an-id"
			}
			result, err := engine.invoke(context.Background(), inferenceTestBinding(), request)
			expectInferenceFailure(t, err, code)
			if len(result.Data) != 0 || calls.Load() != 0 {
				t.Fatal("denied invocation reached provider")
			}
			if _, err := ledger.bill("tenant-a", inferenceTestBinding().TaskID); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unadmitted request created a bill")
			}
		})
	}
}

func TestInferenceEngineProviderFailuresHaveDurableMetering(t *testing.T) {
	for _, name := range []string{"status", "redirect", "media", "json", "limit", "partial"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			body := []byte(`{"error":"busy"}`)
			status, code := 200, "inference_response_json"
			switch name {
			case "status":
				status, code = 429, "inference_status"
			case "redirect":
				status, code = 307, "inference_redirect"
			case "json":
				body = []byte("not-json")
			case "limit":
				body, code = []byte(strings.Repeat("x", 200)), "inference_response_limit"
			case "partial":
				body, code = []byte(`{"`), "inference_response"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if name == "media" {
					w.Header().Set("Content-Type", "text/plain")
				}
				if name == "redirect" {
					w.Header().Set("Location", "/unexpected-replay")
				}
				if name == "partial" {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)
			engine, ledger, _, _ := inferenceEngineFixture(t, server.URL, nil, nil)
			result, err := engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
			expectInferenceFailure(t, err, code)
			bill, receipt := inferenceOneReceipt(t, ledger)
			if len(result.Data) != 0 || calls.Load() != 1 || receipt.HTTPStatus != status || !receipt.Dispatched || receipt.Code != code {
				t.Fatal("provider failure exposed data, replayed, or lost metering", bill)
			}
			if name == "partial" {
				if receipt.State != "uncertain" || bill.HeldUnits != receipt.ReservedUnits || bill.SettledUnits != 0 || receipt.OutputBytes != 2 {
					t.Fatal("interrupted response released unknown budget", bill)
				}
			} else if receipt.State != "failed" || bill.HeldUnits != 0 || bill.SettledUnits == 0 {
				t.Fatal("known bounded failure was not settled", bill)
			}
			if name == "limit" && (receipt.OutputBytes != 129 || receipt.SettledUnits != receipt.ReservedUnits) {
				t.Fatal("oversized response exceeded its reserved price cap", bill)
			}
		})
	}
}

func TestInferenceEngineCancellationTimeoutAndShutdownHoldUnknownBudget(t *testing.T) {
	for _, name := range []string{"cancel", "timeout", "shutdown"} {
		t.Run(name, func(t *testing.T) {
			arrived := make(chan struct{}, 1)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				calls.Add(1)
				arrived <- struct{}{}
				<-r.Context().Done()
			}))
			t.Cleanup(server.Close)
			engine, ledger, tenant, _ := inferenceEngineFixture(t, server.URL, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := inferenceRequest(1)
			if name == "timeout" {
				request.TimeoutMS = 100
			}
			done := make(chan error, 1)
			go func() { _, err := engine.invoke(ctx, inferenceTestBinding(), request); done <- err }()
			select {
			case <-arrived:
			case <-time.After(3 * time.Second):
				t.Fatal("provider did not receive request")
			}
			code := "inference_cancelled"
			switch name {
			case "cancel":
				cancel()
			case "timeout":
				code = "inference_timeout"
			case "shutdown":
				engine.Close()
			}
			select {
			case err := <-done:
				expectInferenceFailure(t, err, code)
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not join the outbound call")
			}
			bill, receipt := inferenceOneReceipt(t, ledger)
			if receipt.State != "uncertain" || !receipt.Dispatched || bill.HeldUnits != receipt.ReservedUnits || bill.SettledUnits != 0 ||
				len(engine.egress.slots) != 0 || len(tenant.netSem) != 0 || calls.Load() != 1 {
				t.Fatal("unknown outcome lost its reservation or leaked a quota", bill)
			}
			_, err := engine.invoke(context.Background(), inferenceTestBinding(), request)
			if name == "shutdown" {
				expectInferenceFailure(t, err, "inference_unavailable")
			} else {
				expectInferenceFailure(t, err, "inference_replay")
			}
			if calls.Load() != 1 {
				t.Fatal("interrupted POST was automatically replayed")
			}
		})
	}
}

func TestInferenceEngineBeforeDispatchCancellationIsUncharged(t *testing.T) {
	engine, ledger, _, _ := inferenceEngineFixture(t, "http://127.0.0.1:1/invoke", nil, nil)
	var dials atomic.Int32
	engine.egress.engine.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := engine.invoke(ctx, inferenceTestBinding(), inferenceRequest(1))
	expectInferenceFailure(t, err, "inference_cancelled")
	bill, receipt := inferenceOneReceipt(t, ledger)
	if receipt.State != "failed" || receipt.Dispatched || bill.HeldUnits != 0 || bill.SettledUnits != 0 || dials.Load() != 0 {
		t.Fatal("request canceled before dispatch consumed budget", bill)
	}
}
