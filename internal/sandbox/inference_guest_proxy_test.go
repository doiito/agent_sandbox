package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferenceGuestOuterPolicyErrorMatchesSharedWireFixture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the authenticated outer proxy endpoint requires kernel root credentials")
	}
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"answer":"unexpected"}`))
	}))
	t.Cleanup(provider.Close)
	server, root, main, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	binding := inferenceTestBinding()
	if _, err := root.task(context.Background(), "bind", binding); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://egress.invalid/v1/guest-proxy", nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"Connection": "upgrade", "Upgrade": guestProxyUpgrade,
		"X-OSV-Tenant": binding.Tenant, "X-OSV-Task": binding.TaskID, "X-OSV-VM": binding.VMID,
		"X-OSV-Lease": binding.LeaseID, "X-OSV-Inference": "remote-infer-v1", "X-OSV-Inference-Policy": strings.Repeat("a", 64)} {
		request.Header.Set(key, value)
	}
	response, err := inferenceRootHTTP(main, 2*time.Second).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || response.StatusCode != 503 || len(data) > 4096 {
		t.Fatal("outer policy refusal did not return its bounded error", response.StatusCode, err)
	}
	fixture, err := os.ReadFile("../../tests/fixtures/egress-outer-policy-rejection.json")
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected map[string]string
	if json.Unmarshal(data, &actual) != nil || json.Unmarshal(fixture, &expected) != nil || len(actual) != len(expected) {
		t.Fatal("actual error envelope differs from shared Python verifier fixture", string(data))
	}
	for key, value := range expected {
		if actual[key] != value {
			t.Fatal("actual error field differs from shared verifier fixture", key)
		}
	}
	bill, err := server.inference.ledger.boundTask(binding, true)
	if err != nil || len(bill.Invocations) != 0 || calls.Load() != 0 {
		t.Fatal("outer rejection started an invocation or reached the provider", err)
	}
}

func inferenceGuestExchange(t *testing.T, main, method, path string, data []byte, granted bool, spoof bool) (int, []byte) {
	t.Helper()
	binding := inferenceTestBinding()
	var grant []guestInferenceGrant
	if granted {
		grant = append(grant, inferenceGuestTestGrant(t, main, binding))
	}
	conn, reader, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID, grant...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request, _ := http.NewRequest(method, "http://"+inferenceGuestHost+path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if spoof {
		request.Header.Set("X-OSV-Task", "444444444444444444444444")
		request.Header.Set("X-OSV-Tenant", "tenant-b")
		request.Header.Set("X-OSV-VM", "444444444444444444444444")
		request.Header.Set("X-OSV-Lease", "444444444444444444444444")
		request.Header.Set("X-OSV-Inference", "remote-infer-v1")
		request.Header.Set("X-OSV-Inference-Policy", strings.Repeat("f", 64))
	}
	if err := request.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseData
}

// Fixture-only discovery: production root grants use their startup auth
// snapshot and must never adopt a restarted egress service's current policy.
func inferenceGuestTestGrant(t *testing.T, main string, binding inferenceBinding) guestInferenceGrant {
	t.Helper()
	state, err := NewEgressClient(main).inferenceState(context.Background(), "Bearer inference-test-token")
	if err != nil || !validSHA256Hex(state.PolicySHA256) {
		t.Fatal("fixture inference policy unavailable", err)
	}
	return guestInferenceGrant{Binding: binding, PolicySHA256: state.PolicySHA256}
}

func TestInferenceGuestUsesRootLogicalTaskAndRejectsOldGrant(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":42}`))
	}))
	t.Cleanup(provider.Close)
	s, root, main, _, _ := inferenceServiceFixture(t, provider.URL, func(n *EgressPolicy, _ *InferencePolicy) { n.MaxConcurrent = 1 })
	if _, err := root.task(context.Background(), "bind", inferenceTestBinding()); err != nil {
		t.Fatal(err)
	}
	data, _ := marshalInferenceJSON(inferenceRequest(1))
	status, response := inferenceGuestExchange(t, main, "POST", "/v1/invoke", data, false, true)
	if status != 403 || !bytes.Contains(response, []byte("inference_disabled")) || calls.Load() != 0 {
		t.Fatal("legacy outer grant gained inference from inner guest headers")
	}
	status, response = inferenceGuestExchange(t, main, "POST", "/v1/invoke", data, true, true)
	var result InferenceInvokeResult
	if status != 200 || decodeInferenceJSON(response, &result) != nil || result.Invocation.ID != inferenceRequest(1).ID || calls.Load() != 1 {
		t.Fatal("root-bound guest invocation failed", status)
	}
	status, response = inferenceGuestExchange(t, main, "GET", "/v1/bill", nil, true, true)
	var bill InferenceBill
	if status != 200 || decodeInferenceJSON(response, &bill) != nil || validateInferenceBill(bill, inferenceTestBinding()) != nil || len(bill.Invocations) != 1 || bill.SettledUnits == 0 {
		t.Fatal("guest selected a foreign task or lost its logical task bill", status)
	}
	if bill.TaskID == bill.VMID || bill.TaskID == bill.LeaseID || bill.Tenant != "tenant-a" {
		t.Fatal("physical/lease identity replaced root logical task")
	}
	status, response = inferenceGuestExchange(t, main, "GET", "/v1/policy", nil, true, false)
	if status != 200 || bytes.Contains(response, []byte(provider.URL)) || !bytes.Contains(response, []byte(`"name":"model"`)) {
		t.Fatal("guest discovery exposed an endpoint URL or omitted its alias")
	}
	// A complete response can reach the client before the handler's deferred
	// audit/slot release runs. Check bounded drain, not scheduler ordering.
	deadline := time.Now().Add(time.Second)
	for len(s.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.slots) != 0 {
		t.Fatal("guest inference leaked or double-acquired a network quota")
	}
}

func TestInferenceGuestRejectsBodyIdentityAndUnknownGrant(t *testing.T) {
	s, root, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	data, _ := marshalInferenceJSON(inferenceRequest(1))
	status, response := inferenceGuestExchange(t, main, "POST", "/v1/invoke", data, true, false)
	if status != 404 || !bytes.Contains(response, []byte("inference_not_found")) {
		t.Fatal("guest consumed a task that root never bound")
	}
	if _, err := root.task(context.Background(), "bind", inferenceTestBinding()); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"id":"000000000000000000000001","endpoint":"model","payload":{},"binding":{"tenant":"tenant-b"}}`)
	status, _ = inferenceGuestExchange(t, main, "POST", "/v1/invoke", request, true, false)
	if status != 400 {
		t.Fatal("guest supplied task binding in JSON")
	}
	bill, err := s.inference.ledger.boundTask(inferenceTestBinding(), true)
	if err != nil || len(bill.Invocations) != 0 {
		t.Fatal("denied guest request created consumption")
	}
}

func TestInferenceGuestEOFJoinsModelAndKeepsUnknownHold(t *testing.T) {
	arrived := make(chan struct{}, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(provider.Close)
	s, root, main, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	binding := inferenceTestBinding()
	if _, err := root.task(context.Background(), "bind", binding); err != nil {
		t.Fatal(err)
	}
	conn, _, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID, inferenceGuestTestGrant(t, main, binding))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, _ := marshalInferenceJSON(inferenceRequest(1))
	request, _ := http.NewRequest("POST", "http://"+inferenceGuestHost+"/v1/invoke", bytes.NewReader(data))
	if err := request.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("guest request did not reach provider")
	}
	_ = conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		bill, err := s.inference.ledger.boundTask(binding, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(bill.Invocations) == 1 && bill.Invocations[0].State == "uncertain" {
			if bill.HeldUnits == 0 || bill.SettledUnits != 0 {
				t.Fatal("guest EOF released unknown consumption")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guest EOF did not cancel and settle its outbound request")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInferenceGuestBillAndPolicyRemainAvailableWithFullModelQuota(t *testing.T) {
	arrived := make(chan struct{}, 1)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		calls.Add(1)
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(provider.Close)
	s, root, main, _, _ := inferenceServiceFixture(t, provider.URL, func(network *EgressPolicy, _ *InferencePolicy) {
		network.MaxConcurrent = 1
	})
	// Configure the global model lane before any consuming request; the root
	// readiness/bind channel is independent and has acquired no work slot.
	s.slots = make(chan struct{}, 1)
	binding := inferenceTestBinding()
	if _, err := root.task(context.Background(), "bind", binding); err != nil {
		t.Fatal(err)
	}
	conn, _, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID,
		inferenceGuestTestGrant(t, main, binding))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, _ := marshalInferenceJSON(inferenceRequest(1))
	request, _ := http.NewRequest("POST", "http://"+inferenceGuestHost+"/v1/invoke", bytes.NewReader(data))
	if err := request.WriteProxy(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("model was not dispatched")
	}
	status, response := inferenceGuestExchange(t, main, "GET", "/v1/bill", nil, true, false)
	var bill InferenceBill
	if status != 200 || decodeInferenceJSON(response, &bill) != nil || len(bill.Invocations) != 1 || bill.Invocations[0].State != "reserved" {
		t.Fatal("guest cannot observe its running model", status, string(response))
	}
	status, response = inferenceGuestExchange(t, main, "GET", "/v1/policy", nil, true, false)
	if status != 200 || !bytes.Contains(response, []byte(`"name":"model"`)) || len(s.slots) != 1 || calls.Load() != 1 {
		t.Fatal("observation consumed or released the model work slot", status)
	}
	busy, _ := marshalInferenceJSON(inferenceRequest(2))
	status, response = inferenceGuestExchange(t, main, "POST", "/v1/invoke", busy, true, false)
	if status != 429 || !bytes.Contains(response, []byte(`"code":"inference_busy"`)) || calls.Load() != 1 {
		t.Fatal("guest inference bypassed the full model quota", status, string(response))
	}
	ordinary, ordinaryReader, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID,
		inferenceGuestTestGrant(t, main, binding))
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	get, _ := http.NewRequest("GET", provider.URL, nil)
	if err := get.WriteProxy(ordinary); err != nil {
		t.Fatal(err)
	}
	ordinaryResponse, err := http.ReadResponse(ordinaryReader, get)
	if err != nil {
		t.Fatal(err)
	}
	_ = ordinaryResponse.Body.Close()
	if ordinaryResponse.StatusCode != 429 || calls.Load() != 1 {
		t.Fatal("v7 ordinary egress bypassed the full shared work quota")
	}
	_ = conn.Close()
	closed, err := root.task(context.Background(), "close", binding)
	if err != nil || !closed.Closed || len(closed.Invocations) != 1 || closed.Invocations[0].State != "uncertain" || closed.HeldUnits == 0 {
		t.Fatal("close lost the cancelled model hold", err)
	}
}

func TestInferenceGuestIngressLimitsKeepBoundedObservationLane(t *testing.T) {
	for _, limits := range []struct {
		name          string
		tenantMaximum int
		held          int
	}{
		{"tenant", 1, 5},
		{"global", 16, 17},
	} {
		t.Run(limits.name, func(t *testing.T) {
			s, root, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", func(network *EgressPolicy, _ *InferencePolicy) {
				network.MaxConcurrent = limits.tenantMaximum
			})
			s.slots = make(chan struct{}, 1)
			binding := inferenceTestBinding()
			if _, err := root.task(context.Background(), "bind", binding); err != nil {
				t.Fatal(err)
			}
			grant := inferenceGuestTestGrant(t, main, binding)
			var connections []io.Closer
			t.Cleanup(func() {
				for _, conn := range connections {
					_ = conn.Close()
				}
			})
			for n := 0; n < limits.held; n++ {
				conn, _, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID, grant)
				if err != nil {
					t.Fatal("bounded observation headroom rejected early", n, err)
				}
				// Leave the first inner header pending, as a slow guest could.
				connections = append(connections, conn)
			}
			conn, _, err := dialGuestProxyEgress(context.Background(), main, binding.Tenant, binding.VMID, binding.LeaseID, grant)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "egress_busy") || len(s.slots) != 0 {
				t.Fatal("slow headers exceeded the ingress bound or consumed model capacity", err)
			}
			for _, conn := range connections {
				_ = conn.Close()
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				s.proxyMu.Lock()
				remaining := s.proxyInferenceIngress
				s.proxyMu.Unlock()
				if remaining == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("closed slow headers retained ingress capacity", remaining)
				}
				time.Sleep(time.Millisecond)
			}
			status, _ := inferenceGuestExchange(t, main, "GET", "/v1/bill", nil, true, false)
			if status != 200 {
				t.Fatal("released observation lane was not reusable")
			}
		})
	}
}

func TestInferenceGuestLargeJSONDoesNotExpandHTML(t *testing.T) {
	data := []byte(`{"text":"` + strings.Repeat("<", egressResponseLimit-32) + `"}`)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(provider.Close)
	_, root, main, _, _ := inferenceServiceFixture(t, provider.URL, func(n *EgressPolicy, p *InferencePolicy) {
		n.MaxResponseBytes, n.TimeoutMS, p.BudgetUnits = egressResponseLimit, 5000, nil
	})
	if _, err := root.task(context.Background(), "bind", inferenceTestBinding()); err != nil {
		t.Fatal(err)
	}
	result, err := root.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	if err != nil || !bytes.Equal(result.Data, data) || result.Invocation.OutputBytes != uint64(len(data)) {
		t.Fatal("root response changed or expanded a bounded JSON body", err)
	}
	request, _ := marshalInferenceJSON(inferenceRequest(2))
	status, response := inferenceGuestExchange(t, main, "POST", "/v1/invoke", request, true, false)
	if status != 200 || len(response) > 1<<20 || json.Unmarshal(response, &result) != nil || !bytes.Equal(result.Data, data) {
		t.Fatal("guest JSON expansion exceeded its transport budget", status, len(response))
	}
}
