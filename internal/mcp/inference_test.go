package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func inferenceFixture(t *testing.T) (sandbox.SessionCapabilityReport, sandbox.InferenceInvokeResult, sandbox.InferenceBill) {
	t.Helper()
	data, err := os.ReadFile("../../tests/fixtures/inference-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Capabilities sandbox.SessionCapabilityReport `json:"capabilities"`
		Result       sandbox.InferenceInvokeResult   `json:"result"`
		Bill         sandbox.InferenceBill           `json:"bill"`
	}
	if json.Unmarshal(data, &fixture) != nil {
		t.Fatal("invalid shared SDK fixture")
	}
	fixture.Capabilities.Limits = testCapabilities().Limits
	return fixture.Capabilities, fixture.Result, fixture.Bill
}

func inferenceArgs(cap sandbox.SessionCapabilityReport, result sandbox.InferenceInvokeResult) json.RawMessage {
	return rawObject(map[string]any{"session_id": cap.SessionID, "invocation_id": result.Invocation.ID, "endpoint": "model", "payload": map[string]string{"query": "hi"}})
}

func TestInferenceToolDiscoveryAndHistorySurviveUnavailableAdmission(t *testing.T) {
	bound, _, _ := inferenceFixture(t)
	cap := bound.CapabilityReport
	if !inferenceCapable(cap) || len(inferenceToolsFor(cap)) != 2 {
		t.Fatal("missing valid inference tools")
	}
	for _, edit := range []func(*sandbox.CapabilityReport){
		func(c *sandbox.CapabilityReport) { c.ArtifactAuthenticated = false },
		func(c *sandbox.CapabilityReport) { c.ArtifactManifestProtocol = "osv-sandbox-artifacts/v6" },
		func(c *sandbox.CapabilityReport) { c.Features.RemoteInference = false },
		func(c *sandbox.CapabilityReport) { c.Features.NetworkEgress = false },
		func(c *sandbox.CapabilityReport) { c.RemoteInferencePolicy = nil },
	} {
		other := cap
		edit(&other)
		tools := inferenceToolsFor(other)
		if supported(tools, "sandbox.ml.invoke") || !supported(tools, "sandbox.ml.bill") {
			t.Fatal("disabled invocation or historical bill scope changed")
		}
	}
	catalog := &sandbox.TemplateCatalogReport{Templates: []sandbox.TemplateReport{{ID: "old", Available: false, Capabilities: cap}}}
	tools := toolsFor(sandbox.CapabilityReport{}, catalog)
	if !supported(tools, "sandbox.ml.invoke") || !supported(tools, "sandbox.ml.bill") || supported(tools, "sandbox.session.create") {
		t.Fatal("expired admission lost owner operations or admitted new sessions")
	}
	defaultCap := sandbox.CapabilityReport{Features: sandbox.CapabilityFeatures{InferenceBilling: true}}
	if !supported(toolsFor(defaultCap, &sandbox.TemplateCatalogReport{}), "sandbox.ml.bill") {
		t.Fatal("bill discovery depends on an available template")
	}
}

func TestInferenceToolMapsKnownIdentityAndKeepsExactBills(t *testing.T) {
	cap, result, bill := inferenceFixture(t)
	var calls []string
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("missing tenant authentication")
		}
		if r.URL.Path == "/v2/sessions/"+cap.SessionID+"/capabilities" {
			return reply(cap), nil
		}
		if r.URL.Path == "/v2/ml/bills/"+cap.SessionID {
			return reply(bill), nil
		}
		if r.Method != "POST" || r.GetBody != nil {
			t.Fatal("unexpected operation or replayable body")
		}
		var request sandbox.InferenceInvokeRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.ID != result.Invocation.ID || request.Endpoint != "model" || string(request.Payload) != `{"query":"hi"}` {
			t.Fatal("invocation payload or identity changed")
		}
		return reply(result), nil
	}))
	value := s.callTool(context.Background(), "sandbox.ml.invoke", inferenceArgs(cap, result), sandbox.CapabilityReport{})
	if value.IsError || value.Rollback != nil || !bytes.Contains(value.Data, []byte(`"settled_units":"9007199254741066"`)) {
		t.Fatal("valid inference lost amount or acquired a rollback", string(value.Data))
	}
	value = s.callTool(context.Background(), "sandbox.ml.bill", rawObject(map[string]string{"task_id": cap.SessionID}), sandbox.CapabilityReport{})
	if value.IsError || len(calls) != 3 || calls[2] != "GET /v2/ml/bills/"+cap.SessionID {
		t.Fatal("bill required active owner or new admission", string(value.Data), calls)
	}
}

func TestInferenceToolRejectsBadArgumentsBeforeAnyAPICall(t *testing.T) {
	cap, result, _ := inferenceFixture(t)
	s := codeServerForTest(roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input reached API"); return nil, nil }))
	for _, mutation := range []func(map[string]any){
		func(v map[string]any) { delete(v, "invocation_id") }, func(v map[string]any) { delete(v, "payload") },
		func(v map[string]any) { v["endpoint"] = "https://provider.invalid" }, func(v map[string]any) { v["tenant"] = "other" },
		func(v map[string]any) { v["timeout_ms"] = nil }, func(v map[string]any) { v["timeout_ms"] = 1.5 },
		func(v map[string]any) { v["timeout_ms"] = 30001 }, func(v map[string]any) { v["task_id"] = cap.SessionID },
	} {
		var request map[string]any
		_ = json.Unmarshal(inferenceArgs(cap, result), &request)
		mutation(request)
		if value := s.callTool(context.Background(), "sandbox.ml.invoke", rawObject(request), cap.CapabilityReport); !value.IsError {
			t.Fatal("invalid inference arguments accepted")
		}
	}
	if value := s.callTool(context.Background(), "sandbox.ml.bill", rawObject(map[string]string{"task_id": "bad"}), cap.CapabilityReport); !value.IsError {
		t.Fatal("invalid bill ID accepted")
	}
}

func TestInferenceToolLostOrMalformedResultsNeverReplayAndRetainKnownID(t *testing.T) {
	for _, kind := range []string{"lost", "owner", "meter", "unfinished", "status"} {
		t.Run(kind, func(t *testing.T) {
			cap, result, _ := inferenceFixture(t)
			var posts atomic.Int32
			s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					return reply(cap), nil
				}
				posts.Add(1)
				switch kind {
				case "lost":
					return nil, errors.New("lost-response-secret-must-not-appear")
				case "owner":
					result.TaskID = strings.Repeat("e", 24)
				case "meter":
					result.Invocation.SettledUnits = 0
				case "unfinished":
					result.Invocation.FinishedAt = nil
				case "status":
					result.Invocation.HTTPStatus = 500
				}
				return reply(result), nil
			}))
			value := s.callTool(context.Background(), "sandbox.ml.invoke", inferenceArgs(cap, result), cap.CapabilityReport)
			if !value.IsError || value.Rollback != nil || posts.Load() != 1 || !bytes.Contains(value.Data, []byte(result.Invocation.ID)) ||
				!bytes.Contains(value.Data, []byte(`"delivery_unknown":true`)) || bytes.Contains(value.Data, []byte("must-not-appear")) {
				t.Fatal("uncertain result replayed, lost ID or leaked diagnostics", string(value.Data))
			}
		})
	}
}

func TestInferenceToolCancellationAndBillDoNotDependOnDiscovery(t *testing.T) {
	cap, result, bill := inferenceFixture(t)
	entered := make(chan struct{})
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v2/sessions/" + cap.SessionID + "/capabilities":
			return reply(cap), nil
		case "/v2/ml/bills/" + cap.SessionID:
			return reply(bill), nil
		case "/v2/sessions/" + cap.SessionID + "/ml/invocations":
			close(entered)
			<-r.Context().Done()
			return nil, r.Context().Err()
		default:
			t.Error("tool queried unavailable admission", r.URL.Path)
			return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"unavailable"}`))}, nil
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan outcome, 1)
	go func() {
		done <- s.callTool(ctx, "sandbox.ml.invoke", inferenceArgs(cap, result), sandbox.CapabilityReport{})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("model request did not start")
	}
	cancel()
	select {
	case value := <-done:
		if !value.IsError || !bytes.Contains(value.Data, []byte(`"delivery_unknown":true`)) {
			t.Fatal("cancelled call lost uncertainty", string(value.Data))
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt transport")
	}
	// Exercise actual MCP dispatch: its discovery call would fail above.
	h := harness(t, s)
	h.send(modern(1, "tools/call", map[string]any{"name": "sandbox.ml.bill", "arguments": map[string]string{"task_id": cap.SessionID}}))
	response := h.receive()
	if response["error"] != nil || !strings.Contains(string(rawObject(response)), `9007199254741066`) {
		t.Fatal("wire dispatch depended on discovery", response)
	}
	if err := h.close(); err != nil {
		t.Fatal(err)
	}
}
