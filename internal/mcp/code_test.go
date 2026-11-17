package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var codeSID = strings.Repeat("1", 24)
var codeCID = strings.Repeat("2", 24)
var codeEID = strings.Repeat("3", 24)

func codeCapabilityForTest() sandbox.CapabilityReport {
	cap := testCapabilities()
	cap.ArtifactManifestProtocol = "osv-sandbox-artifacts/v5"
	cap.Features.CodeContexts = true
	cap.CodeLanguages = []string{"python", "javascript", "typescript"}
	cap.CodeRuntime = &sandbox.SignedCodeRuntime{Architecture: "amd64", KernelProtocol: "osv-code-kernel/v2", PythonVersion: "3.12.16", NodeVersion: "22.23.4", TypeScriptVersion: "5.9.3", PrewarmLanguage: "python",
		RuntimeInventorySHA256: strings.Repeat("a", 64), KernelScriptsSHA256: map[string]string{"python.py": strings.Repeat("b", 64), "node.cjs": strings.Repeat("c", 64)}, MinimumCPUFeatures: []string{"sse4_1"}}
	return cap
}
func codeContextForTest() sandbox.CodeContext {
	pid := uint32(42)
	return sandbox.CodeContext{SessionID: codeSID, ID: codeCID, Generation: 1, Language: "python", Cwd: "/workspace", State: "idle", PID: &pid}
}
func codePageForTest() sandbox.CodeExecutionPage {
	usable, main := true, true
	return sandbox.CodeExecutionPage{SessionID: codeSID, ID: codeEID, ContextID: codeCID, Generation: 1, Language: "python", Status: "completed", LastSequence: 3, NextSequence: 3,
		Events: []sandbox.CodeSequencedEvent{{Sequence: 1, Event: sandbox.CodeEvent{Type: "started"}},
			{Sequence: 2, Event: sandbox.CodeEvent{Type: "result", Data: json.RawMessage(`{"application/json":{"integer":9007199254740993},"text/plain":"42"}`), IsMainResult: &main}},
			{Sequence: 3, Event: sandbox.CodeEvent{Type: "finished", Status: "completed", ContextUsable: &usable}}}}
}
func codeServerForTest(handler roundTrip) *Server {
	return newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: handler}}, 4)
}

func TestCodeToolDiscoveryGatesRuntimePolicyAndUnavailableNewAdmission(t *testing.T) {
	cap := codeCapabilityForTest()
	if len(codeToolsFor(cap)) != 9 {
		t.Fatal("missing code tools")
	}
	for _, edit := range []func(*sandbox.CapabilityReport){
		func(c *sandbox.CapabilityReport) { c.ArtifactAuthenticated = false }, func(c *sandbox.CapabilityReport) { c.ArtifactManifestProtocol = "osv-sandbox-artifacts/v4" },
		func(c *sandbox.CapabilityReport) { c.Features.CodeContexts = false }, func(c *sandbox.CapabilityReport) { c.Backend = "firecracker-osv" }, func(c *sandbox.CapabilityReport) { c.CodeRuntime = nil }} {
		copy := cap
		edit(&copy)
		if len(codeToolsFor(copy)) != 0 {
			t.Fatal("unsupported code runtime published")
		}
	}
	cap.CodeLanguages = []string{}
	tools := codeToolsFor(cap)
	if len(tools) != 5 || supported(tools, "sandbox.code.execute") || !supported(tools, "sandbox.code.cancel") {
		t.Fatal("language revocation blocked observation or allowed admission", tools)
	}
	for _, definition := range tools {
		if definition.Name == "sandbox.code.poll" && !definition.Annotations["readOnlyHint"] {
			t.Fatal("code polling wrongly acknowledges output")
		}
	}
	cap = codeCapabilityForTest()
	catalog := &sandbox.TemplateCatalogReport{Templates: []sandbox.TemplateReport{{ID: "code", Available: false, Capabilities: cap}}}
	tools = toolsFor(sandbox.CapabilityReport{}, catalog)
	if !supported(tools, "sandbox.code.cancel") || !supported(tools, "sandbox.code.execute") || !supported(tools, "sandbox.session.close") || supported(tools, "sandbox.session.create") || supported(tools, "sandbox.exec") {
		t.Fatal("expired new admission lost existing code or allowed new VM")
	}
}

func TestCodeToolsMapAllNineOperationsAndKeepKnownIdentities(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("authentication omitted")
		}
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/v2/sessions/"+codeSID+"/capabilities" {
			return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: codeCapabilityForTest()}), nil
		}
		if r.URL.Path == "/v1/capabilities" {
			t.Fatal("code queried new admission instead of owner")
		}
		body := map[string]any{}
		if r.Body != nil {
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("bad code request body")
			}
			bodies = append(bodies, body)
		}
		if body["session_id"] != nil || body["operation"] != nil {
			t.Error("control metadata leaked into HTTP body", body)
		}
		switch {
		case r.URL.Path == "/v2/sessions/"+codeSID+"/contexts" && r.Method == "GET":
			return reply(map[string]any{"session_id": codeSID, "contexts": []sandbox.CodeContext{codeContextForTest()}}), nil
		case strings.Contains(r.URL.Path, "/code-executions/") && r.Method == "GET":
			return reply(codePageForTest()), nil
		case strings.HasSuffix(r.URL.Path, "/code-executions") || strings.Contains(r.URL.Path, "/code-executions/"):
			return reply(map[string]any{"session_id": codeSID, "execution_id": codeEID, "accepted": true}), nil
		case r.Method == "DELETE":
			return reply(map[string]any{"session_id": codeSID, "context_id": codeCID, "removed": true}), nil
		default:
			return reply(codeContextForTest()), nil
		}
	}))
	base := map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID}
	for _, row := range []struct {
		name string
		args map[string]any
		last string
	}{
		{"context.create", map[string]any{"session_id": codeSID, "context_id": codeCID, "language": "python"}, "POST /v2/sessions/" + codeSID + "/contexts"},
		{"context.default", map[string]any{"session_id": codeSID, "language": "python"}, "POST /v2/sessions/" + codeSID + "/contexts/default"},
		{"context.list", map[string]any{"session_id": codeSID}, "GET /v2/sessions/" + codeSID + "/contexts"},
		{"context.info", map[string]any{"session_id": codeSID, "context_id": codeCID}, "GET /v2/sessions/" + codeSID + "/contexts/" + codeCID},
		{"context.restart", map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1}, "POST /v2/sessions/" + codeSID + "/contexts/" + codeCID + "/restart"},
		{"context.remove", map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1}, "DELETE /v2/sessions/" + codeSID + "/contexts/" + codeCID + "?generation=1"},
		{"execute", map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID, "code": ""}, "POST /v2/sessions/" + codeSID + "/code-executions"},
		{"poll", base, "GET /v2/sessions/" + codeSID + "/code-executions/" + codeEID + "?after=0"},
		{"cancel", base, "DELETE /v2/sessions/" + codeSID + "/code-executions/" + codeEID + "?context_id=" + codeCID + "&generation=1"},
	} {
		before := len(calls)
		result := s.callTool(context.Background(), "sandbox.code."+row.name, rawObject(row.args), testCapabilities())
		if result.IsError || result.Rollback != nil || calls[before] != "GET /v2/sessions/"+codeSID+"/capabilities" || calls[len(calls)-1] != row.last {
			t.Fatal(row.name, calls, string(result.Data))
		}
		if row.name == "poll" {
			data, _ := json.Marshal(callResult(result))
			if !bytes.Contains(data, []byte("9007199254740993")) {
				t.Fatal("rich JSON was rounded", string(data))
			}
		}
	}
	var execute map[string]any
	for _, body := range bodies {
		if _, ok := body["code"]; ok {
			execute = body
		}
	}
	if execute["code"] != "" || execute["timeout_ms"] != float64(60000) || execute["environment"] == nil {
		t.Fatal("required empty/default fields lost", execute)
	}
}

func TestCodeToolInputValidationPrecedesEveryAPICall(t *testing.T) {
	s := codeServerForTest(roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input reached API"); return nil, nil }))
	for _, test := range []struct{ name, args string }{
		{"context.create", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","language":"ruby"}`},
		{"context.create", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","language":"python","cwd":"/tmp"}`},
		{"context.list", `{"session_id":"111111111111111111111111","operation":"execute"}`},
		{"context.info", `{"session_id":"../host","context_id":"222222222222222222222222"}`},
		{"execute", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","execution_id":"333333333333333333333333","generation":0,"code":""}`},
		{"execute", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","execution_id":"333333333333333333333333","generation":1,"code":"","environment":null}`},
		{"poll", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","execution_id":"333333333333333333333333","generation":1,"after":257}`},
		{"cancel", `{"session_id":"111111111111111111111111","context_id":"222222222222222222222222","execution_id":"333333333333333333333333","generation":1,"code":"unexpected"}`},
	} {
		if got := s.callTool(context.Background(), "sandbox.code."+test.name, json.RawMessage(test.args), codeCapabilityForTest()); !got.IsError {
			t.Fatal("invalid input accepted", test)
		}
	}
}

func TestCodeToolOwnerBindingAndCurrentLanguagePolicyAreAuthoritative(t *testing.T) {
	for _, mode := range []string{"foreign", "old", "language", "zero-languages"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/capabilities") {
					cap := codeCapabilityForTest()
					sid := codeSID
					if mode == "foreign" {
						sid = strings.Repeat("4", 24)
					}
					if mode == "old" {
						cap.ArtifactManifestProtocol = "osv-sandbox-artifacts/v4"
					}
					if mode == "language" {
						cap.CodeLanguages = []string{"javascript"}
					}
					if mode == "zero-languages" {
						cap.CodeLanguages = []string{}
					}
					return reply(sandbox.SessionCapabilityReport{SessionID: sid, CapabilityReport: cap}), nil
				}
				if r.Method == "GET" {
					return reply(codeContextForTest()), nil
				}
				writes.Add(1)
				return reply(map[string]any{}), nil
			}))
			args := rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID, "code": "do_not_run()"})
			got := s.callTool(context.Background(), "sandbox.code.execute", args, codeCapabilityForTest())
			if !got.IsError || writes.Load() != 0 {
				t.Fatal(mode, string(got.Data), writes.Load())
			}
		})
	}
}

func TestCodeToolUncertainWritesRetainIDsWithoutRollbackOrDiagnosticLeaks(t *testing.T) {
	for _, mode := range []string{"transport", "api503", "rejected", "bad-ack"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/capabilities") {
					return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: codeCapabilityForTest()}), nil
				}
				if r.Method == "GET" {
					return reply(codeContextForTest()), nil
				}
				writes.Add(1)
				switch mode {
				case "transport":
					return nil, errors.New("secret transport diagnostic")
				case "api503", "rejected":
					status := 503
					if mode == "rejected" {
						status = 409
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"code":"unavailable","error":"test-secret body diagnostic"}`)), Header: make(http.Header)}, nil
				default:
					return reply(map[string]any{"session_id": strings.Repeat("4", 24), "execution_id": codeEID, "accepted": true}), nil
				}
			}))
			got := s.callTool(context.Background(), "sandbox.code.execute", rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID, "code": "secret_source()", "environment": map[string]string{"TOKEN": "secret-value"}}), codeCapabilityForTest())
			var result struct {
				SessionID       string `json:"session_id"`
				ExecutionID     string `json:"execution_id"`
				DeliveryUnknown bool   `json:"delivery_unknown"`
			}
			if !got.IsError || got.Rollback != nil || json.Unmarshal(got.Data, &result) != nil || result.SessionID != codeSID || result.ExecutionID != codeEID || result.DeliveryUnknown != (mode != "rejected") || writes.Load() != 1 {
				t.Fatal(mode, string(got.Data), writes.Load())
			}
			for _, secret := range []string{"secret_source", "secret-value", "test-secret", "body diagnostic", "transport diagnostic"} {
				if bytes.Contains(got.Data, []byte(secret)) {
					t.Fatal("diagnostic/source leaked", string(got.Data))
				}
			}
		})
	}
}

func TestCodeToolPollRejectsMisboundAndMalformedPages(t *testing.T) {
	for _, edit := range []func(*sandbox.CodeExecutionPage){
		func(p *sandbox.CodeExecutionPage) { p.SessionID = strings.Repeat("4", 24) }, func(p *sandbox.CodeExecutionPage) { p.ContextID = strings.Repeat("4", 24) },
		func(p *sandbox.CodeExecutionPage) { p.Generation = 2 }, func(p *sandbox.CodeExecutionPage) { p.Events[0].Sequence = 2 },
		func(p *sandbox.CodeExecutionPage) { p.NextSequence = 2 }, func(p *sandbox.CodeExecutionPage) { p.Language = "ruby" },
	} {
		page := codePageForTest()
		edit(&page)
		s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/capabilities") {
				return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: codeCapabilityForTest()}), nil
			}
			return reply(page), nil
		}))
		got := s.callTool(context.Background(), "sandbox.code.poll", rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID}), codeCapabilityForTest())
		if !got.IsError {
			t.Fatal("malformed page accepted", string(got.Data))
		}
	}
}

func TestCodeToolCancellationAndPollingUseIndependentBoundedContexts(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/capabilities") {
			return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: codeCapabilityForTest()}), nil
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("unbounded code HTTP")
		}
		close(entered)
		<-r.Context().Done()
		close(stopped)
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan outcome, 1)
	go func() {
		done <- s.callTool(ctx, "sandbox.code.cancel", rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID}), codeCapabilityForTest())
	}()
	<-entered
	cancel()
	select {
	case result := <-done:
		if !result.IsError || result.Rollback != nil {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		t.Fatal("MCP cancellation did not release code RPC")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("HTTP reader retained cancelled request")
	}
}

func TestCodeToolReadAndCleanupSurviveLanguageRevocationAndRemovedContext(t *testing.T) {
	cap := codeCapabilityForTest()
	cap.CodeLanguages = []string{}
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/capabilities") {
			return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: cap}), nil
		}
		if strings.Contains(r.URL.Path, "/contexts/") && r.Method == "GET" {
			t.Fatal("journal depended on a removed context")
		}
		if r.Method == "GET" {
			return reply(codePageForTest()), nil
		}
		if strings.Contains(r.URL.Path, "/code-executions/") {
			return reply(map[string]any{"session_id": codeSID, "execution_id": codeEID, "accepted": true}), nil
		}
		return reply(map[string]any{"session_id": codeSID, "context_id": codeCID, "removed": true}), nil
	}))
	args := rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID})
	for _, name := range []string{"sandbox.code.poll", "sandbox.code.cancel"} {
		if result := s.callTool(context.Background(), name, args, cap); result.IsError {
			t.Fatal(name, string(result.Data))
		}
	}
	if result := s.callTool(context.Background(), "sandbox.code.context.remove", rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1}), cap); result.IsError {
		t.Fatal(string(result.Data))
	}
}

func TestCodeToolPagesSurfaceUserErrorsFailureAndEvictionWithoutLosingData(t *testing.T) {
	for _, mode := range []string{"error", "failed", "cancelled", "timed_out", "evicted", "preempted"} {
		page := codePageForTest()
		switch mode {
		case "error":
			page.Events[1].Event = sandbox.CodeEvent{Type: "error", Name: "Error", Value: "", Traceback: ""}
		case "evicted":
			page.Events = []sandbox.CodeSequencedEvent{}
			page.NextSequence = 0
			page.EventsEvicted = true
		case "preempted":
			usable := true
			failure := "cancelled_before_submit"
			page.Failure = &failure
			page.Status = "cancelled"
			page.Events = []sandbox.CodeSequencedEvent{{Sequence: 1, Event: sandbox.CodeEvent{Type: "finished", Status: "cancelled", ContextUsable: &usable}}}
			page.LastSequence, page.NextSequence = 1, 1
		default:
			page.Status = mode
			page.Events[2].Event.Status = mode
		}
		s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/capabilities") {
				return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: codeCapabilityForTest()}), nil
			}
			return reply(page), nil
		}))
		result := s.callTool(context.Background(), "sandbox.code.poll", rawObject(map[string]any{"session_id": codeSID, "context_id": codeCID, "generation": 1, "execution_id": codeEID}), codeCapabilityForTest())
		if !result.IsError || bytes.Contains(result.Data, []byte(`"delivery_unknown"`)) || !bytes.Contains(result.Data, []byte(`"events"`)) {
			t.Fatal("execution error data was hidden/reclassified", mode, string(result.Data))
		}
	}
}

func TestCodeToolDiscoveryMergesLanguageEnumsAndBoundCapabilitiesIgnoreDefault(t *testing.T) {
	one, two := codeCapabilityForTest(), codeCapabilityForTest()
	one.CodeLanguages = []string{"python"}
	two.CodeLanguages = []string{"typescript"}
	two.ArtifactManifestSHA256 = strings.Repeat("b", 64)
	catalog := &sandbox.TemplateCatalogReport{Templates: []sandbox.TemplateReport{{ID: "one", Available: true, Capabilities: one}, {ID: "two", Available: false, Capabilities: two}}}
	for _, definition := range toolsFor(testCapabilities(), catalog) {
		if definition.Name == "sandbox.code.context.create" {
			properties := definition.InputSchema["properties"].(map[string]any)
			values := schemaStrings(properties["language"].(map[string]any))
			if !contains(values, "python") || !contains(values, "typescript") {
				t.Fatal(values)
			}
		}
	}
	s := codeServerForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v2/sessions/"+codeSID+"/capabilities" {
			t.Fatal("owner lookup selected new/default template", r.URL.Path)
		}
		return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: two}), nil
	}))
	result := s.callTool(context.Background(), "sandbox.capabilities", rawObject(map[string]any{"session_id": codeSID}), testCapabilities(), catalog)
	if result.IsError || !bytes.Contains(result.Data, []byte(two.ArtifactManifestSHA256)) {
		t.Fatal(string(result.Data))
	}
	if invalid := s.callTool(context.Background(), "sandbox.capabilities", rawObject(map[string]any{"session_id": codeSID, "backend": "firecracker-linux"}), one, catalog); !invalid.IsError {
		t.Fatal("contradictory owner+template selector accepted")
	}
}
