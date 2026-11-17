package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// This checks the real writer, including the correlation field that must survive
// a failed/uncertain invocation. The optional output captures actual bytes for
// independent offline schema validation; no model request or VM is started.
func TestRESTWireContractInferenceErrorPreservesInvocation(t *testing.T) {
	var samples []json.RawMessage
	for _, id := range []string{"", strings.Repeat("a", 24)} {
		w := httptest.NewRecorder()
		writeAPIInferenceError(w, inferenceError(502, "inference_upstream"), id)
		var object map[string]any
		if w.Code != 502 || json.Unmarshal(w.Body.Bytes(), &object) != nil || object["code"] != "inference_upstream" || object["error"] == "" {
			t.Fatalf("inference error changed: %d %s", w.Code, w.Body.String())
		}
		if id != "" && object["invocation_id"] != id || id == "" && len(object) != 2 {
			t.Fatalf("invocation correlation changed: %s", w.Body.String())
		}
		samples = append(samples, append(json.RawMessage(nil), w.Body.Bytes()...))
	}
	if output := os.Getenv("OSV_REST_WIRE_SAMPLES"); output != "" {
		data, err := json.Marshal(samples)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRESTWireContractActualHTTPResponsesAndAllRouteErrors(t *testing.T) {
	document, err := os.ReadFile("../../api/contracts/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			ID string `json:"operationId"`
		} `json:"paths"`
	}
	if json.Unmarshal(document, &contract) != nil {
		t.Fatal("invalid canonical OpenAPI")
	}
	operationID := func(pattern string) string {
		method, path, _ := strings.Cut(pattern, " ")
		value := contract.Paths[path][strings.ToLower(method)].ID
		if value == "" {
			t.Fatalf("actual route missing from contract: %s", pattern)
		}
		return value
	}
	h := newAPIWithEgress(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	var samples []map[string]any
	call := func(pattern, method, path, body string, validateRequest bool) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		value := any(w.Body.String())
		mediaType := strings.Split(w.Header().Get("Content-Type"), ";")[0]
		if mediaType == "application/json" {
			if json.Unmarshal(w.Body.Bytes(), &value) != nil {
				t.Fatalf("invalid actual JSON response for %s", pattern)
			}
		}
		sample := map[string]any{"operation_id": operationID(pattern), "status": w.Code, "response": value, "media_type": mediaType}
		if validateRequest {
			var request any
			if json.Unmarshal([]byte(body), &request) != nil {
				t.Fatal("invalid request fixture")
			}
			sample["validate_request"], sample["request"] = true, request
		}
		samples = append(samples, sample)
	}
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	for pattern := range h.api.routes {
		_, path, _ := strings.Cut(pattern, " ")
		path = wildcard.ReplaceAllString(path, strings.Repeat("a", 24))
		call(pattern, "PUT", path, "", false)
	}
	for _, pattern := range []string{"GET /healthz", "GET /readyz", "GET /metrics", "GET /v1/doctor", "GET /v1/capabilities", "GET /v2/templates", "GET /v2/sessions"} {
		method, path, _ := strings.Cut(pattern, " ")
		call(pattern, method, path, "", false)
	}
	call("POST /v1/jobs", "POST", "/v1/jobs", `{"entrypoint":"/bin/echo"}`, true)
	call("POST /v2/jobs", "POST", "/v2/jobs", `{"entrypoint":"/bin/echo","backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("b", 64)+`","memory_mib":null,"timeout_ms":0,"stdin":null}`, true)
	call("POST /v2/sessions/{id}/ml/invocations", "POST", "/v2/sessions/"+strings.Repeat("a", 24)+"/ml/invocations", `{}`, false)
	call("GET /v2/ml/bills/{task}", "GET", "/v2/ml/bills/"+strings.Repeat("a", 24), "", false)
	data, err := json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-B", "../../scripts/check-api-contract.py", "--exchanges", "-")
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual handler/contract mismatch: %v: %s", err, output)
	}
	if path := os.Getenv("OSV_REST_CONTRACT_HTTP_SAMPLES"); path != "" {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("validated %d actual HTTP handler exchanges, including every registered route method rejection", len(samples))
}
