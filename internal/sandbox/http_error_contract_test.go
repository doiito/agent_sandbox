package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func errorContractAPI(calls *atomic.Int32) *apiHTTPHandler {
	runner := &telemetryTestRunner{run: func(_ context.Context, _ RunRequest) (RunResult, error) {
		calls.Add(1)
		return RunResult{}, nil
	}}
	return newAPIWithEgress(runner, NewSingleTokenAuthenticator("contract-token"), slog.New(slog.NewTextHandler(io.Discard, nil)), "")
}

func errorContractRequest(handler http.Handler, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("private-body-sentinel"))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func checkErrorEnvelope(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("error wire mismatch: status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatalf("error response is not JSON: %v", err)
	}
	message, ok := value["error"].(string)
	if !ok || message == "" {
		t.Fatalf("error explanation absent: %v", value)
	}
	if code == "" {
		if len(value) != 1 {
			t.Fatalf("legacy envelope changed: %v", value)
		}
	} else if len(value) != 2 || value["code"] != code {
		t.Fatalf("versioned envelope mismatch: %v; want code %s", value, code)
	}
	for _, secret := range []string{"private-path-sentinel", "private-query-sentinel", "private-body-sentinel", "contract-token"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("routing error reflected private input %q", secret)
		}
	}
}

func TestHTTPErrorContractEveryRegisteredRoutePreservesMethodAllow(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	reference := http.NewServeMux()
	for pattern := range handler.api.routes {
		reference.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {
			t.Error("unsupported method reached a registered handler")
		})
	}
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	for pattern := range handler.api.routes {
		_, path, _ := strings.Cut(pattern, " ")
		path = wildcard.ReplaceAllString(path, "identifier")
		t.Run(pattern, func(t *testing.T) {
			want := errorContractRequest(reference, "PUT", path, "")
			if want.Code != 405 || want.Header().Get("Allow") == "" {
				t.Fatalf("invalid route fixture: %d %v", want.Code, want.Header())
			}
			got := errorContractRequest(handler, "PUT", path, "contract-token")
			code := ""
			if strings.HasPrefix(path, "/v2/") {
				code = "method_not_allowed"
			}
			checkErrorEnvelope(t, got, 405, code)
			if got.Header().Get("Allow") != want.Header().Get("Allow") {
				t.Fatalf("Allow changed: got %q want %q", got.Header().Get("Allow"), want.Header().Get("Allow"))
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("routing rejection executed a task")
	}
}

func TestHTTPErrorContractAuthenticationPrecedesRouteClassification(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	for _, path := range []string{"/v2/jobs", "/v2/private-path-sentinel", "/v2"} {
		for _, token := range []string{"", "wrong-token"} {
			t.Run(path+"/"+token, func(t *testing.T) {
				w := errorContractRequest(handler, "PUT", path, token)
				checkErrorEnvelope(t, w, 401, "unauthorized")
				if w.Header().Get("Allow") != "" {
					t.Fatal("unauthenticated request exposed method discovery")
				}
			})
		}
	}
	handler.api.auth = nil
	w := errorContractRequest(handler, "PUT", "/v2/private-path-sentinel", "contract-token")
	checkErrorEnvelope(t, w, 503, "unavailable")
	if calls.Load() != 0 {
		t.Fatal("failed authentication reached runner")
	}
}

func TestHTTPErrorContractVersionBoundaryAndRoutingPrivacy(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	for _, path := range []string{"/v2", "/v2/", "/v2/private-path-sentinel?secret=private-query-sentinel", "/v2/%2Fprivate-path-sentinel"} {
		t.Run(path, func(t *testing.T) {
			checkErrorEnvelope(t, errorContractRequest(handler, "GET", path, "contract-token"), 404, "not_found")
		})
	}
	for _, path := range []string{"/v1/private-path-sentinel", "/v20", "/private-path-sentinel"} {
		t.Run(path, func(t *testing.T) {
			checkErrorEnvelope(t, errorContractRequest(handler, "GET", path, "contract-token"), 404, "")
		})
	}
	if calls.Load() != 0 {
		t.Fatal("unknown route reached runner")
	}
}

func TestHTTPErrorContractPreservesRedirectsConnectAndBusinessWildcards(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	for _, path := range []string{"/v2/sessions//identifier", "/v2/unknown//leaf?secret=keep-query"} {
		got := errorContractRequest(handler, "GET", path, "contract-token")
		if got.Code != 301 || got.Header().Get("Location") != strings.ReplaceAll(path, "//", "/") {
			t.Fatalf("canonical redirect changed: %d %v", got.Code, got.Header())
		}
	}
	checkErrorEnvelope(t, errorContractRequest(handler, "CONNECT", "/v2/unknown//leaf", "contract-token"), 404, "not_found")
	w := errorContractRequest(handler, "GET", "/v2/sessions/encoded%2Fidentifier", "contract-token")
	checkErrorEnvelope(t, w, 404, "not_found")
	if !strings.Contains(w.Body.String(), "session not found") {
		t.Fatal("registered wildcard route was replaced by generated routing error")
	}
	// This route shares its path with POST; GET is valid and must reach the
	// application's absent-owner error, not the framework's method error.
	w = errorContractRequest(handler, "GET", "/v2/sessions", "contract-token")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sessions":[]`) {
		t.Fatalf("registered GET route changed: %d %s", w.Code, w.Body.String())
	}
}

func TestHTTPErrorContractMTLSHTTP1AndHTTP2Wire(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	serverTLS, clientTLS := portTLSFixture(t)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	for _, h2 := range []bool{false, true} {
		name := "http1"
		wantProto := 1
		if h2 {
			name, wantProto = "http2", 2
		}
		t.Run(name, func(t *testing.T) {
			config := clientTLS.Clone()
			config.NextProtos = nil
			transport := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: h2}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			for _, row := range []struct {
				method, path, code string
				status             int
			}{
				{"GET", "/v2/private-path-sentinel?secret=private-query-sentinel", "not_found", 404},
				{"OPTIONS", "/v2/jobs", "method_not_allowed", 405},
				{"HEAD", "/v2/private-path-sentinel", "", 404},
				{"HEAD", "/healthz", "", 200},
			} {
				r, _ := http.NewRequest(row.method, server.URL+row.path, nil)
				r.Header.Set("Authorization", "Bearer contract-token")
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != row.status || response.ProtoMajor != wantProto {
					t.Fatalf("wire response mismatch: status=%d proto=%s err=%v", response.StatusCode, response.Proto, err)
				}
				if row.method == "HEAD" {
					if len(data) != 0 {
						t.Fatal("HEAD returned body bytes on wire")
					}
					continue
				}
				w := httptest.NewRecorder()
				w.Code, w.Body = response.StatusCode, bytes.NewBuffer(data)
				for key, values := range response.Header {
					w.Header()[key] = values
				}
				checkErrorEnvelope(t, w, row.status, row.code)
				if row.status == 405 && response.Header.Get("Allow") != "POST" {
					t.Fatal("wire response lost Allow")
				}
			}
		})
	}
	config := clientTLS.Clone()
	config.Certificates = nil
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	if response, err := client.Get(server.URL + "/v2/unknown"); err == nil {
		_ = response.Body.Close()
		t.Fatal("client without mutual TLS reached application routing")
	}
	if calls.Load() != 0 {
		t.Fatal("wire routing error reached backend")
	}
}

func TestHTTPErrorContractActualResponsesMatchOfflineSchema(t *testing.T) {
	var calls atomic.Int32
	handler := errorContractAPI(&calls)
	var responses []json.RawMessage
	for _, row := range []struct{ method, path, token string }{
		{"GET", "/v2/unknown", "contract-token"},
		{"GET", "/v2/jobs", "contract-token"},
		{"GET", "/v2/unknown", ""},
		{"POST", "/v2/jobs", "contract-token"},
		{"GET", "/v2/sessions/absent", "contract-token"},
	} {
		w := errorContractRequest(handler, row.method, row.path, row.token)
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("actual response cannot be validated as JSON: %s", w.Body.String())
		}
		responses = append(responses, append(json.RawMessage(nil), w.Body.Bytes()...))
	}
	data, err := json.Marshal(responses)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := filepath.Abs("../../docs/contracts/http-errors-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the fixed validation dependencies already present for release
	// SBOM checks. No schema reference may retrieve from the network.
	script := `import json,socket,sys
from jsonschema import Draft202012Validator
from referencing import Registry
from referencing.exceptions import NoSuchResource
def forbidden(*args,**kwargs): raise AssertionError('network retrieval forbidden')
def missing(uri): raise NoSuchResource(ref=uri)
socket.create_connection=forbidden
schema=json.load(open(sys.argv[1]))
Draft202012Validator.check_schema(schema)
v=Draft202012Validator(schema,registry=Registry(retrieve=missing))
actual=json.load(sys.stdin)
for item in actual: v.validate(item)
v.validate({'code':'future_new_code','error':'future explanation'})
for item in [{},{'code':'only'},{'error':'only'},{'code':'','error':'empty code'},{'code':4,'error':'wrong type'},{'code':'bad','error':False},{'code':'bad','error':'extra','detail':'private'}]:
 if v.is_valid(item): raise AssertionError('invalid envelope accepted: '+repr(item))
print('validated '+str(len(actual))+' actual responses and seven negative cases without network')
`
	command := exec.Command("python3", "-B", "-c", script, schema)
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("offline contract validation failed: %v: %s", err, output)
	}
}

func TestHTTPErrorContractRoutingOTLPStatusesAreFailuresWithoutRawURL(t *testing.T) {
	capture := &telemetryCapture{bodies: make(map[string][][]byte)}
	collector := httptest.NewServer(http.HandlerFunc(capture.serve))
	defer collector.Close()
	config := apiTelemetryConfig(collector.URL)
	config.Signals = []string{"logs", "traces"}
	h, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, NewSingleTokenAuthenticator("contract-token"),
		slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	defer closeAPITelemetry(t, handler)
	for _, row := range []struct{ method, path string }{
		{"GET", "/v2/private-path-sentinel?secret=private-query-sentinel"},
		{"PATCH", "/v2/jobs?secret=private-query-sentinel"},
	} {
		errorContractRequest(handler, row.method, row.path, "contract-token")
	}
	if err := closeAPITelemetry(t, handler); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	logs := telemetryRows(t, capture.bodies["/v1/logs"], "logs")
	spans := telemetryRows(t, capture.bodies["/v1/traces"], "traces")
	if len(logs) != 2 || len(spans) != 2 {
		t.Fatalf("routing event count mismatch: logs=%d spans=%d", len(logs), len(spans))
	}
	for i, status := range []string{"404", "405"} {
		for _, row := range []map[string]any{logs[i], spans[i]} {
			tags := telemetryTags(row)
			if tags["http.response.status_code"] != status || tags["http.route"] != "unmatched" {
				t.Fatalf("routing status/route missing: %v", tags)
			}
		}
		if spans[i]["status"].(map[string]any)["code"] != float64(2) {
			t.Fatal("routing refusal exported as successful span")
		}
	}
	for _, bodies := range capture.bodies {
		for _, body := range bodies {
			for _, secret := range []string{"private-path-sentinel", "private-query-sentinel", "private-body-sentinel", "contract-token"} {
				if bytes.Contains(body, []byte(secret)) {
					t.Fatal("routing telemetry leaked private input")
				}
			}
		}
	}
}
