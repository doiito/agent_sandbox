package apicontract

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func TestContractMatchesAllActualRoutesAndCanonicalBytes(t *testing.T) {
	root := "../.."
	first, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(root)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("contract generation is not deterministic")
	}
	canonical, err := os.ReadFile(filepath.Join(root, "api/contracts/openapi.json"))
	if err != nil || !bytes.Equal(append(first, '\n'), canonical) {
		t.Fatal("canonical contract is stale")
	}
	actual, err := SourceRoutes(filepath.Join(root, "internal/sandbox/http.go"))
	if err != nil || len(actual) != 48 || len(RoutePatterns()) != 48 {
		t.Fatal("full route denominator changed without contract review")
	}
}

func TestContractRejectsMissingChangedAndDuplicateRoutes(t *testing.T) {
	original, err := os.ReadFile("../../internal/sandbox/http.go")
	if err != nil {
		t.Fatal(err)
	}
	for name, altered := range map[string]string{
		"missing":   strings.Replace(string(original), `register("GET /healthz", api.health)`, "", 1),
		"handler":   strings.Replace(string(original), `register("GET /healthz", api.health)`, `register("GET /healthz", api.ready)`, 1),
		"duplicate": strings.Replace(string(original), `register("GET /healthz", api.health)`, "register(\"GET /healthz\", api.health)\n register(\"GET /healthz\", api.health)", 1),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "internal/sandbox")
			if os.MkdirAll(directory, 0o755) != nil || os.WriteFile(filepath.Join(directory, "http.go"), []byte(altered), 0o600) != nil {
				t.Fatal("cannot create mutated route fixture")
			}
			if _, err := Generate(root); err == nil {
				t.Fatal("changed route surface accepted")
			}
		})
	}
}

type unknownJSONCodec uint64

func (unknownJSONCodec) MarshalJSON() ([]byte, error) { return []byte(`"custom"`), nil }

func TestContractRefusesUnknownCustomJSONMarshaler(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unknown custom JSON format was inferred from its underlying kind")
		}
	}()
	newSchemaBuilder().ref(unknownJSONCodec(2), false)
}

func TestContractActualWireEncodersValidateOffline(t *testing.T) {
	id, other := strings.Repeat("a", 24), strings.Repeat("b", 24)
	digest := strings.Repeat("c", 64)
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	zero := uint64(0)
	falseValue := false
	var samples []object
	add := func(name string, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("actual wire encoder %s: %v", name, err)
		}
		samples = append(samples, object{"schema": name, "value": json.RawMessage(data)})
	}
	add("APIErrorResponseOutput", sandbox.APIErrorResponse{Code: "future_code", Error: "explanation"})
	add("LegacyAPIErrorResponseOutput", sandbox.LegacyAPIErrorResponse{Error: "explanation"})
	add("InferenceAPIErrorResponseOutput", sandbox.InferenceAPIErrorResponse{Code: "inference_upstream", Error: "inference upstream", InvocationID: id})
	add("InferenceAPIErrorResponseOutput", sandbox.InferenceAPIErrorResponse{Code: "inference_request", Error: "invalid"})
	add("StatusResponseOutput", sandbox.StatusResponse{Status: "ready"})
	add("RunRequestV2Input", sandbox.RunRequest{Backend: "firecracker-linux", ArtifactManifestSHA256: digest, Entrypoint: "/bin/echo", Args: []string{"hello"}, Stdin: []byte{0, 255}})
	add("RunRequestInput", sandbox.RunRequest{})
	add("SessionCreateRequestInput", sandbox.SessionCreateRequest{Backend: "firecracker-linux", ArtifactManifestSHA256: digest})
	add("SessionCommandRequestInput", sandbox.SessionCommandRequest{Entrypoint: "/bin/echo"})
	add("SessionTimeoutRequestInput", sandbox.SessionTimeoutRequest{TTLMS: 1000})
	add("PreviewCreateRequestInput", sandbox.PreviewCreateRequest{TTLMS: 300000})
	add("CodeContextCreateRequestInput", sandbox.CodeContextCreateRequest{ID: id, Language: "python"})
	add("CodeContextDefaultRequestInput", sandbox.CodeContextDefaultRequest{})
	add("CodeContextRestartRequestInput", sandbox.CodeContextRestartRequest{Generation: 1})
	for _, timeout := range []*uint64{nil, &zero} {
		add("CodeExecutionRequestInput", sandbox.CodeExecutionRequest{ContextID: id, Generation: 1, ExecutionID: other, TimeoutMS: timeout})
	}
	add("SessionCommandInputRequestInput", sandbox.SessionCommandInputRequest{DataBase64: "AP8="})
	add("SessionCommandInputRequestInput", sandbox.SessionCommandInputRequest{Close: true})
	add("SessionWatchRequestInput", sandbox.SessionWatchRequest{Path: "/workspace"})
	empty, destination := "", "/workspace/renamed"
	for _, request := range []sandbox.SessionFileRequest{{Action: "write", Path: "/workspace/file", DataBase64: &empty}, {Action: "rename", Path: "/workspace/file", Destination: &destination}, {Action: "list", Path: "/workspace"}} {
		add("SessionFileRequestInput", request)
	}
	add("NetworkFetchRequestInput", sandbox.NetworkFetchRequest{URL: "https://service.example/path"})
	add("SessionPortLimitsInput", sandbox.SessionPortLimits{MaxBytes: 1, TimeoutMS: 1, IdleTimeoutMS: 1})
	add("InferenceInvokeRequestInput", sandbox.InferenceInvokeRequest{ID: id, Endpoint: "0model", Payload: json.RawMessage(`{"input":"hello"}`)})
	add("InferenceBillOutput", sandbox.InferenceBill{Protocol: "osv-sandbox-inference-bill/v1", Tenant: "tenant-a", TaskID: id, VMID: other, LeaseID: id, Unit: "units", HeldUnits: sandbox.InferenceUnits(1<<63 + 7), SettledUnits: sandbox.InferenceUnits(^uint64(0))})
	add("CodeContextOutput", sandbox.CodeContext{ID: id, Generation: 1, Language: "python", Cwd: "/workspace", State: "idle"})
	for _, event := range []sandbox.CodeEvent{
		{Type: "started"}, {Type: "stdout", Data: json.RawMessage(`"AP8="`)},
		{Type: "stderr", Data: json.RawMessage(`""`)},
		{Type: "result", Data: json.RawMessage(`{"application/json":{"answer":42},"text/plain":"42"}`), IsMainResult: &falseValue},
		{Type: "error", Name: "Error", Value: "", Traceback: ""},
		{Type: "finished", Status: "completed", ContextUsable: &falseValue},
	} {
		add("CodeEventOutput", event)
	}
	add("CodeExecutionPageOutput", sandbox.CodeExecutionPage{ID: id, ContextID: other, Generation: 1, Status: "completed"})
	add("SessionOutputFrameOutput", sandbox.SessionOutputFrame{SessionID: id, CommandID: other, SessionOutputEvent: sandbox.SessionOutputEvent{Sequence: 1, Stream: "stdout", DataBase64: "AP8="}})
	add("SessionCommandTimeoutFrameOutput", sandbox.SessionCommandTimeoutFrame{SessionID: id, CommandID: other})
	add("SessionInfoOutput", sandbox.SessionInfo{ID: id, State: "active", Backend: "firecracker-linux", ArtifactManifestSHA256: digest, CreatedAt: now, ExpiresAt: now.Add(time.Minute), StartupMode: "warm"})
	add("SessionListPageOutput", sandbox.SessionListPage{Sessions: []sandbox.SessionInfo{}})
	add("SessionCommandsResponseOutput", sandbox.SessionCommandsResponse{SessionID: id})
	add("SessionWatchesResponseOutput", sandbox.SessionWatchesResponse{SessionID: id})
	add("CodeContextsResponseOutput", sandbox.CodeContextsResponse{SessionID: id})
	add("PortConnectionResponseOutput", sandbox.PortConnectionResponse{SessionID: id, Connection: sandbox.SessionPortInfo{ID: other, Port: 8080, Status: "completed"}})
	add("PreviewGrantInfoOutput", sandbox.PreviewGrantInfo{Protocol: "osv-sandbox-preview/v1", ID: id, SessionID: other, Port: 8080, Origin: "https://preview.example", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Status: "active"})
	data, err := json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-B", "../../scripts/check-api-contract.py", "--samples", "-")
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("independent offline wire validation failed: %v: %s", err, output)
	}
	if path := os.Getenv("OSV_REST_CONTRACT_ENCODER_SAMPLES"); path != "" {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("validated %d actual Go encoder samples with the independent offline validator", len(samples))
}
