package controlgrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"github.com/doiito/agent_sandbox/internal/sandbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const fixtureToken = "native-grpc-test-only"
const fixtureID = "aaaaaaaaaaaaaaaaaaaaaaaa"

func bridgeForTest(t *testing.T, handler http.Handler, options ...grpc.DialOption) (*Bridge, *grpc.ClientConn, *httptest.Server) {
	t.Helper()
	bridge, err := New(handler, sandbox.NewSingleTokenAuthenticator(fixtureToken))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(bridge)
	server.EnableHTTP2 = true
	server.StartTLS()
	tls := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(tls)), grpc.WithNoProxy(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxResponseBytes)))
	connection, err := grpc.NewClient(strings.TrimPrefix(server.URL, "https://"), options...)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := bridge.Shutdown(ctx); err != nil {
			t.Errorf("bridge close: %v", err)
		}
	})
	return bridge, connection, server
}

func authContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+fixtureToken), cancel
}

func TestBridgeNativeUnaryAuthPrivacyAndNoRetry(t *testing.T) {
	var calls, invoked atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			_ = json.NewEncoder(w).Encode(sandbox.StatusResponse{Status: "ok"})
		case "/readyz":
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(sandbox.StatusResponse{Status: "not-ready"})
		case "/metrics":
			_, _ = io.WriteString(w, "fixture_counter 1\n")
		case "/v2/jobs":
			var request sandbox.RunRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.Backend != "firecracker-linux" || request.Entrypoint != "/bin/echo" {
				t.Error("typed job input changed")
			}
			_ = json.NewEncoder(w).Encode(sandbox.RunResult{ID: fixtureID, State: "completed", Backend: request.Backend,
				Output: "ok", ProtocolOK: true, StartupMode: "cold", GuestResult: json.RawMessage(`{"large":18446744073709551615}`)})
		default:
			invoked.Add(1)
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(sandbox.InferenceAPIErrorResponse{Code: "inference_upstream", Error: "private-output-sentinel", InvocationID: fixtureID})
		}
	})
	retryPolicy := `{"methodConfig":[{"name":[{"service":"sandbox.control.v1.Control"}],"retryPolicy":{"maxAttempts":3,"initialBackoff":"0.001s","maxBackoff":"0.005s","backoffMultiplier":1,"retryableStatusCodes":["UNAVAILABLE"]}}]}`
	bridge, connection, server := bridgeForTest(t, handler, grpc.WithDefaultServiceConfig(retryPolicy))
	client := controlv1.NewControlClient(connection)
	ctx, cancel := authContext(t)
	defer cancel()
	response, err := client.RunJob(ctx, &controlv1.RunJobRequest{Body: &controlv1.RunRequestV2Input{
		Backend: proto.String("firecracker-linux"), ArtifactManifestSha256: proto.String(strings.Repeat("c", 64)), Entrypoint: proto.String("/bin/echo")}})
	if err != nil || response.GetId() != fixtureID || response.GetOutput() != "ok" || response.GetGuestResult().GetObject().GetValues()["large"].GetNumber() != "18446744073709551615" {
		t.Fatalf("native typed RPC failed: %v: %v", response, err)
	}
	var trailers metadata.MD
	ready, err := client.Readiness(ctx, &controlv1.ReadinessRequest{}, grpc.Trailer(&trailers))
	if err != nil || ready.GetStatus() != "not-ready" || trailers.Get("osv-http-status")[0] != "503" {
		t.Fatalf("readiness diagnostic lost: %v: %v", ready, err)
	}
	metrics, err := client.PrometheusMetrics(ctx, &controlv1.PrometheusMetricsRequest{})
	if err != nil || metrics.GetText() != "fixture_counter 1\n" {
		t.Fatalf("metrics changed: %v", err)
	}
	before := calls.Load()
	for _, authenticated := range []bool{false, true} {
		unknownCtx := context.Background()
		if authenticated {
			unknownCtx = ctx
		}
		err := connection.Invoke(unknownCtx, servicePrefix+"private-path-sentinel", &controlv1.TransportEmpty{}, &controlv1.TransportEmpty{})
		want := codes.Unauthenticated
		if authenticated {
			want = codes.Unimplemented
		}
		if status.Code(err) != want || strings.Contains(err.Error(), "private-path-sentinel") {
			t.Fatalf("unknown method auth/privacy: %v", err)
		}
	}
	for _, token := range []string{"", fixtureToken} {
		request, _ := http.NewRequest("POST", server.URL+servicePrefix+"RunJob", bytes.NewReader([]byte{0, 0, 0, 0, 1, 255}))
		request.Header.Set("Content-Type", "application/grpc")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		want := "16"
		if token != "" {
			want = "3"
		}
		if response.ProtoMajor != 2 || response.Trailer.Get("Grpc-Status") != want {
			t.Fatalf("authentication/decoder order: HTTP %d, %v", response.StatusCode, response.Trailer)
		}
	}
	if calls.Load() != before {
		t.Fatal("unknown/unauthenticated/malformed RPC reached business handler")
	}
	body := sandbox.InferenceInvokeRequest{ID: fixtureID, Endpoint: "model", Payload: json.RawMessage(`{"x":1}`)}
	data, _ := json.Marshal(body)
	request, err := bridge.codec.fromValue("InvokeInferenceRequest", map[string]any{"id": fixtureID, "body": valueForTest(t, data)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = connection.Invoke(ctx, servicePrefix+"InvokeInference", request, &controlv1.InferenceInvokeResultOutput{})
	if status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private-output-sentinel") || invoked.Load() != 1 {
		t.Fatalf("committed RPC retried or leaked response text: %v (%d)", err, invoked.Load())
	}
	details := status.Convert(err).Details()
	if len(details) != 1 {
		t.Fatalf("missing typed error details: %v", err)
	}
	detail, ok := details[0].(*controlv1.ErrorDetail)
	if !ok || detail.GetInvocationId() != fixtureID || detail.GetHttpStatus() != 503 || detail.GetCode() != "inference_upstream" {
		t.Fatalf("lost dispatched invocation: %v", details)
	}
}

func TestBridgeRealCommonHTTPAndRPCHealth(t *testing.T) {
	_, connection, server := bridgeForTest(t, sandbox.NewAPI(nil, fixtureToken, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := controlv1.NewControlClient(connection).Health(ctx, &controlv1.HealthRequest{})
	if err != nil || response.GetStatus() != "ok" {
		t.Fatalf("actual common handler over native RPC: %v %v", response, err)
	}
	httpResponse, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != 200 {
		t.Fatal(httpResponse.StatusCode)
	}
}

func TestBridgeShutdownDrainsAcceptedUnary(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	bridge, connection, _ := bridgeForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(sandbox.StatusResponse{Status: "ok"})
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	// Read initial headers separately from the unary response so a buffered
	// commit header cannot pass after the held handler is released.
	call, err := connection.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, controlv1.Control_Health_FullMethodName)
	if err != nil {
		t.Fatal(err)
	}
	if err := call.SendMsg(&controlv1.HealthRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := call.CloseSend(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if header, err := call.Header(); err != nil || strings.Join(header.Get("osv-rpc-accepted"), ",") != "1" {
		t.Fatalf("dispatch must commit the headers before the handler returns: %v %v", header, err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- bridge.Shutdown(ctx) }()
	select {
	case err := <-stopped:
		t.Fatalf("accepted call did not drain: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	var response controlv1.StatusResponseOutput
	if err := call.RecvMsg(&response); err != nil || response.GetStatus() != "ok" {
		t.Fatalf("draining response: %v %v", response.GetStatus(), err)
	}
	if err := call.RecvMsg(&controlv1.StatusResponseOutput{}); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}
