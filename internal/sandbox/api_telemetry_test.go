package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

type telemetryTestRunner struct {
	run  func(context.Context, RunRequest) (RunResult, error)
	pool func(context.Context) (WarmPoolSnapshot, error)
}

func (r *telemetryTestRunner) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	if r.run != nil {
		return r.run(ctx, req)
	}
	return RunResult{ID: strings.Repeat("a", 24), State: "succeeded", Backend: "firecracker-linux",
		TemplateID: "template-a", ArtifactManifestSHA256: strings.Repeat("b", 64), StartupMode: "warm", ProtocolOK: true}, nil
}
func (*telemetryTestRunner) Doctor() DoctorReport { return DoctorReport{Ready: true} }
func (*telemetryTestRunner) Capabilities() (CapabilityReport, error) {
	return CapabilityReport{Backend: "firecracker-linux"}, nil
}
func (r *telemetryTestRunner) WarmPoolStatusContext(ctx context.Context) (WarmPoolSnapshot, error) {
	if r.pool != nil {
		return r.pool(ctx)
	}
	return WarmPoolSnapshot{Healthy: true}, ctx.Err()
}

type telemetryCapture struct {
	mu     sync.Mutex
	bodies map[string][][]byte
}

func (c *telemetryCapture) serve(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	c.mu.Lock()
	c.bodies[r.URL.Path] = append(c.bodies[r.URL.Path], data)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"partialSuccess":{}}`)
}

func apiTelemetryConfig(endpoint string) otlp.Config {
	return otlp.Config{Endpoint: endpoint, AllowLoopbackHTTP: true, IntervalMS: 60000, TimeoutMS: 1000}
}

func closeAPITelemetry(t *testing.T, handler *apiHTTPHandler) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = handler.Shutdown(ctx)
	err := handler.CloseTelemetry(ctx)
	if exporter := handler.api.telemetry.Load(); exporter != nil {
		select {
		case <-exporter.Done():
		case <-time.After(time.Second):
			t.Error("telemetry worker did not exit")
		}
	}
	return err
}

func telemetryRows(t *testing.T, bodies [][]byte, signal string) []map[string]any {
	t.Helper()
	root, scopes, records := "resourceMetrics", "scopeMetrics", "metrics"
	if signal == "logs" {
		root, scopes, records = "resourceLogs", "scopeLogs", "logRecords"
	} else if signal == "traces" {
		root, scopes, records = "resourceSpans", "scopeSpans", "spans"
	}
	var rows []map[string]any
	for _, data := range bodies {
		var batch map[string]any
		if json.Unmarshal(data, &batch) != nil {
			t.Fatal("invalid emitted OTLP JSON")
		}
		for _, r := range batch[root].([]any) {
			for _, s := range r.(map[string]any)[scopes].([]any) {
				for _, value := range s.(map[string]any)[records].([]any) {
					rows = append(rows, value.(map[string]any))
				}
			}
		}
	}
	return rows
}

func telemetryTags(row map[string]any) map[string]string {
	tags := map[string]string{}
	for _, value := range row["attributes"].([]any) {
		attribute := value.(map[string]any)
		tags[attribute["key"].(string)] = attribute["value"].(map[string]any)["stringValue"].(string)
	}
	return tags
}

func TestOTLPConfigValidationAndSnapshotDoNotOpenCredentials(t *testing.T) {
	c := testConfig()
	n := 750
	c.OTLP = &otlp.Config{Endpoint: "https://127.0.0.1:1", CAFile: "/not-present/otlp-ca.pem", Signals: []string{"metrics"}, TraceSamplePermille: &n}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	copy := c.snapshot()
	c.OTLP.Signals[0], *c.OTLP.TraceSamplePermille = "logs", 0
	if copy.OTLP.Signals[0] != "metrics" || *copy.OTLP.TraceSamplePermille != 750 {
		t.Fatal("caller mutation reached the frozen configuration")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(c)
	if os.WriteFile(path, data, 0o600) != nil {
		t.Fatal("cannot create config fixture")
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(data, &object)
	object["otlp"].(map[string]any)["unknown"] = "secret"
	data, _ = json.Marshal(object)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown telemetry config field accepted")
	}
	c.OTLP.Source = "host.launcher.audit"
	if c.Validate() == nil {
		t.Fatal("API resource can impersonate a durable root audit")
	}
	c.OTLP.Source = ""
	if _, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, nil, slog.Default(), "", nil, c.OTLP); err == nil {
		t.Fatal("construction did not validate actual credential files")
	}
	disabled := NewAPIWithAuthenticator(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.Default()).(*apiHTTPHandler)
	if disabled.api.telemetry.Load() != nil || closeAPITelemetry(t, disabled) != nil {
		t.Fatal("disabled telemetry started a worker or altered shutdown")
	}
}

func TestOTLPAPIThreeSignalsUseTrustedMetadataAndNeverRawRequestData(t *testing.T) {
	capture := &telemetryCapture{bodies: map[string][][]byte{}}
	collector := httptest.NewServer(http.HandlerFunc(capture.serve))
	defer collector.Close()
	secret := "DO-NOT-EXPORT-request-output-token-code-cookie"
	runner := &telemetryTestRunner{run: func(ctx context.Context, request RunRequest) (RunResult, error) {
		if request.tenantID != "legacy" || len(request.Args) != 1 || request.Args[0] != secret {
			t.Error("task semantics changed while adding telemetry")
		}
		return RunResult{ID: strings.Repeat("a", 24), State: "succeeded", Backend: "firecracker-linux", Output: secret,
			TemplateID: "template-a", ArtifactManifestSHA256: strings.Repeat("b", 64), StartupMode: "warm", ProtocolOK: true,
			GuestResult: json.RawMessage(`{"private":"` + secret + `"}`)}, nil
	}}
	config := apiTelemetryConfig(collector.URL)
	h, _, err := NewAPIWithTelemetry(runner, NewSingleTokenAuthenticator(secret), slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	defer closeAPITelemetry(t, handler)
	for _, test := range []struct {
		method, path, body, token string
		status                    int
	}{
		{"POST", "/v1/jobs?private=" + secret, `{"entrypoint":"/agent","args":["` + secret + `"]}`, secret, 200},
		{secret, "/not-registered/" + secret, "", secret, 404},
		{"GET", "/v1/doctor?private=" + secret, "", "wrong-" + secret, 401},
	} {
		r := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		r.Header.Set("Authorization", "Bearer "+test.token)
		r.Header.Set("Cookie", secret)
		r.RemoteAddr = secret
		r.Pattern = secret
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		if response.Code != test.status {
			t.Fatalf("response changed: %d %s", response.Code, response.Body.String())
		}
	}
	if err := closeAPITelemetry(t, handler); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	for _, bodies := range capture.bodies {
		for _, body := range bodies {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("private request or response data exported")
			}
		}
	}
	logs := telemetryRows(t, capture.bodies["/v1/logs"], "logs")
	traces := telemetryRows(t, capture.bodies["/v1/traces"], "traces")
	metrics := telemetryRows(t, capture.bodies["/v1/metrics"], "metrics")
	if len(logs) != 3 || len(traces) != 3 || len(metrics) < 5 {
		t.Fatal("application events or metrics absent")
	}
	first := telemetryTags(logs[0])
	if first["tenant"] != "legacy" || first["http.route"] != "POST /v1/jobs" || first["osv.job.id"] != strings.Repeat("a", 24) ||
		first["osv.job.state"] != "succeeded" || first["osv.startup.mode"] != "warm" || first["http.response.status_code"] != "200" ||
		first["osv.observation.source"] != "host.api" || traces[0]["kind"] != float64(2) {
		t.Fatal("trusted task metadata or provenance missing")
	}
	unknown, rejected := telemetryTags(logs[1]), telemetryTags(logs[2])
	if unknown["http.route"] != "unmatched" || unknown["http.request.method"] != "OTHER" || unknown["http.response.status_code"] != "404" ||
		rejected["tenant"] != "" || rejected["http.response.status_code"] != "401" || rejected["osv.job.id"] != "" {
		t.Fatal("unknown handler success inferred or unauthenticated tenant exposed")
	}
	for index := range logs {
		if logs[index]["traceId"] != traces[index]["traceId"] || logs[index]["spanId"] != traces[index]["spanId"] {
			t.Fatal("request log and span lost their correlation")
		}
	}
	state := handler.api.telemetry.Load().Stats()
	if state.DroppedEvents != 0 || state.Signals["logs"].ExportedRecords != 3 || state.Signals["traces"].ExportedRecords != 3 {
		t.Fatal("normal application shutdown lost accepted events")
	}
}

func TestOTLPAPIQueuePressureAndCollectorFailureDoNotBlockBusiness(t *testing.T) {
	entered, exited := make(chan struct{}, 1), make(chan struct{}, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
		exited <- struct{}{}
	}))
	defer collector.Close()
	config := apiTelemetryConfig(collector.URL)
	config.Signals, config.QueueCapacity, config.BatchSize = []string{"logs"}, 2, 1
	h, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.Default(), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	defer closeAPITelemetry(t, handler)
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if get("/healthz").Code != 200 {
		t.Fatal("health failed")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach the stalled collector")
	}
	started := time.Now()
	for i := 0; i < 4; i++ {
		if get("/healthz").Code != 200 {
			t.Fatal("collector failure affected business response")
		}
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("full export queue blocked API handlers")
	}
	if get("/metrics").Body.String() == "" || handler.api.telemetry.Load().Stats().EventLoss.QueueFull == 0 {
		t.Fatal("export pressure was not observable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if handler.CloseTelemetry(ctx) == nil {
		t.Fatal("cancelled export falsely reported complete delivery")
	}
	select {
	case <-handler.api.telemetry.Load().Done():
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("cancelled export request remained open")
	}
}

func TestOTLPMetricsPoolFailurePreservesAPIAndContextCancellation(t *testing.T) {
	h := newAPIWithEgress(&telemetryTestRunner{pool: func(ctx context.Context) (WarmPoolSnapshot, error) {
		return WarmPoolSnapshot{}, errors.New("private-root-detail")
	}}, NewSingleTokenAuthenticator("token"), slog.Default(), "")
	h.api.metrics.httpRequests.Store(9007199254740993)
	h.api.metrics.recordJob("tenant-a", "succeeded", 10*time.Millisecond)
	metrics, err := h.api.otlpMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]otlp.Metric{}
	for _, metric := range metrics {
		byName[metric.Name] = metric
	}
	if *byName["osv_sandbox_http_requests_total"].Sum.DataPoints[0].AsInt != "9007199254740993" ||
		*byName["osv_sandbox_warm_pool_snapshot_available"].Gauge.DataPoints[0].AsInt != "0" ||
		byName["osv_sandbox_jobs_total"].Sum.DataPoints[0].StartTimeUnixNano == "" {
		t.Fatal("pool failure erased precise API counters or falsified availability")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.api.otlpMetrics(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("metric source ignored cancellation")
	}
	if _, err := testManager(t, "output").WarmPoolStatusContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("manager snapshot ignored cancellation")
	}
}

func TestOTLPLauncherSnapshotCancellationClosesTheActualSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launcher.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, exited := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request launcherRequest
		if json.NewDecoder(conn).Decode(&request) != nil || request.Operation != "warm-status" {
			return
		}
		close(entered)
		_, _ = io.Copy(io.Discard, conn)
		close(exited)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := (LauncherClient{SocketPath: path}).WarmPoolStatusContext(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot RPC did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("RPC cancellation was not preserved", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled pool RPC did not exit")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("cancelled RPC socket was not closed")
	}
}

func TestOTLPPoolProfilesRemainDistinctAndUseObservedCounterOrigins(t *testing.T) {
	metrics := poolOTLPMetrics(WarmPoolSnapshot{Enabled: true, Healthy: true, Hits: 9,
		Misses: map[string]uint64{"empty": 1, "PRIVATE-root-reason": 2},
		Profiles: []WarmProfileSnapshot{{Name: "small", Key: strings.Repeat("a", 64), TemplateID: "linux", Backend: "firecracker-linux", Ready: 1},
			{Name: "small", Key: strings.Repeat("b", 64), TemplateID: "osv", Backend: "firecracker-osv", Ready: 2}}}, time.Now(), "host.launcher")
	var ready *otlp.Gauge
	for _, metric := range metrics {
		if metric.Sum != nil {
			t.Fatal("launcher counters claimed the unrelated API cumulative origin")
		}
		if metric.Name == "osv_sandbox_warm_pool_ready" {
			ready = metric.Gauge
		}
	}
	if ready == nil || len(ready.DataPoints) != 2 || ready.DataPoints[0].Attributes[2].Value == ready.DataPoints[1].Attributes[2].Value {
		t.Fatal("same-name profiles from different templates collided")
	}
	data, _ := json.Marshal(metrics)
	if bytes.Contains(data, []byte("PRIVATE")) || !bytes.Contains(data, []byte("host.launcher")) || !bytes.Contains(data, []byte("other")) {
		t.Fatal("snapshot provenance or reason privacy incorrect")
	}
}

type telemetryInterfaceWriter struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (w *telemetryInterfaceWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, errors.New("test-only-hijack")
}

func TestOTLPRequestObservationPreservesWriterInterfacesAndOriginalPanic(t *testing.T) {
	capture := &telemetryCapture{bodies: map[string][][]byte{}}
	collector := httptest.NewServer(http.HandlerFunc(capture.serve))
	defer collector.Close()
	config := apiTelemetryConfig(collector.URL)
	config.Signals = []string{"logs", "traces"}
	h, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.Default(), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	defer closeAPITelemetry(t, handler)
	writer := &telemetryInterfaceWriter{ResponseRecorder: httptest.NewRecorder()}
	secret := "PRIVATE-panic-state-backend-output"
	mux := http.NewServeMux()
	handler.api.routes["GET /observe-test"] = struct{}{}
	mux.HandleFunc("GET /observe-test", func(w http.ResponseWriter, r *http.Request) {
		if w != writer {
			t.Error("ResponseWriter identity changed")
		}
		w.(http.Flusher).Flush()
		_, _, _ = w.(http.Hijacker).Hijack()
		observeRequestStatus(r, 200)
		observeJobResult(r, RunResult{ID: secret, Backend: secret, TemplateID: "/" + secret, ArtifactManifestSHA256: secret, StartupMode: secret}, secret)
		panic(secret)
	})
	handler.handler = handler.api.secure(mux)
	r := httptest.NewRequest("GET", "/observe-test", nil)
	r.Header.Set("Authorization", "Bearer token")
	var caught any
	func() { defer func() { caught = recover() }(); handler.ServeHTTP(writer, r) }()
	if caught != secret || !writer.hijacked || !writer.Flushed {
		t.Fatal("observation changed optional interfaces or swallowed the original panic")
	}
	if err := closeAPITelemetry(t, handler); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	logs := telemetryRows(t, capture.bodies["/v1/logs"], "logs")
	traces := telemetryRows(t, capture.bodies["/v1/traces"], "traces")
	if len(logs) != 1 || len(traces) != 1 || telemetryTags(logs[0])["http.handler.returned"] != "false" ||
		telemetryTags(logs[0])["osv.job.state"] != "unknown" || traces[0]["status"].(map[string]any)["code"] != float64(2) {
		t.Fatal("panic was falsely reported as a successful handler return")
	}
	for _, bodies := range capture.bodies {
		for _, body := range bodies {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("private panic or invalid result metadata exported")
			}
		}
	}
}

func TestOTLPEnabledRealMTLSPortUpgradeAndFinalTelemetryDrain(t *testing.T) {
	capture := &telemetryCapture{bodies: map[string][][]byte{}}
	collector := httptest.NewServer(http.HandlerFunc(capture.serve))
	defer collector.Close()
	fixture := newPortHTTPFixture(t, func(conn net.Conn, reader *bufio.Reader, request linuxPortRequest) {
		if request.Operation != "open" {
			sendPortControlInfo(conn, request, "cancelled")
			return
		}
		_ = writePortBytes(conn, testPortJSON(testPortReply(request)))
		kind, _, err := readTestPortFrame(reader)
		if err != nil || kind != portEOFFrame {
			t.Error("client half-close was not received")
			return
		}
		_ = writePortBytes(conn, testPortFrame(portEOFFrame, nil))
		body, _ := json.Marshal(SessionPortInfo{ID: request.ID, Port: request.Port, Status: "completed"})
		_ = writePortBytes(conn, testPortFrame(portFinishedFrame, body))
	})
	config := apiTelemetryConfig(collector.URL)
	config.Signals = []string{"logs", "traces"}
	exporter, err := otlp.New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.api.telemetry.Store(exporter)
	defer closeAPITelemetry(t, fixture.handler)
	conn, reader, response, err := fixture.open(portOpenRequest(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if response.StatusCode != 101 {
		t.Fatal("enabling telemetry broke the actual port upgrade")
	}
	if err := writePortBytes(conn, testPortFrame(portEOFFrame, nil)); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []byte{portEOFFrame, portFinishedFrame} {
		kind, _, err := readTestPortFrame(reader)
		if err != nil || kind != expected {
			t.Fatal("upgraded stream framing changed", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if fixture.handler.Shutdown(ctx) != nil || fixture.server.Config.Shutdown(ctx) != nil || fixture.handler.CloseTelemetry(ctx) != nil {
		t.Fatal("upgraded HTTP and telemetry failed to drain")
	}
	if exporter.Stats().Signals["logs"].ExportedRecords != 1 || exporter.Stats().Signals["traces"].ExportedRecords != 1 {
		t.Fatalf("upgraded request's final event was lost: %+v", exporter.Stats())
	}
}

func TestOTLPFinalCloseWaitsForOuterHandlerObservation(t *testing.T) {
	capture := &telemetryCapture{bodies: map[string][][]byte{}}
	collector := httptest.NewServer(http.HandlerFunc(capture.serve))
	defer collector.Close()
	config := apiTelemetryConfig(collector.URL)
	config.Signals = []string{"logs"}
	h, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.Default(), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() { unblock(); <-returned; _ = closeAPITelemetry(t, handler) }()
	mux := http.NewServeMux()
	handler.api.routes["GET /outer-observation-test"] = struct{}{}
	mux.HandleFunc("GET /outer-observation-test", func(w http.ResponseWriter, r *http.Request) {
		_, _, _ = w.(http.Hijacker).Hijack()
		close(entered)
		<-release // Child transport is done; outer request has not returned.
	})
	handler.handler = handler.api.secure(mux)
	r := httptest.NewRequest("GET", "/outer-observation-test", nil)
	r.Header.Set("Authorization", "Bearer token")
	go func() {
		handler.ServeHTTP(&telemetryInterfaceWriter{ResponseRecorder: httptest.NewRecorder()}, r)
		close(returned)
	}()
	<-entered
	closing := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { closing <- handler.CloseTelemetry(ctx) }()
	select {
	case err := <-closing:
		t.Fatalf("telemetry close returned before outer handler observation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-closing:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("telemetry close did not finish after the outer handler")
	}
	if state := handler.api.telemetry.Load().Stats(); state.AcceptedEvents != 1 || state.Signals["logs"].ExportedRecords != 1 || state.EventLoss.Closed != 0 {
		t.Fatalf("final outer observation was not delivered: %+v", state)
	}
}

func TestOTLPFinalCloseDeadlinePersistsAndRejectsNewRequests(t *testing.T) {
	config := apiTelemetryConfig("http://127.0.0.1:1")
	config.Signals = []string{"logs"}
	h, _, err := NewAPIWithTelemetry(&telemetryTestRunner{}, NewSingleTokenAuthenticator("token"), slog.Default(), "", nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*apiHTTPHandler)
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer func() { unblock(); <-returned; _ = closeAPITelemetry(t, handler) }()
	handler.handler = handler.api.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	r := httptest.NewRequest("GET", "/healthz", nil)
	go func() { handler.ServeHTTP(httptest.NewRecorder(), r); close(returned) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := handler.CloseTelemetry(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unfinished outer request falsely reported complete delivery", err)
	}
	select {
	case <-handler.api.telemetry.Load().Done():
	case <-time.After(time.Second):
		t.Fatal("deadline did not stop the export worker")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 503 {
		t.Fatal("new request admitted after telemetry drain began")
	}
	unblock()
	<-returned
	if err := handler.CloseTelemetry(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("repeated closure forgot incomplete request delivery", err)
	}
}
