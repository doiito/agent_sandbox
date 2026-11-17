package otlp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("bounded OTLP observation timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func ack(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{}`)
}

func TestExporterThreeSignalsAndSharedTraceLogIDs(t *testing.T) {
	var mu sync.Mutex
	requests := map[string][][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid OTLP request headers")
		}
		mu.Lock()
		requests[r.URL.Path] = append(requests[r.URL.Path], body)
		mu.Unlock()
		ack(w)
	}))
	defer server.Close()
	c := testConfig(server.URL + "/collector")
	c.Signals = []string{"metrics", "logs", "traces"}
	e, err := New(c, func(context.Context) ([]Metric, error) { return sampleMetrics(), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	attributes := []Attribute{{"tenant", "tenant-a"}}
	if !e.Record(Event{Name: "api.request.complete", Source: "host.api", Kind: 2, Attributes: attributes}) ||
		!e.Record(Event{Name: "guest.resource.sample", Source: "guest.reported", Failed: true}) {
		t.Fatal("valid records not admitted")
	}
	attributes[0].Value = "mutated-after-record"
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"metrics", "logs", "traces"} {
		if len(requests["/collector/v1/"+name]) != 1 {
			t.Fatalf("wrong request count for %s", name)
		}
	}
	var logs struct {
		Resources []struct {
			Scopes []struct {
				Records []struct {
					TraceID, SpanID string
					Attributes      []struct {
						Key   string
						Value struct{ StringValue string }
					}
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	var traces struct {
		Resources []struct {
			Scopes []struct {
				Spans []struct {
					TraceID, SpanID string
					Kind, Flags     int
				}
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if json.Unmarshal(requests["/collector/v1/logs"][0], &logs) != nil || json.Unmarshal(requests["/collector/v1/traces"][0], &traces) != nil {
		t.Fatal("invalid wire envelope")
	}
	lr, sp := logs.Resources[0].Scopes[0].Records, traces.Resources[0].Scopes[0].Spans
	if len(lr) != 2 || len(sp) != 2 || sp[0].Kind != 2 || sp[1].Kind != 1 || sp[0].Flags != 1 {
		t.Fatal("event counts or enum encoding invalid")
	}
	for i := range lr {
		trace, err := hex.DecodeString(lr[i].TraceID)
		if err != nil || len(trace) != 16 || len(lr[i].SpanID) != 16 || lr[i].TraceID != sp[i].TraceID || lr[i].SpanID != sp[i].SpanID {
			t.Fatal("trace/log identity not valid shared hex")
		}
	}
	if lr[0].TraceID == lr[1].TraceID || strings.Contains(string(requests["/collector/v1/logs"][0]), "mutated-after-record") ||
		!strings.Contains(string(requests["/collector/v1/logs"][0]), "guest.reported") {
		t.Fatal("identity, copied metadata or guest provenance invalid")
	}
	state := e.Stats()
	if state.AcceptedEvents != 2 || state.DroppedEvents != 0 || state.Signals["metrics"].ExportedRecords != 3 ||
		state.Signals["logs"].ExportedRecords != 2 || state.Signals["traces"].ExportedRecords != 2 {
		t.Fatal("export accounting invalid")
	}
}

func TestExporterConcurrentRecordAndCloseHasNoAcceptedLoss(t *testing.T) {
	var received atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data struct {
			Resources []struct {
				Scopes []struct {
					Records []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			t.Error("bad concurrent log data")
		} else {
			received.Add(uint64(len(data.Resources[0].Scopes[0].Records)))
		}
		ack(w)
	}))
	defer server.Close()
	c := testConfig(server.URL)
	c.QueueCapacity, c.BatchSize = 16384, 64
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	var accepted atomic.Uint64
	if e.Record(Event{Name: "seed", Source: "host.api"}) {
		accepted.Add(1)
	}
	var writers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for n := 0; n < 128; n++ {
				if e.Record(Event{Name: "concurrent", Source: "host.api"}) {
					accepted.Add(1)
				}
			}
		}()
	}
	close(start)
	finished := make(chan struct{})
	go func() { _ = e.Close(context.Background()); close(finished) }()
	writers.Wait()
	<-finished
	if received.Load() != accepted.Load() || accepted.Load() != e.Stats().AcceptedEvents {
		t.Fatal("an admitted event was stranded at close")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = e.Close(ctx) // Repeated closure never creates a new worker/request.
	if e.Record(Event{Name: "late", Source: "host.api"}) {
		t.Fatal("closed exporter accepted an event")
	}
}

func TestExporterQueuePressureAndCancellationRemainBounded(t *testing.T) {
	entered := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
		finished <- struct{}{}
	}))
	defer server.Close()
	c := testConfig(server.URL)
	c.QueueCapacity, c.BatchSize, c.TimeoutMS = 2, 1, 3000
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if !e.Record(Event{Name: "slow", Source: "host.api"}) {
		t.Fatal("first valid event was not admitted")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach slow collector")
	}
	if !e.Record(Event{Name: "queued-1", Source: "host.api"}) || !e.Record(Event{Name: "queued-2", Source: "host.api"}) {
		t.Fatal("queue did not accept its configured capacity")
	}
	started := time.Now()
	if e.Record(Event{Name: "overflow", Source: "host.api"}) || time.Since(started) > 100*time.Millisecond {
		t.Fatal("full queue blocked or accepted overflow")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.Close(ctx); err == nil {
		t.Fatal("deadline claimed full shutdown")
	}
	select {
	case <-e.Done():
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join worker")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close the active request")
	}
	state := e.Stats()
	logs, loss := state.Signals["logs"], state.EventLoss
	// Cancellation can select stop, wake, or ctx.Done. A queued event may be
	// abandoned before encoding or counted as a failed encoded batch; the
	// disjoint totals must account for every event under either schedule.
	if state.AcceptedEvents != 3 || state.QueueDepth != 0 || loss.QueueFull != 1 || loss.Invalid != 0 || loss.Closed != 0 ||
		loss.Unencoded+logs.DroppedRecords != state.AcceptedEvents || loss.Unencoded > 2 ||
		state.DroppedEvents != 1+loss.Unencoded || logs.Requests != 1 || logs.Retries != 0 ||
		logs.FailedBatches != logs.DroppedRecords || logs.FullBatches != 0 || logs.PartialBatches != 0 ||
		logs.ExportedRecords != 0 || logs.RejectedRecords != 0 || state.CollectionErrors != 0 || state.InternalErrors != 0 {
		t.Fatalf("queue/cancellation accounting did not conserve events: %+v", state)
	}
}

func TestExporterAdmissionRejectionsAreSeparated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ack(w) }))
	defer server.Close()
	e, err := New(testConfig(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if e.Record(Event{Name: "invalid", Source: "untrusted-source"}) {
		t.Fatal("invalid event accepted")
	}
	if e.Close(context.Background()) == nil {
		t.Fatal("known admission loss was not reported")
	}
	if e.Record(Event{Name: "late", Source: "host.api"}) {
		t.Fatal("event admitted after worker exit")
	}
	s := e.Stats()
	if s.AcceptedEvents != 0 || s.DroppedEvents != 2 || s.EventLoss != (EventLossStats{Invalid: 1, Closed: 1}) ||
		s.Signals["logs"].Requests != 0 || s.Signals["logs"].DroppedRecords != 0 {
		t.Fatalf("admission rejection causes mixed with transport loss: %+v", s)
	}
}

func TestExporterSamplingIsExplicitAndDoesNotCountAsTransportLoss(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ack(w) }))
	defer server.Close()
	n := 500
	c := testConfig(server.URL)
	c.Signals, c.TraceSamplePermille, c.QueueCapacity, c.BatchSize = []string{"traces"}, &n, 2048, 1024
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	for i := 0; i < 1000; i++ {
		e.Record(Event{Name: "sampled", Source: "host.api"})
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := e.Stats()
	if s.SampledOutTraces != 500 || s.AcceptedEvents != 500 || s.DroppedEvents != 0 || s.Signals["traces"].ExportedRecords != 500 {
		t.Fatal("trace sampling/loss accounting invalid")
	}
}

func TestExporterMetricsAreSplitWithoutChangingValues(t *testing.T) {
	var mu sync.Mutex
	var values []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Resources []struct {
				Scopes []struct {
					Metrics []struct {
						Sum struct {
							DataPoints []struct {
								AsInt string `json:"asInt"`
							} `json:"dataPoints"`
						} `json:"sum"`
					} `json:"metrics"`
				} `json:"scopeMetrics"`
			} `json:"resourceMetrics"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		} else {
			mu.Lock()
			for _, metric := range body.Resources[0].Scopes[0].Metrics {
				for _, point := range metric.Sum.DataPoints {
					values = append(values, point.AsInt)
				}
			}
			mu.Unlock()
		}
		ack(w)
	}))
	defer server.Close()
	c := testConfig(server.URL)
	c.Signals, c.BatchSize = []string{"metrics"}, 2
	m := sampleMetrics()[0]
	point := m.Sum.DataPoints[0]
	m.Sum.DataPoints = []NumberPoint{point, point, point, point, point}
	e, err := New(c, func(context.Context) ([]Metric, error) { return []Metric{m}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(values) != 5 || e.Stats().Signals["metrics"].FullBatches != 3 {
		t.Fatal("metric point batch boundaries invalid")
	}
	for _, value := range values {
		if value != "9007199254740993" {
			t.Fatal("metric value changed during batching")
		}
	}
}

func TestExporterByteLimitSplitsLargeLogBatches(t *testing.T) {
	var requests atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if len(data) > 64<<10 {
			t.Error("byte limit exceeded")
		}
		requests.Add(1)
		ack(w)
	}))
	defer server.Close()
	c := testConfig(server.URL)
	c.BatchSize, c.MaxBatchBytes = 128, 64<<10
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	attrs := []Attribute{{"data", strings.Repeat("x", 256)}, {"more", strings.Repeat("y", 256)}}
	for i := 0; i < 128; i++ {
		if !e.Record(Event{Name: "bounded", Source: "host.api", Attributes: attrs}) {
			t.Fatal("bounded event not admitted")
		}
	}
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() < 2 || e.Stats().Signals["logs"].ExportedRecords != 128 {
		t.Fatal("large batch was not split without loss")
	}
}

func TestExporterPeriodicMetricsAndCallbackFailureContainment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ack(w) }))
	defer server.Close()
	c := testConfig(server.URL)
	c.IntervalMS, c.Signals = 100, []string{"metrics"}
	var calls atomic.Uint64
	e, err := New(c, func(context.Context) ([]Metric, error) {
		calls.Add(1)
		return sampleMetrics(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	waitFor(t, func() bool { return e.Stats().Signals["metrics"].FullBatches > 0 })
	if calls.Load() == 0 {
		t.Fatal("no periodic source collection")
	}
	bad, err := New(c, func(context.Context) ([]Metric, error) { panic("do-not-log-private-panic-data") })
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, bad)
	waitFor(t, func() bool { return bad.Stats().InternalErrors != 0 })
	if bad.Close(context.Background()) == nil || bad.Record(Event{Name: "after-failure", Source: "host.api"}) {
		t.Fatal("callback panic did not stop/reject exporter safely")
	}
	encoded, _ := json.Marshal(bad.Stats())
	if strings.Contains(string(encoded), "private-panic") {
		t.Fatal("private panic details escaped counters")
	}
}

func TestExporterInvalidMetricsAreNotSent(t *testing.T) {
	var requests atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); ack(w) }))
	defer server.Close()
	c := testConfig(server.URL)
	c.Signals = []string{"metrics"}
	e, err := New(c, func(context.Context) ([]Metric, error) { return []Metric{{Name: "bad-type"}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if e.Close(context.Background()) == nil || requests.Load() != 0 || e.Stats().CollectionErrors != 1 {
		t.Fatal("invalid metric source was exported or uncounted")
	}
}
