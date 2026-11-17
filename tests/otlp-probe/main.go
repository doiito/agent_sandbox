// otlp-probe exercises the actual asynchronous exporter against an independent collector.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

func main() {
	endpoint := flag.String("endpoint", "", "explicit collector origin")
	ca := flag.String("ca", "", "collector CA PEM")
	cert := flag.String("cert", "", "client certificate PEM")
	key := flag.String("key", "", "private client key")
	output := flag.String("output", "", "new result JSON")
	flag.Parse()
	start := time.Now().Add(-time.Second)
	config := otlp.Config{Endpoint: *endpoint, CAFile: *ca, ClientCertFile: *cert, ClientKeyFile: *key,
		ServiceName: "osv-sandbox-otlp-probe", InstanceID: "independent-collector-check", IntervalMS: 60000}
	source := func(ctx context.Context) ([]otlp.Metric, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at := time.Now()
		attrs := []otlp.Attribute{{Key: "tenant", Value: "tenant-a"}, {Key: "osv.observation.source", Value: "host.api"}}
		return []otlp.Metric{
			{Name: "osv_sandbox_jobs_total", Unit: "{job}", Sum: &otlp.Sum{AggregationTemporality: 2, IsMonotonic: true,
				DataPoints: []otlp.NumberPoint{otlp.UintPoint(9007199254740993, start, at, attrs...)}}},
			{Name: "osv_sandbox_jobs_inflight", Gauge: &otlp.Gauge{DataPoints: []otlp.NumberPoint{otlp.IntPoint(2, time.Time{}, at, attrs...)}}},
			{Name: "osv_sandbox_uint64_counter_double", Sum: &otlp.Sum{AggregationTemporality: 2, IsMonotonic: true,
				DataPoints: []otlp.NumberPoint{otlp.UintPoint(math.MaxUint64, start, at, attrs...)}}},
			{Name: "osv_sandbox_job_duration_milliseconds", Unit: "ms", Histogram: &otlp.Histogram{AggregationTemporality: 2,
				DataPoints: []otlp.HistogramPoint{otlp.HistogramSample(math.MaxUint64, 0, []float64{1}, []uint64{math.MaxUint64, 0}, start, at, attrs...)}}},
		}, nil
	}
	exporter, err := otlp.New(config, source)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exporter construction failed")
		os.Exit(1)
	}
	now := time.Now()
	accepted := exporter.Record(otlp.Event{Name: "api.request.complete", Source: "host.api", Kind: 2,
		Start: now.Add(-10 * time.Millisecond), End: now,
		Attributes: []otlp.Attribute{{Key: "tenant", Value: "tenant-a"}, {Key: "http.route", Value: "POST /v2/jobs"}}})
	accepted = exporter.Record(otlp.Event{Name: "guest.resource.sample", Source: "guest.reported", Start: now, End: now,
		Failed: true, Attributes: []otlp.Attribute{{Key: "tenant", Value: "tenant-a"}}}) && accepted
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = exporter.Close(ctx)
	stats := exporter.Stats()
	passed := accepted && err == nil && stats.DroppedEvents == 0 && stats.Signals["metrics"].ExportedRecords == 4 &&
		stats.Signals["logs"].ExportedRecords == 2 && stats.Signals["traces"].ExportedRecords == 2
	result := struct {
		Passed bool       `json:"passed"`
		Stats  otlp.Stats `json:"stats"`
	}{passed, stats}
	file, openErr := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		fmt.Fprintln(os.Stderr, "result file unavailable")
		os.Exit(1)
	}
	encodeErr := json.NewEncoder(file).Encode(result)
	closeErr := file.Close()
	if !passed || encodeErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "OTLP probe did not complete all three signals")
		os.Exit(1)
	}
	fmt.Println("OTLP probe: metrics=4 logs=2 traces=2 accepted")
}
