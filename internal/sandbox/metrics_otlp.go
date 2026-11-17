package sandbox

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

func observationAttributes(source string) []otlp.Attribute {
	return []otlp.Attribute{{Key: "osv.observation.source", Value: source}}
}

func (s metricsSnapshot) otlpMetrics() []otlp.Metric {
	attrs := observationAttributes("host.api")
	sum := func(name, unit string, value uint64) otlp.Metric {
		return otlp.Metric{Name: name, Unit: unit, Sum: &otlp.Sum{AggregationTemporality: 2, IsMonotonic: true,
			DataPoints: []otlp.NumberPoint{otlp.UintPoint(value, s.started, s.at, attrs...)}}}
	}
	metrics := []otlp.Metric{
		sum("osv_sandbox_http_requests_total", "{request}", s.httpRequests),
		sum("osv_sandbox_auth_failures_total", "{request}", s.authFailures),
		{Name: "osv_sandbox_jobs_inflight", Gauge: &otlp.Gauge{DataPoints: []otlp.NumberPoint{
			otlp.IntPoint(s.inflight, time.Time{}, s.at, attrs...)}}},
	}
	keys := make([]string, 0, len(s.jobs))
	for key := range s.jobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	jobs := &otlp.Sum{AggregationTemporality: 2, IsMonotonic: true}
	for _, key := range keys {
		tenant, state, _ := strings.Cut(key, "\x00")
		tags := append(observationAttributes("host.api"), otlp.Attribute{Key: "tenant", Value: tenant}, otlp.Attribute{Key: "state", Value: state})
		jobs.DataPoints = append(jobs.DataPoints, otlp.UintPoint(s.jobs[key], s.started, s.at, tags...))
	}
	metrics = append(metrics, otlp.Metric{Name: "osv_sandbox_jobs_total", Unit: "{job}", Sum: jobs})
	bounds := make([]float64, len(metricBucketsMS))
	buckets := append([]uint64(nil), s.buckets[:]...)
	var count uint64
	for index, value := range buckets {
		count += value
		if index < len(bounds) {
			bounds[index] = float64(metricBucketsMS[index])
		}
	}
	metrics = append(metrics, otlp.Metric{Name: "osv_sandbox_job_duration_milliseconds", Unit: "ms",
		Histogram: &otlp.Histogram{AggregationTemporality: 2, DataPoints: []otlp.HistogramPoint{
			otlp.HistogramSample(count, float64(s.durationMS), bounds, buckets, s.started, s.at, attrs...)}}})
	return metrics
}

type exporterCounter struct {
	name  string
	value uint64
	tags  []otlp.Attribute
}

func exporterCounters(state otlp.Stats) []exporterCounter {
	values := []exporterCounter{
		{"osv_sandbox_otlp_events_accepted_total", state.AcceptedEvents, nil},
		{"osv_sandbox_otlp_traces_sampled_out_total", state.SampledOutTraces, nil},
		{"osv_sandbox_otlp_collection_errors_total", state.CollectionErrors, nil},
		{"osv_sandbox_otlp_internal_errors_total", state.InternalErrors, nil},
	}
	for _, row := range []struct {
		reason string
		count  uint64
	}{{"invalid", state.EventLoss.Invalid}, {"queue_full", state.EventLoss.QueueFull}, {"closed", state.EventLoss.Closed}, {"unencoded", state.EventLoss.Unencoded}} {
		values = append(values, exporterCounter{"osv_sandbox_otlp_event_drops_total", row.count, []otlp.Attribute{{Key: "reason", Value: row.reason}}})
	}
	for _, name := range []string{"metrics", "logs", "traces"} {
		signal := state.Signals[name]
		for _, row := range []struct {
			name  string
			count uint64
		}{{"requests", signal.Requests}, {"retries", signal.Retries}, {"full_batches", signal.FullBatches},
			{"partial_batches", signal.PartialBatches}, {"failed_batches", signal.FailedBatches},
			{"exported_records", signal.ExportedRecords}, {"rejected_records", signal.RejectedRecords}, {"dropped_records", signal.DroppedRecords}} {
			values = append(values, exporterCounter{"osv_sandbox_otlp_" + row.name + "_total", row.count, []otlp.Attribute{{Key: "signal", Value: name}}})
		}
	}
	return values
}

func exporterOTLPMetrics(state otlp.Stats, start, at time.Time) []otlp.Metric {
	var metrics []otlp.Metric
	byName := map[string]*otlp.Sum{}
	for _, row := range exporterCounters(state) {
		series := byName[row.name]
		if series == nil {
			series = &otlp.Sum{AggregationTemporality: 2, IsMonotonic: true}
			byName[row.name] = series
			metrics = append(metrics, otlp.Metric{Name: row.name, Sum: series})
		}
		attrs := append(observationAttributes("host.api"), row.tags...)
		series.DataPoints = append(series.DataPoints, otlp.UintPoint(row.value, start, at, attrs...))
	}
	for _, row := range []struct {
		name  string
		value int
	}{{"osv_sandbox_otlp_queue_depth", state.QueueDepth}, {"osv_sandbox_otlp_queue_capacity", state.QueueCapacity}} {
		metrics = append(metrics, otlp.Metric{Name: row.name, Gauge: &otlp.Gauge{DataPoints: []otlp.NumberPoint{
			otlp.IntPoint(int64(row.value), time.Time{}, at, observationAttributes("host.api")...)}}})
	}
	return metrics
}

func writeOTLPExporterMetrics(writer io.Writer, state otlp.Stats) {
	seen := map[string]bool{}
	for _, row := range exporterCounters(state) {
		if !seen[row.name] {
			fmt.Fprintf(writer, "# TYPE %s counter\n", row.name)
			seen[row.name] = true
		}
		fmt.Fprint(writer, row.name)
		if len(row.tags) != 0 {
			fmt.Fprintf(writer, "{%s=%q}", row.tags[0].Key, row.tags[0].Value)
		}
		fmt.Fprintf(writer, " %d\n", row.value)
	}
	fmt.Fprintf(writer, "# TYPE osv_sandbox_otlp_queue_depth gauge\nosv_sandbox_otlp_queue_depth %d\n", state.QueueDepth)
	fmt.Fprintf(writer, "# TYPE osv_sandbox_otlp_queue_capacity gauge\nosv_sandbox_otlp_queue_capacity %d\n", state.QueueCapacity)
}

func (a *API) otlpMetrics(ctx context.Context) ([]otlp.Metric, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := a.metrics.snapshot()
	metrics := snapshot.otlpMetrics()
	if exporter := a.telemetry.Load(); exporter != nil {
		metrics = append(metrics, exporterOTLPMetrics(exporter.Stats(), snapshot.started, time.Now())...)
	}
	if source, ok := a.runner.(interface {
		WarmPoolStatusContext(context.Context) (WarmPoolSnapshot, error)
	}); ok {
		// A source must honor cancellation. No background goroutine is used to
		// hide a blocking legacy call, and one unavailable pool does not erase
		// the already captured API metrics.
		status, err := source.WarmPoolStatusContext(ctx)
		at := time.Now()
		available := int64(0)
		if err == nil {
			available = 1
			origin := "host.api"
			switch a.runner.(type) {
			case LauncherClient, *LauncherClient:
				origin = "host.launcher"
			}
			metrics = append(metrics, poolOTLPMetrics(status, at, origin)...)
		}
		metrics = append(metrics, otlp.Metric{Name: "osv_sandbox_warm_pool_snapshot_available", Gauge: &otlp.Gauge{
			DataPoints: []otlp.NumberPoint{otlp.IntPoint(available, time.Time{}, at, observationAttributes("host.api")...)}}})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return metrics, nil
}

func poolOTLPMetrics(snapshot WarmPoolSnapshot, at time.Time, source string) []otlp.Metric {
	var metrics []otlp.Metric
	add := func(name string, value uint64, tags ...otlp.Attribute) {
		attrs := append(observationAttributes(source), tags...)
		metrics = append(metrics, otlp.Metric{Name: name, Gauge: &otlp.Gauge{DataPoints: []otlp.NumberPoint{
			otlp.UintPoint(value, time.Time{}, at, attrs...)}}})
	}
	bit := func(value bool) uint64 {
		if value {
			return 1
		}
		return 0
	}
	add("osv_sandbox_warm_pool_enabled", bit(snapshot.Enabled))
	add("osv_sandbox_warm_pool_healthy", bit(snapshot.Healthy))
	add("osv_sandbox_warm_pool_memory_pressure", bit(snapshot.MemoryPressure))
	// Launcher lifetime is independent of the API lifetime. Until its origin
	// is in the protocol, observed counts are gauges, never false cumulative
	// sums with the API process start timestamp.
	add("osv_sandbox_warm_pool_hits_observed", snapshot.Hits)
	add("osv_sandbox_warm_pool_refill_failures_observed", snapshot.RefillFailures)
	profiles := map[string]*otlp.Gauge{}
	for _, profile := range snapshot.Profiles {
		if !safeTenantID(profile.Name) || !validSHA256Hex(profile.Key) {
			continue
		}
		tags := []otlp.Attribute{{Key: "profile", Value: profile.Name}, {Key: "pool.key", Value: profile.Key}}
		if safeTenantID(profile.TemplateID) {
			tags = append(tags, otlp.Attribute{Key: "template", Value: profile.TemplateID})
		}
		switch profile.Backend {
		case "firecracker-linux", "firecracker-osv":
			tags = append(tags, otlp.Attribute{Key: "backend", Value: profile.Backend})
		}
		for _, row := range []struct {
			name  string
			value int
		}{{"ready", profile.Ready}, {"booting", profile.Booting}, {"desired", profile.Desired}} {
			name := "osv_sandbox_warm_pool_" + row.name
			gauge := profiles[name]
			if gauge == nil {
				gauge = &otlp.Gauge{}
				profiles[name] = gauge
				metrics = append(metrics, otlp.Metric{Name: name, Gauge: gauge})
			}
			attrs := append(observationAttributes(source), tags...)
			gauge.DataPoints = append(gauge.DataPoints, otlp.IntPoint(int64(row.value), time.Time{}, at, attrs...))
		}
	}
	for _, group := range []struct {
		name   string
		values map[string]uint64
	}{{"misses", snapshot.Misses}, {"discarded", snapshot.Discarded}} {
		counts := map[string]uint64{}
		for reason, count := range group.values {
			switch reason {
			case "empty", "profile_mismatch", "dead", "unhealthy", "lifetime", "prepare_not_sent", "foreground", "minimum_rebalance", "audit", "template_invalid", "memory_pressure", "idle_expired":
			default:
				reason = "other"
			}
			counts[reason] += count
		}
		keys := make([]string, 0, len(counts))
		for reason := range counts {
			keys = append(keys, reason)
		}
		sort.Strings(keys)
		// Keep each definition once, with one point per bounded reason.
		gauge := &otlp.Gauge{}
		for _, reason := range keys {
			attrs := append(observationAttributes(source), otlp.Attribute{Key: "reason", Value: reason})
			gauge.DataPoints = append(gauge.DataPoints, otlp.UintPoint(counts[reason], time.Time{}, at, attrs...))
		}
		metrics = append(metrics, otlp.Metric{Name: "osv_sandbox_warm_pool_" + group.name + "_observed", Gauge: gauge})
	}
	return metrics
}
