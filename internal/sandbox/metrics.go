package sandbox

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var metricBucketsMS = [...]int64{100, 250, 500, 1000, 2000, 5000, 10_000, 30_000, 60_000, 300_000}

type Metrics struct {
	httpRequests atomic.Uint64
	authFailures atomic.Uint64
	inflight     atomic.Int64
	mu           sync.Mutex
	jobs         map[string]uint64
	buckets      [len(metricBucketsMS) + 1]uint64
	durationMS   uint64
}

func newMetrics() *Metrics { return &Metrics{jobs: make(map[string]uint64)} }

func (m *Metrics) recordJob(tenant, state string, duration time.Duration) {
	if !safeTenantID(tenant) {
		tenant = "unknown"
	}
	switch state {
	case "succeeded", "failed", "timed_out", "guest_error", "protocol_error", "rejected", "busy":
	default:
		state = "unknown"
	}
	milliseconds := duration.Milliseconds()
	m.mu.Lock()
	m.jobs[tenant+"\x00"+state]++
	m.durationMS += uint64(max(milliseconds, 0))
	index := len(metricBucketsMS)
	for i, upper := range metricBucketsMS {
		if milliseconds <= upper {
			index = i
			break
		}
	}
	m.buckets[index]++
	m.mu.Unlock()
}

func (m *Metrics) writePrometheus(writer io.Writer) {
	fmt.Fprintln(writer, "# TYPE osv_sandbox_http_requests_total counter")
	fmt.Fprintf(writer, "osv_sandbox_http_requests_total %d\n", m.httpRequests.Load())
	fmt.Fprintln(writer, "# TYPE osv_sandbox_auth_failures_total counter")
	fmt.Fprintf(writer, "osv_sandbox_auth_failures_total %d\n", m.authFailures.Load())
	fmt.Fprintln(writer, "# TYPE osv_sandbox_jobs_inflight gauge")
	fmt.Fprintf(writer, "osv_sandbox_jobs_inflight %d\n", m.inflight.Load())
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.jobs))
	for key := range m.jobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintln(writer, "# TYPE osv_sandbox_jobs_total counter")
	for _, key := range keys {
		separator := 0
		for separator < len(key) && key[separator] != 0 {
			separator++
		}
		fmt.Fprintf(writer, "osv_sandbox_jobs_total{tenant=%q,state=%q} %d\n", key[:separator], key[separator+1:], m.jobs[key])
	}
	fmt.Fprintln(writer, "# TYPE osv_sandbox_job_duration_milliseconds histogram")
	cumulative := uint64(0)
	for index, upper := range metricBucketsMS {
		cumulative += m.buckets[index]
		fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_bucket{le=%q} %d\n", fmt.Sprint(upper), cumulative)
	}
	cumulative += m.buckets[len(metricBucketsMS)]
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_sum %d\n", m.durationMS)
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_count %d\n", cumulative)
}
