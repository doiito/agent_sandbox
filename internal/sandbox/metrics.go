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
	started      time.Time
	httpRequests atomic.Uint64
	authFailures atomic.Uint64
	inflight     atomic.Int64
	mu           sync.Mutex
	jobs         map[string]uint64
	buckets      [len(metricBucketsMS) + 1]uint64
	durationMS   uint64
}

func newMetrics() *Metrics { return &Metrics{started: time.Now(), jobs: make(map[string]uint64)} }

type metricsSnapshot struct {
	started, at                time.Time
	httpRequests, authFailures uint64
	inflight                   int64
	jobs                       map[string]uint64
	buckets                    [len(metricBucketsMS) + 1]uint64
	durationMS                 uint64
}

// snapshot owns its map and bucket values. In particular, a slow reader must
// never retain the task accounting lock while writing a response or exporting.
func (m *Metrics) snapshot() metricsSnapshot {
	s := metricsSnapshot{started: m.started, httpRequests: m.httpRequests.Load(),
		authFailures: m.authFailures.Load(), inflight: m.inflight.Load()}
	m.mu.Lock()
	s.jobs = make(map[string]uint64, len(m.jobs))
	for key, value := range m.jobs {
		s.jobs[key] = value
	}
	s.buckets, s.durationMS = m.buckets, m.durationMS
	m.mu.Unlock()
	s.at = time.Now()
	return s
}

func (m *Metrics) recordJob(tenant, state string, duration time.Duration) {
	if !safeTenantID(tenant) {
		tenant = "unknown"
	}
	state = metricJobState(state)
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

func metricJobState(state string) string {
	switch state {
	case "succeeded", "failed", "cancelled", "timed_out", "guest_error", "protocol_error", "rejected", "busy":
		return state
	default:
		return "unknown"
	}
}

func (m *Metrics) writePrometheus(writer io.Writer) {
	s := m.snapshot()
	fmt.Fprintln(writer, "# TYPE osv_sandbox_http_requests_total counter")
	fmt.Fprintf(writer, "osv_sandbox_http_requests_total %d\n", s.httpRequests)
	fmt.Fprintln(writer, "# TYPE osv_sandbox_auth_failures_total counter")
	fmt.Fprintf(writer, "osv_sandbox_auth_failures_total %d\n", s.authFailures)
	fmt.Fprintln(writer, "# TYPE osv_sandbox_jobs_inflight gauge")
	fmt.Fprintf(writer, "osv_sandbox_jobs_inflight %d\n", s.inflight)
	keys := make([]string, 0, len(s.jobs))
	for key := range s.jobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintln(writer, "# TYPE osv_sandbox_jobs_total counter")
	for _, key := range keys {
		separator := 0
		for separator < len(key) && key[separator] != 0 {
			separator++
		}
		fmt.Fprintf(writer, "osv_sandbox_jobs_total{tenant=%q,state=%q} %d\n", key[:separator], key[separator+1:], s.jobs[key])
	}
	fmt.Fprintln(writer, "# TYPE osv_sandbox_job_duration_milliseconds histogram")
	cumulative := uint64(0)
	for index, upper := range metricBucketsMS {
		cumulative += s.buckets[index]
		fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_bucket{le=%q} %d\n", fmt.Sprint(upper), cumulative)
	}
	cumulative += s.buckets[len(metricBucketsMS)]
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_sum %d\n", s.durationMS)
	fmt.Fprintf(writer, "osv_sandbox_job_duration_milliseconds_count %d\n", cumulative)
}
