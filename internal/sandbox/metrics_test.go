package sandbox

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

type stalledMetricsWriter struct {
	buffer  bytes.Buffer
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (w *stalledMetricsWriter) Write(data []byte) (int, error) {
	if strings.Contains(string(data), "# TYPE osv_sandbox_jobs_total counter") {
		w.once.Do(func() { close(w.entered); <-w.release })
	}
	return w.buffer.Write(data)
}

func TestMetricsSlowPrometheusWriterDoesNotBlockJobAccounting(t *testing.T) {
	m := newMetrics()
	m.recordJob("tenant-a", "succeeded", 50*time.Millisecond)
	w := &stalledMetricsWriter{entered: make(chan struct{}), release: make(chan struct{})}
	written := make(chan struct{})
	go func() { m.writePrometheus(w); close(written) }()
	defer func() {
		close(w.release)
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Error("stopped writer did not finish after release")
		}
	}()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not reach the job metrics section")
	}
	recorded := make(chan struct{})
	go func() { m.recordJob("tenant-a", "succeeded", 250*time.Millisecond); close(recorded) }()
	select {
	case <-recorded:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow Prometheus client held the job accounting lock")
	}
	if m.snapshot().jobs["tenant-a\x00succeeded"] != 2 {
		t.Fatal("concurrent completed job was lost")
	}
}

func TestMetricsSnapshotOwnsCountersAndHistogram(t *testing.T) {
	m := newMetrics()
	m.httpRequests.Add(3)
	m.authFailures.Add(1)
	m.inflight.Add(2)
	m.recordJob("tenant-a", "succeeded", 50*time.Millisecond)
	first := m.snapshot()
	m.recordJob("tenant-a", "succeeded", 250*time.Millisecond)
	second := m.snapshot()
	if first.jobs["tenant-a\x00succeeded"] != 1 || first.durationMS != 50 || first.buckets[0] != 1 || first.buckets[1] != 0 ||
		second.jobs["tenant-a\x00succeeded"] != 2 || second.durationMS != 300 || second.buckets[0] != 1 || second.buckets[1] != 1 {
		t.Fatal("job counters and raw histogram were aliased or incoherent")
	}
	first.jobs["tenant-a\x00succeeded"], first.buckets[0] = 999, 999
	if current := m.snapshot(); current.jobs["tenant-a\x00succeeded"] != 2 || current.buckets[0] != 1 {
		t.Fatal("snapshot mutation changed live accounting")
	}
	if first.started.IsZero() || first.started != second.started || first.at.Before(first.started) || second.at.Before(first.at) ||
		first.httpRequests != 3 || first.authFailures != 1 || first.inflight != 2 {
		t.Fatal("cumulative origin, capture time or atomic counters invalid")
	}
}
