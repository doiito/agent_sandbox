package otlp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSource is called only by the worker. It must honor cancellation and
// return immutable data owned by this snapshot (not application live slices).
type MetricsSource func(context.Context) ([]Metric, error)

// EventLossStats partitions DroppedEvents. Unencoded counts previously admitted
// events; the other fields count rejected admission. Encoded signal loss is
// reported separately in Signals and must not be counted once per event again.
type EventLossStats struct {
	Invalid   uint64 `json:"invalid"`
	QueueFull uint64 `json:"queue_full"`
	Closed    uint64 `json:"closed"`
	Unencoded uint64 `json:"unencoded"`
}

type Stats struct {
	AcceptedEvents   uint64                 `json:"accepted_events"`
	DroppedEvents    uint64                 `json:"dropped_events"`
	EventLoss        EventLossStats         `json:"event_loss"`
	SampledOutTraces uint64                 `json:"sampled_out_traces"`
	CollectionErrors uint64                 `json:"collection_errors"`
	InternalErrors   uint64                 `json:"internal_errors"`
	QueueDepth       int                    `json:"queue_depth"`
	QueueCapacity    int                    `json:"queue_capacity"`
	Signals          map[string]SignalStats `json:"signals"`
}

type Exporter struct {
	config     Config
	instanceID string
	urls       [3]string
	enabled    [3]bool
	client     *http.Client
	token      string
	source     MetricsSource
	sent       [3]signalCounters
	offered    atomic.Uint64
	dropped    atomic.Uint64
	invalid    atomic.Uint64
	queueFull  atomic.Uint64
	closed     atomic.Uint64
	unencoded  atomic.Uint64
	sampled    atomic.Uint64
	sequence   atomic.Uint64
	collection atomic.Uint64
	internal   atomic.Uint64
	queue      chan queuedEvent
	wake       chan struct{}
	stop       chan struct{}
	done       chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	admission  sync.RWMutex
	closing    bool
	closeOnce  sync.Once
	result     error // published by closing done
}

func New(config Config, source MetricsSource) (*Exporter, error) {
	config = config.normalized()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	client, token, err := newHTTPClient(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{config: config, client: client, token: token, source: source,
		queue: make(chan queuedEvent, config.QueueCapacity), wake: make(chan struct{}, 1),
		stop: make(chan struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	for _, name := range config.Signals {
		e.enabled[signalIndex(name)] = true
	}
	if e.enabled[0] && source == nil {
		cancel()
		client.CloseIdleConnections()
		return nil, errors.New("OTLP metrics require a snapshot source")
	}
	e.instanceID = config.InstanceID
	if e.instanceID == "" {
		var value [16]byte
		if _, err := rand.Read(value[:]); err != nil {
			cancel()
			client.CloseIdleConnections()
			return nil, errors.New("OTLP instance identity unavailable")
		}
		e.instanceID = hex.EncodeToString(value[:])
	}
	base, _ := config.endpoint()
	for index, signal := range signals {
		endpoint := *base
		endpoint.Path = strings.TrimSuffix(base.Path, "/") + "/v1/" + signal
		e.urls[index] = endpoint.String()
	}
	go e.run()
	return e, nil
}

// Record copies only bounded metadata, never performs IO, and never waits for
// queue capacity. The adapter is responsible for excluding secrets/raw bodies.
func (e *Exporter) Record(event Event) bool {
	if e == nil {
		return false
	}
	value, valid := event.normalized()
	if !valid {
		e.invalid.Add(1)
		e.dropped.Add(1)
		return false
	}
	trace := e.enabled[2] && e.sequence.Add(1)%1000 < uint64(*e.config.TraceSamplePermille)
	if e.enabled[2] && !trace {
		e.sampled.Add(1)
	}
	if !e.enabled[1] && !trace {
		return false
	}
	e.admission.RLock()
	defer e.admission.RUnlock()
	if e.closing {
		e.closed.Add(1)
		e.dropped.Add(1)
		return false
	}
	select {
	case e.queue <- queuedEvent{Event: value, trace: trace}:
		e.offered.Add(1)
		if len(e.queue) >= e.config.BatchSize {
			e.signalWake()
		}
		return true
	default:
		e.queueFull.Add(1)
		e.dropped.Add(1)
		return false
	}
}

func (e *Exporter) signalWake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Exporter) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	value := Stats{AcceptedEvents: e.offered.Load(), DroppedEvents: e.dropped.Load(), SampledOutTraces: e.sampled.Load(),
		EventLoss:        EventLossStats{Invalid: e.invalid.Load(), QueueFull: e.queueFull.Load(), Closed: e.closed.Load(), Unencoded: e.unencoded.Load()},
		CollectionErrors: e.collection.Load(), InternalErrors: e.internal.Load(), QueueDepth: len(e.queue),
		QueueCapacity: cap(e.queue), Signals: make(map[string]SignalStats, len(signals))}
	for index, name := range signals {
		value.Signals[name] = e.sent[index].snapshot()
	}
	return value
}

// Close linearizes admission, requests a final bounded flush, and joins the
// worker. Cancellation stops IO; a non-nil error never promises full delivery.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.admission.Lock()
		e.closing = true
		e.admission.Unlock()
		close(e.stop)
	})
	select {
	case <-e.done:
		return e.result
	default:
	}
	select {
	case <-e.done:
		return e.result
	case <-ctx.Done():
		e.cancel()
		return ctx.Err()
	}
}

// Done closes only after the worker has actually exited and closed idle IO.
func (e *Exporter) Done() <-chan struct{} { return e.done }

func (e *Exporter) run() {
	defer func() {
		if recover() != nil {
			e.internal.Add(1)
		}
		e.admission.Lock()
		e.closing = true
		e.admission.Unlock()
		for len(e.queue) != 0 {
			<-e.queue
			e.unencoded.Add(1)
			e.dropped.Add(1)
		}
		e.cancel()
		e.client.CloseIdleConnections()
		state := e.Stats()
		loss := state.DroppedEvents != 0 || state.CollectionErrors != 0 || state.InternalErrors != 0
		for _, signal := range state.Signals {
			loss = loss || signal.DroppedRecords != 0 || signal.FailedBatches != 0
		}
		if loss {
			e.result = errors.New("OTLP stopped with recorded data loss; inspect counters")
		}
		close(e.done)
	}()
	interval := time.Duration(e.config.IntervalMS) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	nextMetrics := time.Now().Add(interval)
	for {
		select {
		case <-e.stop:
			final, cancel := context.WithTimeout(e.ctx, time.Duration(e.config.TimeoutMS)*time.Millisecond)
			for len(e.queue) != 0 && final.Err() == nil {
				e.flushEvents(final)
			}
			if e.enabled[0] && final.Err() == nil {
				e.flushMetrics(final)
			}
			cancel()
			return
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.flushEvents(e.ctx)
			if e.enabled[0] {
				e.flushMetrics(e.ctx)
			}
			nextMetrics = time.Now().Add(interval)
		case <-e.wake:
			e.flushEvents(e.ctx)
			if e.enabled[0] && !time.Now().Before(nextMetrics) {
				e.flushMetrics(e.ctx)
				nextMetrics = time.Now().Add(interval)
			}
		}
	}
}

func traceIdentity() (string, string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil || bytes.Equal(value[:16], make([]byte, 16)) || bytes.Equal(value[16:], make([]byte, 8)) {
		return "", "", errors.New("OTLP trace identity unavailable")
	}
	return hex.EncodeToString(value[:16]), hex.EncodeToString(value[16:]), nil
}

func (e *Exporter) flushEvents(parent context.Context) {
	batch := make([]preparedEvent, 0, e.config.BatchSize)
	for len(batch) < e.config.BatchSize {
		select {
		case item := <-e.queue:
			value := preparedEvent{Event: item.Event}
			if item.trace {
				trace, span, err := traceIdentity()
				if err != nil {
					e.unencoded.Add(1)
					e.dropped.Add(1)
					continue
				}
				value.TraceID, value.SpanID = trace, span
			}
			batch = append(batch, value)
		default:
			goto drained
		}
	}
drained:
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(e.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	if e.enabled[1] {
		logs := make([]wireLog, 0, len(batch))
		for _, item := range batch {
			value := wireLog{TimeUnixNano: nanos(item.End), ObservedTimeUnixNano: nanos(time.Now()),
				SeverityNumber: 9, SeverityText: "INFO", Body: map[string]string{"stringValue": item.Name},
				Attributes: item.attributes(), TraceID: item.TraceID, SpanID: item.SpanID}
			if item.Failed {
				value.SeverityNumber, value.SeverityText = 17, "ERROR"
			}
			if item.TraceID != "" {
				value.Flags = 1
			}
			logs = append(logs, value)
		}
		e.sendLogs(ctx, logs)
	}
	if e.enabled[2] {
		var spans []wireSpan
		for _, item := range batch {
			if item.TraceID == "" {
				continue
			}
			value := wireSpan{TraceID: item.TraceID, SpanID: item.SpanID, Name: item.Name, Kind: item.Kind,
				StartTimeUnixNano: nanos(item.Start), EndTimeUnixNano: nanos(item.End), Attributes: item.attributes(), Flags: 1}
			if item.Failed {
				value.Status = map[string]int{"code": 2}
			}
			spans = append(spans, value)
		}
		if len(spans) != 0 {
			e.sendSpans(ctx, spans)
		}
	}
	if len(e.queue) >= e.config.BatchSize {
		e.signalWake()
	}
}

func (e *Exporter) sendLogs(ctx context.Context, batch []wireLog) {
	if ctx.Err() != nil {
		e.sent[1].failed.Add(1)
		e.sent[1].dropped.Add(uint64(len(batch)))
		return
	}
	body, err := json.Marshal(e.envelope("logs", batch))
	if err == nil && len(body) > e.config.MaxBatchBytes && len(batch) > 1 {
		e.sendLogs(ctx, batch[:len(batch)/2])
		e.sendLogs(ctx, batch[len(batch)/2:])
		return
	}
	if err != nil {
		e.sent[1].failed.Add(1)
		e.sent[1].dropped.Add(uint64(len(batch)))
		return
	}
	e.send(ctx, 1, body, uint64(len(batch)))
}

func (e *Exporter) sendSpans(ctx context.Context, batch []wireSpan) {
	if ctx.Err() != nil {
		e.sent[2].failed.Add(1)
		e.sent[2].dropped.Add(uint64(len(batch)))
		return
	}
	body, err := json.Marshal(e.envelope("traces", batch))
	if err == nil && len(body) > e.config.MaxBatchBytes && len(batch) > 1 {
		e.sendSpans(ctx, batch[:len(batch)/2])
		e.sendSpans(ctx, batch[len(batch)/2:])
		return
	}
	if err != nil {
		e.sent[2].failed.Add(1)
		e.sent[2].dropped.Add(uint64(len(batch)))
		return
	}
	e.send(ctx, 2, body, uint64(len(batch)))
}

func (e *Exporter) flushMetrics(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(e.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	metrics, err := e.source(ctx)
	if err != nil || len(metrics) > 128 {
		e.collection.Add(1)
		return
	}
	counts, total := make([]int, len(metrics)), 0
	for index, metric := range metrics {
		count, err := metric.validate()
		if err != nil {
			e.collection.Add(1)
			return
		}
		counts[index] = count
		total += count
		if total > 100000 {
			e.collection.Add(1)
			return
		}
	}
	batch, size, processed := []Metric{}, 0, 0
	for index, metric := range metrics {
		for offset := 0; offset < counts[index]; {
			if ctx.Err() != nil {
				e.sent[0].failed.Add(1)
				e.sent[0].dropped.Add(uint64(total - processed))
				return
			}
			count := min(counts[index]-offset, e.config.BatchSize-size)
			batch = append(batch, metric.subset(offset, offset+count))
			size += count
			offset += count
			if size == e.config.BatchSize {
				e.sendMetrics(ctx, batch)
				processed += size
				batch, size = nil, 0
			}
		}
	}
	if size != 0 {
		e.sendMetrics(ctx, batch)
	}
}

func (e *Exporter) sendMetrics(ctx context.Context, batch []Metric) {
	count := 0
	for _, item := range batch {
		size, _ := item.validate()
		count += size
	}
	if ctx.Err() != nil {
		e.sent[0].failed.Add(1)
		e.sent[0].dropped.Add(uint64(count))
		return
	}
	body, err := json.Marshal(e.envelope("metrics", batch))
	if err == nil && len(body) > e.config.MaxBatchBytes && count > 1 {
		if len(batch) > 1 {
			e.sendMetrics(ctx, batch[:len(batch)/2])
			e.sendMetrics(ctx, batch[len(batch)/2:])
		} else {
			e.sendMetrics(ctx, []Metric{batch[0].subset(0, count/2)})
			e.sendMetrics(ctx, []Metric{batch[0].subset(count/2, count)})
		}
		return
	}
	if err != nil {
		e.sent[0].failed.Add(1)
		e.sent[0].dropped.Add(uint64(count))
		return
	}
	e.send(ctx, 0, body, uint64(count))
}
