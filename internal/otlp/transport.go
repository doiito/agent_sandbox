package otlp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var signals = [...]string{"metrics", "logs", "traces"}

func signalIndex(value string) int {
	for index, name := range signals {
		if value == name {
			return index
		}
	}
	return -1
}

type SignalStats struct {
	Requests        uint64 `json:"requests"`
	Retries         uint64 `json:"retries"`
	FullBatches     uint64 `json:"full_batches"`
	PartialBatches  uint64 `json:"partial_batches"`
	FailedBatches   uint64 `json:"failed_batches"`
	ExportedRecords uint64 `json:"exported_records"`
	RejectedRecords uint64 `json:"rejected_records"`
	DroppedRecords  uint64 `json:"dropped_records"`
}

type signalCounters struct {
	requests, retries, full, partial, failed, exported, rejected, dropped atomic.Uint64
}

func (s *signalCounters) snapshot() SignalStats {
	return SignalStats{s.requests.Load(), s.retries.Load(), s.full.Load(), s.partial.Load(),
		s.failed.Load(), s.exported.Load(), s.rejected.Load(), s.dropped.Load()}
}

func responseObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("OTLP response must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || fields[name] != nil {
			return nil, errors.New("invalid or duplicate OTLP response field")
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, errors.New("invalid OTLP response field")
		}
		fields[name] = raw
	}
	if _, err := decoder.Token(); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid OTLP response tail")
	}
	return fields, nil
}

func parseSuccess(body []byte, index int, records uint64) (partial bool, rejected uint64, err error) {
	fields, err := responseObject(body)
	if err != nil {
		return false, 0, errors.New("invalid OTLP success response")
	}
	rawPartial := fields["partialSuccess"]
	if len(rawPartial) == 0 || string(bytes.TrimSpace(rawPartial)) == "null" {
		return false, 0, nil
	}
	fields, err = responseObject(rawPartial)
	if err != nil {
		return false, 0, errors.New("invalid OTLP partial success")
	}
	var warning string
	if message := fields["errorMessage"]; len(message) != 0 {
		if json.Unmarshal(message, &warning) != nil {
			return false, 0, errors.New("invalid OTLP warning")
		}
	}
	raw := fields[[3]string{"rejectedDataPoints", "rejectedLogRecords", "rejectedSpans"}[index]]
	if len(raw) == 0 {
		return warning != "", 0, nil
	}
	value := strings.TrimSpace(string(raw))
	if strings.HasPrefix(value, `"`) {
		if json.Unmarshal(raw, &value) != nil {
			return false, 0, errors.New("invalid OTLP rejection count")
		}
	}
	number, parseErr := strconv.ParseUint(value, 10, 63)
	if parseErr != nil || number > records {
		return false, 0, errors.New("invalid OTLP rejection count")
	}
	// The Collector JSON marshaler can emit an empty partialSuccess object.
	// Like its official HTTP exporter, distinguish actual warnings/rejections
	// from a semantically empty protobuf response; neither case is retried.
	return warning != "" || number != 0, number, nil
}

func retryableNetwork(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return !errors.As(err, &unknown) && !errors.As(err, &invalid) && !errors.As(err, &hostname)
}

func retryDelay(header string, attempt int, now time.Time) time.Duration {
	if header != "" {
		if seconds, err := strconv.ParseUint(header, 10, 31); err == nil {
			return time.Duration(seconds) * time.Second
		}
		if at, err := http.ParseTime(header); err == nil {
			return max(time.Duration(0), at.Sub(now))
		}
	}
	return time.Duration(100*(1<<attempt)) * time.Millisecond * time.Duration(75+rand.IntN(51)) / 100
}

// send acknowledges a consumed batch (including partial success); per-signal
// counters distinguish full delivery, rejection and loss. It never logs bodies.
func (e *Exporter) send(parent context.Context, index int, body []byte, records uint64) bool {
	stats := &e.sent[index]
	fail := func() bool {
		stats.failed.Add(1)
		stats.dropped.Add(records)
		return false
	}
	if len(body) > e.config.MaxBatchBytes {
		return fail()
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(e.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return fail()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.urls[index], bytes.NewReader(body))
		if err != nil {
			return fail()
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "osv-sandbox-otlp/1")
		if e.token != "" {
			request.Header.Set("Authorization", "Bearer "+e.token)
		}
		stats.requests.Add(1)
		if attempt > 0 {
			stats.retries.Add(1)
		}
		response, sendErr := e.client.Do(request)
		retry, after := false, ""
		if sendErr != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			retry = retryableNetwork(sendErr)
		} else {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
			_ = response.Body.Close()
			if len(data) > 64<<10 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
				return fail()
			}
			if readErr != nil {
				retry = true
			} else if response.StatusCode == http.StatusOK {
				media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
				partial, rejected, parseErr := parseSuccess(data, index, records)
				if mediaErr != nil || media != "application/json" || parseErr != nil {
					return fail()
				}
				if partial {
					stats.partial.Add(1)
					stats.rejected.Add(rejected)
					stats.dropped.Add(rejected)
				} else {
					stats.full.Add(1)
				}
				stats.exported.Add(records - rejected)
				return true
			} else {
				retry = response.StatusCode == 429 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504
				after = response.Header.Get("Retry-After")
			}
		}
		if !retry || attempt == 2 {
			return fail()
		}
		delay := retryDelay(after, attempt, time.Now())
		if deadline, ok := ctx.Deadline(); ok && delay >= time.Until(deadline) {
			return fail() // Never retry earlier than the collector asked.
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return fail()
		}
	}
	return fail()
}
