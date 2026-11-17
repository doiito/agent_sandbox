package otlp

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleMetrics() []Metric {
	start, at := time.Unix(100, 0), time.Unix(101, 0)
	return []Metric{
		{Name: "osv_sandbox_jobs_total", Unit: "{job}", Sum: &Sum{AggregationTemporality: 2, IsMonotonic: true,
			DataPoints: []NumberPoint{UintPoint(9007199254740993, start, at, Attribute{"tenant", "tenant-a"})}}},
		{Name: "osv_sandbox_jobs_inflight", Gauge: &Gauge{DataPoints: []NumberPoint{IntPoint(2, time.Time{}, at)}}},
		{Name: "osv_sandbox_job_duration_milliseconds", Unit: "ms", Histogram: &Histogram{AggregationTemporality: 2,
			DataPoints: []HistogramPoint{HistogramSample(3, 7, []float64{1, 5}, []uint64{1, 1, 1}, start, at)}}},
	}
}

func TestWireExactInt64AndUnsignedCounterOverflowRepresentation(t *testing.T) {
	point := sampleMetrics()[0].Sum.DataPoints[0]
	data, err := json.Marshal(point)
	if err != nil || !strings.Contains(string(data), `"asInt":"9007199254740993"`) || strings.Contains(string(data), "time_unix_nano") {
		t.Fatalf("integer precision or field naming invalid: %s", data)
	}
	large := UintPoint(math.MaxUint64, time.Unix(100, 0), time.Unix(101, 0))
	if large.AsInt != nil || large.AsDouble == nil || *large.AsDouble <= 0 {
		t.Fatal("uint64 outside signed protobuf range was not mapped to double")
	}
	for _, metric := range sampleMetrics() {
		if count, err := metric.validate(); err != nil || count != 1 {
			t.Fatalf("valid sample rejected: %d %v", count, err)
		}
	}
}

func TestWireRejectsInvalidMetricPoints(t *testing.T) {
	mutations := []func([]Metric){
		func(m []Metric) { m[0].Name = "" },
		func(m []Metric) { m[0].Gauge = m[1].Gauge },
		func(m []Metric) { m[0].Sum.AggregationTemporality = 1 },
		func(m []Metric) { m[0].Sum.DataPoints[0].StartTimeUnixNano = "" },
		func(m []Metric) { m[0].Sum.DataPoints[0].TimeUnixNano = "1" },
		func(m []Metric) { value := "-1"; m[0].Sum.DataPoints[0].AsInt = &value },
		func(m []Metric) { value := "9223372036854775808"; m[0].Sum.DataPoints[0].AsInt = &value },
		func(m []Metric) {
			value := math.NaN()
			m[1].Gauge.DataPoints[0].AsInt = nil
			m[1].Gauge.DataPoints[0].AsDouble = &value
		},
		func(m []Metric) { m[2].Histogram.DataPoints[0].Count = "4" },
		func(m []Metric) {
			m[2].Histogram.DataPoints[0].BucketCounts = []string{"18446744073709551615", "1", "0"}
		},
		func(m []Metric) { m[2].Histogram.DataPoints[0].ExplicitBounds = []float64{5, 1} },
		func(m []Metric) { m[2].Histogram.DataPoints[0].ExplicitBounds[0] = math.Inf(1) },
	}
	for index, mutate := range mutations {
		metrics := sampleMetrics()
		mutate(metrics)
		invalid := false
		for _, metric := range metrics {
			_, err := metric.validate()
			invalid = invalid || err != nil
		}
		if !invalid {
			t.Errorf("invalid metric mutation %d accepted", index)
		}
	}
}

func TestWireHistogramCountsAreNoncumulativeAndPrecise(t *testing.T) {
	point := HistogramSample(math.MaxUint64, 0, []float64{}, []uint64{math.MaxUint64}, time.Unix(100, 0), time.Unix(101, 0))
	m := Metric{Name: "large_histogram", Histogram: &Histogram{AggregationTemporality: 2, DataPoints: []HistogramPoint{point}}}
	if _, err := m.validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(point)
	if err != nil || !strings.Contains(string(data), `"count":"18446744073709551615"`) || !strings.Contains(string(data), `"bucketCounts":["18446744073709551615"]`) {
		t.Fatal("uint64 histogram count lost precision")
	}
	if m.subset(0, 1).Histogram.DataPoints[0].Count != strconv.FormatUint(math.MaxUint64, 10) {
		t.Fatal("batch slicing changed cumulative values")
	}
}

func TestWireEventProvenanceAndBounds(t *testing.T) {
	base := Event{Name: "api.request.complete", Source: "guest.reported", Attributes: []Attribute{{"tenant", "tenant-a"}}}
	value, ok := base.normalized()
	if !ok || value.Kind != 1 || value.End.IsZero() || value.Start.IsZero() {
		t.Fatal("valid event rejected")
	}
	base.Attributes[0].Value = "changed-after-record"
	if value.Attributes[0].Value != "tenant-a" {
		t.Fatal("event metadata was not copied")
	}
	bad := []Event{
		{Name: "x", Source: "pretend-root"}, {Name: "x\nsecret", Source: "host.api"},
		{Name: "x", Source: "host.api", Kind: 6},
		{Name: "x", Source: "host.api", Start: time.Unix(101, 0), End: time.Unix(100, 0)},
		{Name: "x", Source: "host.api", Attributes: []Attribute{{"a", "one"}, {"a", "two"}}},
		{Name: "x", Source: "host.api", Attributes: []Attribute{{"osv.observation.source", "host.launcher.audit"}}},
		{Name: "x", Source: "host.api", Attributes: []Attribute{{"value", strings.Repeat("x", 257)}}},
		{Name: "x", Source: "host.api", Attributes: make([]Attribute, 17)},
	}
	for index, event := range bad {
		if _, ok := event.normalized(); ok {
			t.Errorf("invalid event %d accepted", index)
		}
	}
}

func TestSuccessResponsePartialWarningsAndUnknownFields(t *testing.T) {
	for index, field := range []string{"rejectedDataPoints", "rejectedLogRecords", "rejectedSpans"} {
		for _, encoded := range []string{`"2"`, `2`} {
			partial, count, err := parseSuccess([]byte(`{"future":{"value":true},"partialSuccess":{"`+field+`":`+encoded+`,"errorMessage":"private-peer-message"}}`), index, 3)
			if err != nil || !partial || count != 2 {
				t.Fatal("valid partial result not recognized")
			}
		}
	}
	partial, count, err := parseSuccess([]byte(`{"partialSuccess":{"errorMessage":"warning-only"}}`), 1, 3)
	if err != nil || !partial || count != 0 {
		t.Fatal("warning-only partial response not recognized")
	}
	partial, count, err = parseSuccess([]byte(`{"futureField":[1,2]}`), 1, 3)
	if err != nil || partial || count != 0 {
		t.Fatal("unknown response fields not ignored")
	}
}

func TestSuccessResponseRejectsFalseAcknowledgements(t *testing.T) {
	for _, data := range []string{"", "null", "[]", "{} {}", `{"partialSuccess":{},"partialSuccess":null}`, `{"partialSuccess":{"rejectedSpans":"-1"}}`, `{"partialSuccess":{"rejectedSpans":"4"}}`, `{"partialSuccess":{"rejectedSpans":"1.5"}}`, `{"partialSuccess":{"errorMessage":true}}`, `{"partialSuccess":{"rejectedSpans":"1","rejectedSpans":"0"}}`} {
		if _, _, err := parseSuccess([]byte(data), 2, 3); err == nil {
			t.Errorf("malformed success %q accepted", data)
		}
	}
}

func TestSuccessResponseEmptyPartialHasNoWarningOrRejection(t *testing.T) {
	for index, field := range []string{"rejectedDataPoints", "rejectedLogRecords", "rejectedSpans"} {
		for _, body := range []string{`{}`, `{"partialSuccess":null}`, `{"partialSuccess":{}}`,
			`{"partialSuccess":{"errorMessage":""}}`, `{"partialSuccess":{"future":true}}`,
			`{"partialSuccess":{"` + field + `":"0","errorMessage":""}}`, `{"partialSuccess":{"` + field + `":0}}`} {
			partial, rejected, err := parseSuccess([]byte(body), index, 3)
			if err != nil || partial || rejected != 0 {
				t.Errorf("semantically empty acknowledgement classified as a warning for %s: %q", field, body)
			}
		}
		partial, rejected, err := parseSuccess([]byte(`{"partialSuccess":{"`+field+`":"0","errorMessage":"warning"}}`), index, 3)
		if err != nil || !partial || rejected != 0 {
			t.Errorf("nonempty warning lost for %s", field)
		}
	}
}
