package otlp

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const scopeName = "github.com/doiito/agent_sandbox/otlp"

var attributePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

type Attribute struct {
	Key   string
	Value string
}

func (a Attribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Key   string            `json:"key"`
		Value map[string]string `json:"value"`
	}{a.Key, map[string]string{"stringValue": a.Value}})
}

func validText(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validAttributes(values []Attribute) bool {
	if len(values) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range values {
		if !attributePattern.MatchString(a.Key) || !validText(a.Value, 256) || seen[a.Key] || a.Key == "osv.observation.source" && !validSource(a.Value) {
			return false
		}
		seen[a.Key] = true
	}
	return true
}

func validSource(value string) bool {
	return value == "host.api" || value == "host.launcher" || value == "host.launcher.audit" || value == "guest.reported"
}

func nanos(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return strconv.FormatInt(at.UnixNano(), 10)
}

func validTimestamp(value string) bool {
	number, err := strconv.ParseUint(value, 10, 64)
	return err == nil && number > 0 && strconv.FormatUint(number, 10) == value
}

type NumberPoint struct {
	Attributes        []Attribute `json:"attributes,omitempty"`
	StartTimeUnixNano string      `json:"startTimeUnixNano,omitempty"`
	TimeUnixNano      string      `json:"timeUnixNano"`
	AsInt             *string     `json:"asInt,omitempty"`
	AsDouble          *float64    `json:"asDouble,omitempty"`
}

// UintPoint retains exact signed-int64-range counters, including values above
// 2^53. OTLP NumberDataPoint has no uint64 variant; larger values use double.
func UintPoint(value uint64, start, at time.Time, attributes ...Attribute) NumberPoint {
	point := NumberPoint{Attributes: attributes, StartTimeUnixNano: nanos(start), TimeUnixNano: nanos(at)}
	if value <= math.MaxInt64 {
		encoded := strconv.FormatUint(value, 10)
		point.AsInt = &encoded
	} else {
		number := float64(value)
		point.AsDouble = &number
	}
	return point
}

func IntPoint(value int64, start, at time.Time, attributes ...Attribute) NumberPoint {
	encoded := strconv.FormatInt(value, 10)
	return NumberPoint{Attributes: attributes, StartTimeUnixNano: nanos(start), TimeUnixNano: nanos(at), AsInt: &encoded}
}

type Gauge struct {
	DataPoints []NumberPoint `json:"dataPoints"`
}

type Sum struct {
	DataPoints             []NumberPoint `json:"dataPoints"`
	AggregationTemporality int           `json:"aggregationTemporality"`
	IsMonotonic            bool          `json:"isMonotonic"`
}

type HistogramPoint struct {
	Attributes        []Attribute `json:"attributes,omitempty"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	TimeUnixNano      string      `json:"timeUnixNano"`
	Count             string      `json:"count"`
	Sum               *float64    `json:"sum,omitempty"`
	BucketCounts      []string    `json:"bucketCounts"`
	ExplicitBounds    []float64   `json:"explicitBounds"`
}

func HistogramSample(count uint64, sum float64, bounds []float64, buckets []uint64, start, at time.Time, attributes ...Attribute) HistogramPoint {
	point := HistogramPoint{Attributes: attributes, StartTimeUnixNano: nanos(start), TimeUnixNano: nanos(at),
		Count: strconv.FormatUint(count, 10), Sum: &sum, ExplicitBounds: append([]float64{}, bounds...)}
	for _, value := range buckets {
		point.BucketCounts = append(point.BucketCounts, strconv.FormatUint(value, 10))
	}
	return point
}

type Histogram struct {
	DataPoints             []HistogramPoint `json:"dataPoints"`
	AggregationTemporality int              `json:"aggregationTemporality"`
}

type Metric struct {
	Name        string     `json:"name"`
	Unit        string     `json:"unit,omitempty"`
	Description string     `json:"description,omitempty"`
	Gauge       *Gauge     `json:"gauge,omitempty"`
	Sum         *Sum       `json:"sum,omitempty"`
	Histogram   *Histogram `json:"histogram,omitempty"`
}

func validTimes(start, at string, cumulative bool) bool {
	if !validTimestamp(at) || cumulative && start == "" {
		return false
	}
	if start == "" {
		return true
	}
	if !validTimestamp(start) {
		return false
	}
	s, _ := strconv.ParseUint(start, 10, 64)
	t, _ := strconv.ParseUint(at, 10, 64)
	return s <= t
}

func (m Metric) validate() (int, error) {
	if m.Name == "" || !validText(m.Name, 128) || !validText(m.Unit, 32) || !validText(m.Description, 256) {
		return 0, errors.New("invalid OTLP metric metadata")
	}
	kinds := 0
	var numbers []NumberPoint
	monotonic, cumulative := false, false
	if m.Gauge != nil {
		kinds++
		numbers = m.Gauge.DataPoints
	}
	if m.Sum != nil {
		kinds++
		numbers, monotonic, cumulative = m.Sum.DataPoints, m.Sum.IsMonotonic, true
		if m.Sum.AggregationTemporality != 2 {
			return 0, errors.New("OTLP sums must use cumulative temporality")
		}
	}
	if m.Histogram != nil {
		kinds++
		if m.Histogram.AggregationTemporality != 2 {
			return 0, errors.New("OTLP histograms must use cumulative temporality")
		}
	}
	if kinds != 1 {
		return 0, errors.New("OTLP metric must have exactly one supported data type")
	}
	for _, p := range numbers {
		if !validAttributes(p.Attributes) || !validTimes(p.StartTimeUnixNano, p.TimeUnixNano, cumulative) || (p.AsInt == nil) == (p.AsDouble == nil) {
			return 0, errors.New("invalid OTLP number point")
		}
		if p.AsInt != nil {
			value, err := strconv.ParseInt(*p.AsInt, 10, 64)
			if err != nil || strconv.FormatInt(value, 10) != *p.AsInt || monotonic && value < 0 {
				return 0, errors.New("invalid OTLP int64 number point")
			}
		} else if math.IsNaN(*p.AsDouble) || math.IsInf(*p.AsDouble, 0) || monotonic && *p.AsDouble < 0 {
			return 0, errors.New("invalid OTLP double number point")
		}
	}
	if m.Histogram == nil {
		return len(numbers), nil
	}
	for _, p := range m.Histogram.DataPoints {
		count, err := strconv.ParseUint(p.Count, 10, 64)
		if err != nil || strconv.FormatUint(count, 10) != p.Count || !validAttributes(p.Attributes) ||
			!validTimes(p.StartTimeUnixNano, p.TimeUnixNano, true) || len(p.ExplicitBounds) > 64 || len(p.BucketCounts) != len(p.ExplicitBounds)+1 {
			return 0, errors.New("invalid OTLP histogram point")
		}
		if p.Sum != nil && (math.IsInf(*p.Sum, 0) || math.IsNaN(*p.Sum)) {
			return 0, errors.New("invalid OTLP histogram sum")
		}
		var total uint64
		for _, bucket := range p.BucketCounts {
			value, err := strconv.ParseUint(bucket, 10, 64)
			if err != nil || strconv.FormatUint(value, 10) != bucket || math.MaxUint64-total < value {
				return 0, errors.New("invalid OTLP histogram bucket count")
			}
			total += value
		}
		if total != count {
			return 0, errors.New("OTLP histogram buckets do not sum to count")
		}
		for i, bound := range p.ExplicitBounds {
			if math.IsNaN(bound) || math.IsInf(bound, 0) || i > 0 && bound <= p.ExplicitBounds[i-1] {
				return 0, errors.New("invalid OTLP histogram bounds")
			}
		}
	}
	return len(m.Histogram.DataPoints), nil
}

func (m Metric) subset(start, end int) Metric {
	if m.Gauge != nil {
		m.Gauge = &Gauge{DataPoints: m.Gauge.DataPoints[start:end]}
	} else if m.Sum != nil {
		value := *m.Sum
		value.DataPoints = value.DataPoints[start:end]
		m.Sum = &value
	} else {
		value := *m.Histogram
		value.DataPoints = value.DataPoints[start:end]
		m.Histogram = &value
	}
	return m
}

type Event struct {
	Name       string
	Source     string // Explicit host/guest provenance, set by the trusted adapter.
	Start      time.Time
	End        time.Time
	Attributes []Attribute
	Failed     bool
	Kind       int // 1=internal (default), 2=server, 3=client, 4=producer, 5=consumer.
}

func (e Event) normalized() (Event, bool) {
	if e.End.IsZero() {
		e.End = time.Now()
	}
	if e.Start.IsZero() {
		e.Start = e.End
	}
	if e.Kind == 0 {
		e.Kind = 1
	}
	if e.Name == "" || e.Kind < 1 || e.Kind > 5 || !validText(e.Name, 128) || !validAttributes(e.Attributes) || !validTimes(nanos(e.Start), nanos(e.End), true) {
		return e, false
	}
	if !validSource(e.Source) {
		return e, false
	}
	for _, attribute := range e.Attributes {
		if attribute.Key == "osv.observation.source" {
			return e, false
		}
	}
	e.Attributes = append([]Attribute(nil), e.Attributes...)
	return e, true
}

type queuedEvent struct {
	Event
	trace bool
}

type preparedEvent struct {
	Event
	TraceID string
	SpanID  string
}

func (e preparedEvent) attributes() []Attribute {
	return append(append([]Attribute(nil), e.Attributes...), Attribute{"osv.observation.source", e.Source})
}

type wireLog struct {
	TimeUnixNano         string            `json:"timeUnixNano"`
	ObservedTimeUnixNano string            `json:"observedTimeUnixNano"`
	SeverityNumber       int               `json:"severityNumber"`
	SeverityText         string            `json:"severityText"`
	Body                 map[string]string `json:"body"`
	Attributes           []Attribute       `json:"attributes"`
	TraceID              string            `json:"traceId,omitempty"`
	SpanID               string            `json:"spanId,omitempty"`
	Flags                int               `json:"flags,omitempty"`
}

type wireSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []Attribute    `json:"attributes"`
	Status            map[string]int `json:"status,omitempty"`
	Flags             int            `json:"flags"`
}

func (e *Exporter) envelope(signal string, records any) any {
	scope := map[string]any{"scope": map[string]string{"name": scopeName, "version": "1"}}
	resource := map[string]any{"resource": map[string]any{"attributes": []Attribute{
		{"service.name", e.config.ServiceName}, {"service.instance.id", e.instanceID}, {"osv.exporter.source", e.config.Source}}}}
	switch signal {
	case "metrics":
		scope["metrics"] = records
		resource["scopeMetrics"] = []any{scope}
		return map[string]any{"resourceMetrics": []any{resource}}
	case "logs":
		scope["logRecords"] = records
		resource["scopeLogs"] = []any{scope}
		return map[string]any{"resourceLogs": []any{resource}}
	default:
		scope["spans"] = records
		resource["scopeSpans"] = []any{scope}
		return map[string]any{"resourceSpans": []any{resource}}
	}
}
