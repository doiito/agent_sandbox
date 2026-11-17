package sandbox

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

func validateAPITelemetry(config *otlp.Config) error {
	if config == nil {
		return nil
	}
	if config.Source != "" && config.Source != "host.api" {
		return errors.New("API OTLP resource source must be host.api")
	}
	return config.Validate()
}

type requestObservationKey struct{}

type requestObservation struct {
	start    time.Time
	returned bool // written and consumed only by the request goroutine
	mu       sync.Mutex
	status   int
	failed   bool
	job      []otlp.Attribute
}

func (a *API) beginRequestObservation(r *http.Request) (*http.Request, *requestObservation) {
	if a.telemetry.Load() == nil {
		return r, nil
	}
	observation := &requestObservation{start: time.Now()}
	return r.WithContext(context.WithValue(r.Context(), requestObservationKey{}, observation)), observation
}

func observeRequestStatus(r *http.Request, status int) {
	if status < 100 || status > 599 {
		return
	}
	if observation, ok := r.Context().Value(requestObservationKey{}).(*requestObservation); ok {
		observation.mu.Lock()
		observation.status = status
		observation.failed = observation.failed || status >= 400
		observation.mu.Unlock()
	}
}

func observeJobResult(r *http.Request, result RunResult, state string) {
	observation, ok := r.Context().Value(requestObservationKey{}).(*requestObservation)
	if !ok {
		return
	}
	state = metricJobState(state)
	attributes := []otlp.Attribute{{Key: "osv.job.state", Value: state}}
	if canonicalJobID(result.ID) {
		attributes = append(attributes, otlp.Attribute{Key: "osv.job.id", Value: result.ID})
	}
	switch result.Backend {
	case "qemu", "firecracker", "firecracker-linux", "firecracker-osv":
		attributes = append(attributes, otlp.Attribute{Key: "osv.backend", Value: result.Backend})
	}
	if validSHA256Hex(result.ArtifactManifestSHA256) {
		attributes = append(attributes, otlp.Attribute{Key: "osv.artifact_manifest_sha256", Value: result.ArtifactManifestSHA256})
	}
	if safeTenantID(result.TemplateID) {
		attributes = append(attributes, otlp.Attribute{Key: "osv.template.id", Value: result.TemplateID})
	}
	switch result.StartupMode {
	case "cold", "warm", "snapshot":
		attributes = append(attributes, otlp.Attribute{Key: "osv.startup.mode", Value: result.StartupMode})
	}
	observation.mu.Lock()
	observation.job = attributes
	observation.failed = observation.failed || state != "succeeded"
	observation.mu.Unlock()
}

func (a *API) finishRequestObservation(r *http.Request, observation *requestObservation) {
	method := "OTHER"
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		method = r.Method
	}
	route := "unmatched"
	if _, ok := a.routes[r.Pattern]; ok {
		route = r.Pattern
	}
	attributes := []otlp.Attribute{{Key: "http.request.method", Value: method}, {Key: "http.route", Value: route}}
	if tenant, ok := r.Context().Value(tenantContextKey{}).(*tenantRuntime); ok && safeTenantID(tenant.policy.ID) {
		attributes = append(attributes, otlp.Attribute{Key: "tenant", Value: tenant.policy.ID})
	}
	observation.mu.Lock()
	failed := observation.failed || !observation.returned
	if observation.status != 0 {
		attributes = append(attributes, otlp.Attribute{Key: "http.response.status_code", Value: strconv.Itoa(observation.status)})
	}
	attributes = append(attributes, otlp.Attribute{Key: "http.handler.returned", Value: strconv.FormatBool(observation.returned)})
	attributes = append(attributes, observation.job...)
	observation.mu.Unlock()
	a.telemetry.Load().Record(otlp.Event{Name: "api.request.complete", Source: "host.api", Kind: 2,
		Start: observation.start, End: time.Now(), Failed: failed, Attributes: attributes})
}

func writeObservedJobError(w http.ResponseWriter, r *http.Request, status int, code, message string, versioned bool) {
	observeRequestStatus(r, status)
	writeJobError(w, status, code, message, versioned)
}
