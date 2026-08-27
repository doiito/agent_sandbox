package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type API struct {
	runner  Runner
	auth    *Authenticator
	log     *slog.Logger
	metrics *Metrics
}

type Runner interface {
	Run(context.Context, RunRequest) (RunResult, error)
	Doctor() DoctorReport
}

func NewAPI(runner Runner, token string, log *slog.Logger) http.Handler {
	return NewAPIWithAuthenticator(runner, NewSingleTokenAuthenticator(token), log)
}

type tenantContextKey struct{}

func NewAPIWithAuthenticator(runner Runner, auth *Authenticator, log *slog.Logger) http.Handler {
	api := &API{runner: runner, auth: auth, log: log, metrics: newMetrics()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.HandleFunc("GET /metrics", api.prometheus)
	mux.HandleFunc("GET /v1/doctor", api.doctor)
	mux.HandleFunc("POST /v1/jobs", api.run)
	return api.secure(mux)
}

func (a *API) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.metrics.httpRequests.Add(1)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			if a.auth == nil {
				writeError(w, http.StatusServiceUnavailable, "OSV_SANDBOX_TOKEN is not configured")
				return
			}
			tenant, ok := a.auth.Authenticate(r.Header.Get("Authorization"))
			if !ok {
				a.metrics.authFailures.Add(1)
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), tenantContextKey{}, tenant))
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) ready(w http.ResponseWriter, _ *http.Request) {
	if report := a.runner.Doctor(); !report.Ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not-ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *API) prometheus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	a.metrics.writePrometheus(w)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) doctor(w http.ResponseWriter, _ *http.Request) {
	report := a.runner.Doctor()
	status := http.StatusOK
	if !report.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, report)
}

func (a *API) run(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req RunRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON object")
		return
	}
	tenant, ok := r.Context().Value(tenantContextKey{}).(*tenantRuntime)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	release, err := tenant.authorize(req)
	if err != nil {
		status := http.StatusForbidden
		state := "rejected"
		if errors.Is(err, ErrBusy) {
			status, state = http.StatusTooManyRequests, "busy"
		}
		a.metrics.recordJob(tenant.policy.ID, state, 0)
		writeError(w, status, err.Error())
		return
	}
	defer release()
	a.metrics.inflight.Add(1)
	defer a.metrics.inflight.Add(-1)
	started := time.Now()
	req.tenantID = tenant.policy.ID
	result, err := a.runner.Run(r.Context(), req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrBusy) {
			status = http.StatusTooManyRequests
		} else if strings.Contains(err.Error(), "start ") {
			status = http.StatusServiceUnavailable
		}
		a.metrics.recordJob(tenant.policy.ID, "rejected", time.Since(started))
		writeError(w, status, err.Error())
		return
	}
	a.metrics.recordJob(tenant.policy.ID, result.State, time.Since(started))
	a.log.Info("sandbox job completed", "tenant", tenant.policy.ID, "id", result.ID, "state", result.State, "backend", result.Backend, "duration_ms", result.DurationMS, "output_bytes", len(result.Output), "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, result)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
