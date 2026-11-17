package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

type API struct {
	preview            *previewService
	portMu             sync.Mutex
	portClosing        bool
	portTunnels        map[*apiPortTunnel]struct{}
	portWG             sync.WaitGroup
	sessionPagesMu     sync.Mutex
	sessionPages       map[string]*sessionListSnapshot
	runner             Runner
	auth               *Authenticator
	log                *slog.Logger
	metrics            *Metrics
	telemetry          atomic.Pointer[otlp.Exporter]
	routes             map[string]struct{}
	sessionCleanupHold time.Duration
	sessionsMu         sync.Mutex
	sessions           map[string]*apiSession
	egress             *EgressClient
}

type Runner interface {
	Run(context.Context, RunRequest) (RunResult, error)
	Doctor() DoctorReport
	Capabilities() (CapabilityReport, error)
}

func NewAPI(runner Runner, token string, log *slog.Logger) http.Handler {
	return NewAPIWithAuthenticator(runner, NewSingleTokenAuthenticator(token), log)
}

type tenantContextKey struct{}

func NewAPIWithAuthenticator(runner Runner, auth *Authenticator, log *slog.Logger) http.Handler {
	return NewAPIWithEgress(runner, auth, log, "")
}

func NewAPIWithEgress(runner Runner, auth *Authenticator, log *slog.Logger, socket string) http.Handler {
	return newAPIWithEgress(runner, auth, log, socket)
}

// NewAPIWithPreview builds separate authenticated control and browser handlers.
// The caller serves the second handler only over LoadPreviewTLS on its own
// listener and calls Shutdown on the first before shutting either HTTP server.
func NewAPIWithPreview(runner Runner, auth *Authenticator, log *slog.Logger, socket string, config *PreviewConfig) (http.Handler, http.Handler, error) {
	return NewAPIWithTelemetry(runner, auth, log, socket, config, nil)
}

// NewAPIWithTelemetry constructs optional best-effort OTLP export. Call Shutdown
// before HTTP shutdown, then CloseTelemetry after HTTP requests have drained.
func NewAPIWithTelemetry(runner Runner, auth *Authenticator, log *slog.Logger, socket string, config *PreviewConfig, telemetry *otlp.Config) (http.Handler, http.Handler, error) {
	if err := validateAPITelemetry(telemetry); err != nil {
		return nil, nil, err
	}
	control := newAPIWithEgress(runner, auth, log, socket)
	var preview *previewService
	if config != nil {
		var err error
		preview, err = newPreviewService(control.api, *config)
		if err != nil {
			return nil, nil, err
		}
		control.api.preview = preview
	}
	if telemetry != nil {
		exporter, err := otlp.New(*telemetry, control.api.otlpMetrics)
		if err != nil {
			return nil, nil, err
		}
		control.api.telemetry.Store(exporter)
	}
	if preview == nil {
		return control, nil, nil
	}
	return control, preview, nil
}

func newAPIWithEgress(runner Runner, auth *Authenticator, log *slog.Logger, socket string) *apiHTTPHandler {
	api := &API{runner: runner, auth: auth, log: log, metrics: newMetrics(),
		routes:             make(map[string]struct{}),
		sessionCleanupHold: 15 * time.Second, sessions: make(map[string]*apiSession)}
	if socket != "" {
		api.egress = NewEgressClient(socket)
	}
	mux := http.NewServeMux()
	register := func(pattern string, handler http.HandlerFunc) {
		api.routes[pattern] = struct{}{}
		mux.HandleFunc(pattern, handler)
	}
	register("GET /healthz", api.health)
	register("GET /readyz", api.ready)
	register("GET /metrics", api.prometheus)
	register("GET /v1/doctor", api.doctor)
	register("GET /v1/capabilities", api.capabilities)
	register("GET /v2/templates", api.templates)
	register("POST /v1/jobs", api.run)
	register("POST /v2/jobs", api.runV2)
	register("POST /v2/net/fetch", api.networkFetch)
	register("POST /v2/sessions/{id}/ml/invocations", api.invokeSessionInference)
	register("GET /v2/ml/bills/{task}", api.getInferenceBill)
	register("POST /v2/sessions", api.createSession)
	register("GET /v2/sessions", api.listSessions)
	register("POST /v2/sessions/{id}/timeout", api.setSessionTimeout)
	register("GET /v2/sessions/{id}", api.getSession)
	register("POST /v2/sessions/{id}/commands", api.runSessionCommand)
	register("POST /v2/sessions/{id}/commands/start", api.startSessionCommand)
	register("GET /v2/sessions/{id}/commands", api.listSessionCommands)
	register("GET /v2/sessions/{id}/commands/{command}", api.pollSessionCommand)
	register("DELETE /v2/sessions/{id}/commands/{command}", api.cancelSessionCommand)
	register("GET /v2/sessions/{id}/commands/{command}/events", api.streamSessionCommand)
	register("POST /v2/sessions/{id}/commands/{command}/stdin", api.submitCommandInput)
	register("GET /v2/sessions/{id}/commands/{command}/stdin/{sequence}", api.pollCommandInput)
	register("POST /v2/sessions/{id}/files", api.sessionFile)
	register("POST /v2/sessions/{id}/artifacts", api.createSessionArtifact)
	register("POST /v2/sessions/{id}/artifacts/{artifact}/read", api.readSessionArtifact)
	register("DELETE /v2/sessions/{id}/artifacts/{artifact}", api.deleteSessionArtifact)
	register("GET /v2/sessions/{id}/capabilities", api.sessionCapabilities)
	register("POST /v2/sessions/{id}/watches", api.startSessionWatch)
	register("POST /v2/sessions/{id}/ports/{port}/connections/{connection}", api.openPortTunnel)
	register("GET /v2/sessions/{id}/ports/{port}/connections/{connection}", api.getPortConnection)
	register("DELETE /v2/sessions/{id}/ports/{port}/connections/{connection}", api.cancelPortConnection)
	register("POST /v2/sessions/{id}/ports/{port}/previews/{preview}", api.createPreview)
	register("GET /v2/sessions/{id}/previews/{preview}", api.getPreview)
	register("DELETE /v2/sessions/{id}/previews/{preview}", api.revokePreview)
	register("POST /v2/sessions/{id}/contexts", api.createCodeContext)
	register("POST /v2/sessions/{id}/contexts/default", api.defaultCodeContext)
	register("GET /v2/sessions/{id}/contexts", api.listCodeContexts)
	register("GET /v2/sessions/{id}/contexts/{context}", api.getCodeContext)
	register("POST /v2/sessions/{id}/contexts/{context}/restart", api.restartCodeContext)
	register("DELETE /v2/sessions/{id}/contexts/{context}", api.removeCodeContext)
	register("POST /v2/sessions/{id}/code-executions", api.submitCodeExecution)
	register("GET /v2/sessions/{id}/code-executions/{execution}", api.getCodeExecution)
	register("DELETE /v2/sessions/{id}/code-executions/{execution}", api.cancelCodeExecution)
	register("GET /v2/sessions/{id}/watches", api.listSessionWatches)
	register("GET /v2/sessions/{id}/watches/{watch}", api.pollSessionWatch)
	register("DELETE /v2/sessions/{id}/watches/{watch}", api.stopSessionWatch)
	register("DELETE /v2/sessions/{id}", api.deleteSession)
	return &apiHTTPHandler{api: api, handler: api.secure(withHTTPRouteErrors(mux)), requestsDone: make(chan struct{})}
}

type apiHTTPHandler struct {
	api              *API
	handler          http.Handler
	requestsMu       sync.Mutex
	activeRequests   int
	telemetryClosing bool
	telemetryError   error
	requestsDone     chan struct{}
}

func (h *apiHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.api.telemetry.Load() == nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	h.requestsMu.Lock()
	if h.telemetryClosing {
		h.requestsMu.Unlock()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		writeJobError(w, http.StatusServiceUnavailable, "unavailable", "server is stopping", versionedAPIPath(r.URL.Path))
		return
	}
	h.activeRequests++
	h.requestsMu.Unlock()
	defer func() {
		h.requestsMu.Lock()
		h.activeRequests--
		if h.activeRequests == 0 && h.telemetryClosing {
			close(h.requestsDone)
		}
		h.requestsMu.Unlock()
	}()
	h.handler.ServeHTTP(w, r)
}

// Shutdown joins pending and upgraded port handlers; http.Server.Shutdown does
// not own hijacked sockets. Embedding servers call this before HTTP shutdown.
func (h *apiHTTPHandler) Shutdown(ctx context.Context) error {
	var previewErr error
	if h.api.preview != nil {
		previewErr = h.api.preview.shutdown(ctx)
	}
	return errors.Join(previewErr, h.api.shutdownPortTunnels(ctx))
}

func (h *apiHTTPHandler) CloseTelemetry(ctx context.Context) error {
	exporter := h.api.telemetry.Load()
	if exporter == nil {
		return nil
	}
	h.requestsMu.Lock()
	if !h.telemetryClosing {
		h.telemetryClosing = true
		if h.activeRequests == 0 {
			close(h.requestsDone)
		}
	}
	h.requestsMu.Unlock()
	var drainErr error
	select {
	case <-h.requestsDone:
	case <-ctx.Done():
		drainErr = ctx.Err()
	}
	err := errors.Join(drainErr, exporter.Close(ctx))
	h.requestsMu.Lock()
	if h.telemetryError == nil {
		h.telemetryError = err
	}
	err = h.telemetryError
	h.requestsMu.Unlock()
	if err != nil && h.api.log != nil {
		stopped := false
		select {
		case <-exporter.Done():
			stopped = true
		default:
		}
		h.api.log.Warn("OTLP delivery incomplete", "worker_stopped", stopped, "counters", exporter.Stats())
	}
	return err
}

func (a *API) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, observation := a.beginRequestObservation(r)
		if observation != nil {
			defer func() { a.finishRequestObservation(r, observation) }()
		}
		a.metrics.httpRequests.Add(1)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			if a.auth == nil {
				observeRequestStatus(r, http.StatusServiceUnavailable)
				writeJobError(w, http.StatusServiceUnavailable, "unavailable", "OSV_SANDBOX_TOKEN is not configured", versionedAPIPath(r.URL.Path))
				return
			}
			tenant, ok := a.auth.Authenticate(r.Header.Get("Authorization"))
			if !ok {
				observeRequestStatus(r, http.StatusUnauthorized)
				a.metrics.authFailures.Add(1)
				writeJobError(w, http.StatusUnauthorized, "unauthorized", "unauthorized", versionedAPIPath(r.URL.Path))
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), tenantContextKey{}, tenant))
		}
		next.ServeHTTP(w, r)
		if observation != nil {
			observation.returned = true
		}
	})
}

func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if report := a.runner.Doctor(); !report.Ready {
		observeRequestStatus(r, http.StatusServiceUnavailable)
		writeJSON(w, http.StatusServiceUnavailable, StatusResponse{Status: "not-ready"})
		return
	}
	observeRequestStatus(r, http.StatusOK)
	writeJSON(w, http.StatusOK, StatusResponse{Status: "ready"})
}

func (a *API) prometheus(w http.ResponseWriter, r *http.Request) {
	observeRequestStatus(r, http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	a.metrics.writePrometheus(w)
	if exporter := a.telemetry.Load(); exporter != nil {
		writeOTLPExporterMetrics(w, exporter.Stats())
	}
	if source, ok := a.runner.(interface {
		WarmPoolStatusContext(context.Context) (WarmPoolSnapshot, error)
	}); ok {
		if status, err := source.WarmPoolStatusContext(r.Context()); err == nil {
			writeWarmPoolMetrics(w, status)
		}
	}
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	observeRequestStatus(r, http.StatusOK)
	writeJSON(w, http.StatusOK, StatusResponse{Status: "ok"})
}

func (a *API) doctor(w http.ResponseWriter, r *http.Request) {
	report := a.runner.Doctor()
	status := http.StatusOK
	if !report.Ready {
		status = http.StatusServiceUnavailable
	}
	observeRequestStatus(r, status)
	writeJSON(w, status, report)
}

func (a *API) capabilities(w http.ResponseWriter, r *http.Request) {
	tenant, ok := r.Context().Value(tenantContextKey{}).(*tenantRuntime)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	report, err := capabilitiesFor(a.runner, r.URL.Query().Get("backend"), r.URL.Query().Get("artifact_manifest_sha256"))
	if err != nil {
		writeTemplateLookupError(w, err)
		return
	}
	if !tenant.allowsTemplate(report.Backend, report.ArtifactManifestSHA256) {
		if r.URL.Query().Get("backend") != "" || r.URL.Query().Get("artifact_manifest_sha256") != "" {
			writeJobError(w, 403, "forbidden", "template is not allowed for tenant", true)
			return
		}
		// Discovery and host fetch remain available without exposing or
		// selecting a default template that this tenant cannot execute.
		report = CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", AllowedEntrypoints: []string{}, Methods: []string{"GET /v1/capabilities", "GET /v2/templates"}}
	}
	report.restrictEntrypoints(tenant)
	a.apiCapabilityFilter(r)(&report)
	writeJSON(w, http.StatusOK, report)
}

func (a *API) run(w http.ResponseWriter, r *http.Request) {
	a.handleRun(w, r, false)
}

func (a *API) runV2(w http.ResponseWriter, r *http.Request) {
	a.handleRun(w, r, true)
}

func (a *API) handleRun(w http.ResponseWriter, r *http.Request, versioned bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req RunRequest
	if err := dec.Decode(&req); err != nil {
		writeObservedJobError(w, r, http.StatusBadRequest, "invalid_json", "invalid JSON: "+err.Error(), versioned)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeObservedJobError(w, r, http.StatusBadRequest, "invalid_json", "request body must contain exactly one JSON object", versioned)
		return
	}
	if versioned && (req.Entrypoint == "" || req.Backend == "" || !validSHA256Hex(req.ArtifactManifestSHA256)) {
		writeObservedJobError(w, r, http.StatusBadRequest, "invalid_request", "v2 jobs require entrypoint, backend, and lowercase artifact_manifest_sha256", true)
		return
	}
	tenant, ok := r.Context().Value(tenantContextKey{}).(*tenantRuntime)
	if !ok {
		writeObservedJobError(w, r, http.StatusUnauthorized, "unauthorized", "unauthorized", versioned)
		return
	}
	if tenant.policy.AllowedTemplates != nil && req.Backend == "" && req.ArtifactManifestSHA256 == "" {
		report, err := capabilitiesFor(a.runner, "", "")
		if err != nil {
			writeTemplateLookupError(w, err)
			return
		}
		req.Backend, req.ArtifactManifestSHA256 = report.Backend, report.ArtifactManifestSHA256
	}
	if !tenant.allowsTemplate(req.Backend, req.ArtifactManifestSHA256) {
		writeObservedJobError(w, r, 403, "forbidden", "template is not allowed for tenant", versioned)
		return
	}
	if !a.authorizeGuestProxy(w, r, req.Network, req.Backend, req.ArtifactManifestSHA256) {
		return
	}
	release, err := tenant.authorize(req)
	if err != nil {
		status := http.StatusForbidden
		state := "rejected"
		code := "forbidden"
		if errors.Is(err, ErrBusy) {
			status, state = http.StatusTooManyRequests, "busy"
			code = "busy"
		}
		a.metrics.recordJob(tenant.policy.ID, state, 0)
		observeJobResult(r, RunResult{}, state)
		writeObservedJobError(w, r, status, code, err.Error(), versioned)
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
		code := "invalid_request"
		if errors.Is(err, ErrBusy) {
			status = http.StatusTooManyRequests
			code = "busy"
		} else if errors.Is(err, ErrUnavailable) {
			status = http.StatusServiceUnavailable
			code = "unavailable"
		} else if errors.Is(err, ErrTemplateMismatch) {
			status = http.StatusConflict
			code = "template_mismatch"
		} else if strings.Contains(err.Error(), "start ") {
			status = http.StatusServiceUnavailable
			code = "unavailable"
		}
		a.metrics.recordJob(tenant.policy.ID, "rejected", time.Since(started))
		observeJobResult(r, RunResult{}, "rejected")
		writeObservedJobError(w, r, status, code, err.Error(), versioned)
		return
	}
	a.metrics.recordJob(tenant.policy.ID, result.State, time.Since(started))
	observeJobResult(r, result, result.State)
	observeRequestStatus(r, http.StatusOK)
	a.log.Info("sandbox job completed", "tenant", tenant.policy.ID, "id", result.ID, "state", result.State, "backend", result.Backend, "duration_ms", result.DurationMS, "output_bytes", len(result.Output), "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, result)
}

func writeJobError(w http.ResponseWriter, status int, code, message string, versioned bool) {
	if versioned {
		writeJSON(w, status, APIErrorResponse{Code: code, Error: message})
		return
	}
	writeError(w, status, message)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, LegacyAPIErrorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
