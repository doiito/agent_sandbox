package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

type sessionCreator interface {
	CreateSession(context.Context, SessionCreateRequest, string) (*LauncherSessionClient, SessionInfo, error)
}

type apiSession struct {
	previews    map[string]*previewGrant // guarded by the API preview service mutex
	codeEnabled bool
	capability  CapabilityReport
	mu          sync.Mutex
	deadline    time.Time
	closing     bool
	info        SessionInfo
	tenant      *tenantRuntime
	handle      *LauncherSessionClient
	release     func()
	timer       *time.Timer
	done        chan struct{}
	once        sync.Once
}

func (s *apiSession) close(api *API) {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Unlock()
		if api.preview != nil {
			api.preview.closeSession(s)
		}
		api.sessionsMu.Lock()
		if api.sessions[s.info.ID] == s {
			delete(api.sessions, s.info.ID)
		}
		api.sessionsMu.Unlock()
		close(s.done)
		api.releaseSessionAfterClose(s.release, s.handle.Close())
	})
}

// A lost launcher acknowledgment makes cleanup uncertain. Keep the tenant slot
// through the launcher's maximum graceful/forced cleanup window; the launcher
// retains global capacity and fails closed if cleanup itself fails.
func (a *API) releaseSessionAfterClose(release func(), err error) {
	if err == nil {
		release()
		return
	}
	if a.log != nil {
		a.log.Warn("session cleanup acknowledgment lost", "error", err)
	}
	time.AfterFunc(a.sessionCleanupHold, release)
}

func (a *API) createSession(w http.ResponseWriter, r *http.Request) {
	creator, ok := a.runner.(sessionCreator)
	if !ok {
		writeJobError(w, http.StatusNotImplemented, "unsupported", "sessions require a Linux launcher", true)
		return
	}
	var request SessionCreateRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, http.StatusBadRequest, "invalid_json", err.Error(), true)
		return
	}
	if request.Backend == "" || !validSHA256Hex(request.ArtifactManifestSHA256) {
		writeJobError(w, http.StatusBadRequest, "invalid_request", "sessions require backend and lowercase artifact_manifest_sha256", true)
		return
	}
	tenant := tenantFromRequest(r)
	if tenant == nil {
		writeJobError(w, http.StatusUnauthorized, "unauthorized", "unauthorized", true)
		return
	}
	report, err := capabilitiesFor(a.runner, request.Backend, request.ArtifactManifestSHA256)
	if err != nil {
		writeTemplateLookupError(w, err)
		return
	}
	if !tenant.allowsTemplate(report.Backend, report.ArtifactManifestSHA256) {
		writeJobError(w, 403, "forbidden", "template is not allowed for tenant", true)
		return
	}
	boundCapability, err := cloneCapabilityReport(report)
	if err != nil {
		writeSessionError(w, ErrUnavailable)
		return
	}
	report.restrictEntrypoints(tenant)
	if len(report.AllowedEntrypoints) == 0 {
		writeJobError(w, http.StatusForbidden, "forbidden", "tenant has no allowed session entrypoint", true)
		return
	}
	if !a.authorizeGuestProxy(w, r, request.Network, request.Backend, request.ArtifactManifestSHA256) {
		return
	}
	release, err := tenant.authorizeSessionCreate()
	if err != nil {
		writeJobError(w, http.StatusTooManyRequests, "busy", err.Error(), true)
		return
	}
	handle, info, err := creator.CreateSession(r.Context(), request, tenant.policy.ID)
	if err != nil {
		if errors.Is(err, ErrUnavailable) || r.Context().Err() != nil {
			a.releaseSessionAfterClose(release, err)
		} else {
			release()
		}
		writeSessionError(w, err)
		return
	}
	if r.Context().Err() != nil || !validSessionID(info.ID) || !info.ExpiresAt.After(time.Now()) {
		a.releaseSessionAfterClose(release, handle.Close())
		writeJobError(w, http.StatusServiceUnavailable, "unavailable", "session creation was interrupted", true)
		return
	}
	session := &apiSession{
		codeEnabled: report.Features.CodeContexts,
		capability:  boundCapability,
		info:        info, tenant: tenant, handle: handle, release: release,
		done: make(chan struct{}),
	}
	session.updateInfoLocked(info)
	session.timer = time.NewTimer(time.Until(session.deadline))
	a.sessionsMu.Lock()
	if a.sessions[info.ID] != nil {
		a.sessionsMu.Unlock()
		a.releaseSessionAfterClose(release, handle.Close())
		writeJobError(w, http.StatusServiceUnavailable, "unavailable", "session ID collision", true)
		return
	}
	a.sessions[info.ID] = session
	a.sessionsMu.Unlock()
	go a.watchSession(session)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(info); err != nil {
		session.close(a)
	}
}

func (a *API) watchSession(session *apiSession) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-session.done:
			return
		case <-session.timer.C:
			if session.expired() {
				session.close(a)
				return
			}
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := session.handle.Ping(ctx)
			cancel()
			if err != nil && !errors.Is(err, ErrBusy) {
				session.close(a)
				return
			}
		}
	}
}

func (a *API) getSession(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, http.StatusNotFound, "not_found", "session not found", true)
		return
	}
	info, err := a.currentSessionInfo(session)
	if errors.Is(err, ErrBusy) {
		writeSessionError(w, err)
		return
	}
	if err != nil {
		session.close(a)
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *API) runSessionCommand(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, http.StatusNotFound, "not_found", "session not found", true)
		return
	}
	var request SessionCommandRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, http.StatusBadRequest, "invalid_json", err.Error(), true)
		return
	}
	if request.Entrypoint == "" {
		writeJobError(w, http.StatusBadRequest, "invalid_request", "entrypoint is required", true)
		return
	}
	if err := session.tenant.authorizeSessionCommand(request); err != nil {
		if errors.Is(err, ErrBusy) {
			writeJobError(w, http.StatusTooManyRequests, "busy", err.Error(), true)
		} else {
			writeJobError(w, http.StatusForbidden, "forbidden", err.Error(), true)
		}
		return
	}
	result, err := session.handle.Run(r.Context(), request)
	if err != nil {
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSessionClosed) || r.Context().Err() != nil {
			session.close(a)
		}
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) sessionFile(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, http.StatusNotFound, "not_found", "session not found", true)
		return
	}
	var request SessionFileRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, http.StatusBadRequest, "invalid_json", err.Error(), true)
		return
	}
	if err := request.Validate(); err != nil {
		writeSessionError(w, err)
		return
	}
	if err := session.tenant.consumeRequestToken(); err != nil {
		writeJobError(w, http.StatusTooManyRequests, "busy", err.Error(), true)
		return
	}
	result, err := session.handle.File(r.Context(), request)
	if err != nil {
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSessionClosed) || r.Context().Err() != nil {
			session.close(a)
		}
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) deleteSession(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, http.StatusNotFound, "not_found", "session not found", true)
		return
	}
	session.close(a)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) lookupSession(r *http.Request) *apiSession {
	id := r.PathValue("id")
	if !validSessionID(id) {
		return nil
	}
	tenant := tenantFromRequest(r)
	if tenant == nil {
		return nil
	}
	a.sessionsMu.Lock()
	session := a.sessions[id]
	a.sessionsMu.Unlock()
	if session == nil || session.tenant != tenant {
		return nil
	}
	if session.expired() {
		session.close(a)
		return nil
	}
	return session
}

func tenantFromRequest(r *http.Request) *tenantRuntime {
	tenant, _ := r.Context().Value(tenantContextKey{}).(*tenantRuntime)
	return tenant
}

func validSessionID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for _, value := range id {
		if value < '0' || value > '9' {
			if value < 'a' || value > 'f' {
				return false
			}
		}
	}
	return true
}

func decodeHTTPBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

func writeSessionError(w http.ResponseWriter, err error) {
	if writeCodeError(w, err) {
		return
	}
	if errors.Is(err, ErrCommandNotFound) {
		writeJobError(w, http.StatusNotFound, "command_not_found", err.Error(), true)
		return
	}
	switch {
	case errors.Is(err, ErrArtifactsUnsupported):
		writeJobError(w, 501, "artifacts_unsupported", err.Error(), true)
	case errors.Is(err, ErrArtifactLimit):
		writeJobError(w, 429, "artifact_limit", err.Error(), true)
	case errors.Is(err, ErrArtifactTooLarge):
		writeJobError(w, 413, "artifact_too_large", err.Error(), true)
	case errors.Is(err, ErrArtifactNotFound):
		writeJobError(w, 404, "artifact_not_found", err.Error(), true)
	case errors.Is(err, ErrArtifactRange):
		writeJobError(w, 416, "artifact_range", err.Error(), true)
	case errors.Is(err, ErrArtifactChanged):
		writeJobError(w, 409, "artifact_changed", err.Error(), true)
	case errors.Is(err, ErrWatchUnsupported):
		writeJobError(w, 501, "watch_unsupported", err.Error(), true)
	case errors.Is(err, ErrWatchNotFound):
		writeJobError(w, 404, "watch_not_found", err.Error(), true)
	case errors.Is(err, ErrWatchCursor):
		writeJobError(w, 409, "watch_cursor", err.Error(), true)
	case errors.Is(err, ErrTimeoutBeyondLifetime):
		writeJobError(w, 400, "timeout_exceeds_lifetime", err.Error(), true)
	case errors.Is(err, ErrStdinClosed):
		writeJobError(w, 409, "stdin_closed", err.Error(), true)
	case errors.Is(err, ErrStdinUnavailable):
		writeJobError(w, 409, "stdin_unavailable", err.Error(), true)
	case errors.Is(err, ErrStdinLimit):
		writeJobError(w, 413, "stdin_limit", err.Error(), true)
	case errors.Is(err, ErrBusy):
		writeJobError(w, http.StatusTooManyRequests, "busy", ErrBusy.Error(), true)
	case errors.Is(err, ErrUnavailable):
		writeJobError(w, http.StatusServiceUnavailable, "unavailable", ErrUnavailable.Error(), true)
	case errors.Is(err, ErrTemplateMismatch):
		writeJobError(w, http.StatusConflict, "template_mismatch", ErrTemplateMismatch.Error(), true)
	case errors.Is(err, ErrInvalidSelector):
		writeJobError(w, http.StatusBadRequest, "invalid_request", ErrInvalidSelector.Error(), true)
	case errors.Is(err, ErrSessionClosed):
		writeJobError(w, http.StatusGone, "closed", ErrSessionClosed.Error(), true)
	case errors.Is(err, ErrFileNotFound):
		writeJobError(w, http.StatusNotFound, "file_not_found", ErrFileNotFound.Error(), true)
	case errors.Is(err, ErrFileDenied):
		writeJobError(w, http.StatusForbidden, "file_denied", ErrFileDenied.Error(), true)
	case errors.Is(err, ErrFileTooLarge):
		writeJobError(w, http.StatusRequestEntityTooLarge, "file_too_large", ErrFileTooLarge.Error(), true)
	case errors.Is(err, ErrFileOperationLimit):
		writeJobError(w, http.StatusRequestEntityTooLarge, "file_operation_limit", ErrFileOperationLimit.Error(), true)
	case errors.Is(err, ErrFileConflict):
		writeJobError(w, http.StatusConflict, "file_conflict", ErrFileConflict.Error(), true)
	case errors.Is(err, ErrInvalidFilePath):
		writeJobError(w, http.StatusBadRequest, "invalid_path", ErrInvalidFilePath.Error(), true)
	case errors.Is(err, ErrFileIO):
		writeJobError(w, http.StatusServiceUnavailable, "file_io", ErrFileIO.Error(), true)
	default:
		writeJobError(w, http.StatusBadRequest, "invalid_request", err.Error(), true)
	}
}
