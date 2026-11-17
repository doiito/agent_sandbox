package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (a *API) artifactSession(w http.ResponseWriter, r *http.Request) *apiSession {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return nil
	}
	if !s.capability.Features.SessionArtifacts {
		writeSessionError(w, ErrArtifactsUnsupported)
		return nil
	}
	return s
}

func artifactRequestToken(w http.ResponseWriter, s *apiSession) bool {
	if err := s.tenant.consumeRequestToken(); err != nil {
		writeJobError(w, 429, "busy", err.Error(), true)
		return false
	}
	return true
}

func (a *API) artifactOperationError(w http.ResponseWriter, r *http.Request, s *apiSession, err error, creating bool) {
	if errors.Is(err, ErrSessionClosed) || errors.Is(err, ErrUnavailable) && r.Context().Err() == nil || creating && r.Context().Err() != nil {
		s.close(a)
	}
	writeSessionError(w, err)
}

func (a *API) createSessionArtifact(w http.ResponseWriter, r *http.Request) {
	s := a.artifactSession(w, r)
	if s == nil {
		return
	}
	var request SessionArtifactCreateRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if err := request.Validate(); err != nil {
		writeSessionError(w, err)
		return
	}
	if !artifactRequestToken(w, s) {
		return
	}
	info, err := s.handle.CreateArtifact(r.Context(), request)
	if err != nil {
		a.artifactOperationError(w, r, s, err, true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(info); err != nil || r.Context().Err() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.handle.DeleteArtifact(ctx, info.ID); err != nil && !errors.Is(err, ErrArtifactNotFound) {
			s.close(a)
		}
	}
}

func (a *API) readSessionArtifact(w http.ResponseWriter, r *http.Request) {
	s := a.artifactSession(w, r)
	if s == nil {
		return
	}
	id := r.PathValue("artifact")
	if !validSessionID(id) {
		writeSessionError(w, ErrArtifactNotFound)
		return
	}
	var request SessionArtifactReadRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if err := request.Validate(); err != nil {
		writeSessionError(w, err)
		return
	}
	if !artifactRequestToken(w, s) {
		return
	}
	chunk, err := s.handle.ReadArtifact(r.Context(), id, request)
	if err != nil {
		a.artifactOperationError(w, r, s, err, false)
		return
	}
	writeJSON(w, 200, chunk)
}

func (a *API) deleteSessionArtifact(w http.ResponseWriter, r *http.Request) {
	s := a.artifactSession(w, r)
	if s == nil {
		return
	}
	id := r.PathValue("artifact")
	if !validSessionID(id) {
		writeSessionError(w, ErrArtifactNotFound)
		return
	}
	if !artifactRequestToken(w, s) {
		return
	}
	if err := s.handle.DeleteArtifact(r.Context(), id); err != nil {
		a.artifactOperationError(w, r, s, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
