package sandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func (a *API) startSessionWatch(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	var request SessionWatchRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	info, err := s.handle.StartFileWatch(r.Context(), request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = s.handle.StopFileWatch(ctx, info.ID)
		}
	}()
	if r.Context().Err() != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	committed = json.NewEncoder(w).Encode(info) == nil
}

func (a *API) listSessionWatches(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	infos, err := s.handle.ListFileWatches(r.Context())
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, SessionWatchesResponse{SessionID: s.info.ID, Watches: infos})
}

func (a *API) pollSessionWatch(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	after := 0
	if text := r.URL.Query().Get("after"); text != "" {
		value, err := strconv.ParseInt(text, 10, 32)
		if err != nil || value < 0 {
			writeJobError(w, 400, "invalid_request", "invalid watch cursor", true)
			return
		}
		after = int(value)
	}
	page, err := s.handle.PollFileWatch(r.Context(), r.PathValue("watch"), after)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, page)
}

func (a *API) stopSessionWatch(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	stopped, err := s.handle.StopFileWatch(r.Context(), r.PathValue("watch"))
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, WatchStopResponse{Stopped: stopped})
}
