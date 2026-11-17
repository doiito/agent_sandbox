package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (a *API) startSessionCommand(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	var request SessionCommandRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if request.Entrypoint == "" {
		writeJobError(w, 400, "invalid_request", "entrypoint is required", true)
		return
	}
	if err := s.tenant.authorizeSessionCommand(request); err != nil {
		if errors.Is(err, ErrBusy) {
			writeSessionError(w, err)
		} else {
			writeJobError(w, 403, "forbidden", err.Error(), true)
		}
		return
	}
	info, err := s.handle.StartCommand(r.Context(), request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, info)
}
func (a *API) listSessionCommands(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	infos, err := s.handle.ListCommands(ctx)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, SessionCommandsResponse{SessionID: s.info.ID, Commands: infos})
}
func commandCursor(r *http.Request) (int, error) {
	text := r.URL.Query().Get("after")
	if text == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < 0 || value > 256 {
		return 0, fmt.Errorf("invalid command output cursor")
	}
	return value, nil
}
func (a *API) pollSessionCommand(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	after, err := commandCursor(r)
	if err != nil {
		writeJobError(w, 400, "invalid_request", err.Error(), true)
		return
	}
	page, err := observeCommand(s, r.PathValue("command"), after)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, page)
}
func (a *API) cancelSessionCommand(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	killed, err := s.handle.CancelCommand(r.Context(), r.PathValue("command"))
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, CommandCancelResponse{Killed: killed})
}
func (a *API) streamSessionCommand(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	after, err := commandCursor(r)
	if err != nil {
		writeJobError(w, 400, "invalid_request", err.Error(), true)
		return
	}
	watchMS := 0
	if text := r.URL.Query().Get("timeout_ms"); text != "" {
		watchMS, err = strconv.Atoi(text)
		if err != nil || watchMS < 0 || watchMS > 86400000 {
			writeJobError(w, 400, "invalid_request", "invalid observation timeout", true)
			return
		}
	}
	var deadline <-chan time.Time
	if watchMS > 0 {
		timer := time.NewTimer(time.Duration(watchMS) * time.Millisecond)
		defer timer.Stop()
		deadline = timer.C
	}
	id := r.PathValue("command")
	page, err := observeCommand(s, id, after)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	control := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	defer control.SetWriteDeadline(time.Time{})
	emit := func(kind string, sequence int, value any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_ = control.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", sequence, kind, data); err != nil {
			return err
		}
		return control.Flush()
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	heartbeat := time.NewTicker(time.Second)
	defer heartbeat.Stop()
	for {
		for _, event := range page.Events {
			frame := SessionOutputFrame{SessionID: s.info.ID, CommandID: id, SessionOutputEvent: event}
			if emit("output", event.Sequence, frame) != nil {
				return
			}
		}
		after = page.NextSequence
		if page.Complete {
			_ = emit("result", after, page)
			return
		}
		select {
		case <-deadline:
			_ = emit("timeout", after, SessionCommandTimeoutFrame{SessionID: s.info.ID, CommandID: id, NextSequence: after})
			return
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case <-heartbeat.C:
			_ = control.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			if control.Flush() != nil {
				return
			}
		case <-ticker.C:
		}
		page, err = observeCommand(s, id, after)
		if errors.Is(err, ErrBusy) {
			page = SessionCommandPage{NextSequence: after}
			continue
		}
		if err != nil {
			return
		}
	}
}

// Read observers do not own the persistent session control connection.
// Finish the bounded launcher RPC even if the HTTP subscriber disconnects.
func observeCommand(s *apiSession, id string, after int) (SessionCommandPage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.handle.PollCommand(ctx, id, after)
}
