package sandbox

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

func (a *API) submitCommandInput(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	var request SessionCommandInputRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if _, err := request.data(); err != nil {
		writeSessionError(w, err)
		return
	}
	// Complete the short admission even if the observer disconnects mid-response.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	receipt, err := s.handle.SubmitCommandInput(ctx, r.PathValue("command"), request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 202, receipt)
}
func (a *API) pollCommandInput(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	sequence, err := strconv.Atoi(r.PathValue("sequence"))
	if err != nil || sequence < 1 || sequence > commandInputRequestLimit {
		writeJobError(w, 400, "invalid_request", "invalid stdin sequence", true)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	receipt, err := s.handle.PollCommandInput(ctx, r.PathValue("command"), sequence)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, 200, receipt)
}
