package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SessionCapabilityReport describes an already admitted VM. Its template may
// have stopped admitting new VMs; the original lease and API policy still apply.
type SessionCapabilityReport struct {
	SessionID string `json:"session_id"`
	CapabilityReport
}

func cloneCapabilityReport(report CapabilityReport) (CapabilityReport, error) {
	data, err := json.Marshal(report)
	if err != nil {
		return CapabilityReport{}, err
	}
	var clone CapabilityReport
	err = json.Unmarshal(data, &clone)
	return clone, err
}

func (a *API) sessionCapabilities(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	info, err := session.handle.Info(ctx)
	if errors.Is(err, ErrBusy) {
		writeSessionError(w, err)
		return
	}
	if err != nil {
		if r.Context().Err() != nil {
			writeSessionError(w, r.Context().Err())
			return
		}
		session.close(a)
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	bound := session.capability
	if info.ID != session.info.ID || info.Backend != bound.Backend || info.ArtifactManifestSHA256 != bound.ArtifactManifestSHA256 || !bound.ArtifactAuthenticated {
		session.close(a)
		writeSessionError(w, ErrUnavailable)
		return
	}
	session.mu.Lock()
	if session.closing {
		session.mu.Unlock()
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	session.updateInfoLocked(info)
	session.mu.Unlock()
	copy, err := cloneCapabilityReport(bound)
	if err != nil {
		writeSessionError(w, ErrUnavailable)
		return
	}
	copy.restrictEntrypoints(session.tenant)
	a.apiCapabilityFilter(r)(&copy)
	if info.Network != "proxy" {
		disableRemoteInference(&copy)
	}
	writeJSON(w, 200, SessionCapabilityReport{SessionID: info.ID, CapabilityReport: copy})
}
