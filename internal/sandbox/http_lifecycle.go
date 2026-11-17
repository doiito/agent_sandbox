package sandbox

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sessionListSnapshot struct {
	id, tenant, order string
	created           time.Time
	ids               []string
}
type SessionListPage struct {
	Sessions   []SessionInfo `json:"sessions"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func (s *apiSession) snapshotInfo() SessionInfo { s.mu.Lock(); defer s.mu.Unlock(); return s.info }
func (s *apiSession) updateInfoLocked(info SessionInfo) {
	if info.LeaseRevision < s.info.LeaseRevision {
		return
	}
	s.info.ExpiresAt = info.ExpiresAt
	s.info.RemainingTTLMS = info.RemainingTTLMS
	s.info.LeaseRevision = info.LeaseRevision
	duration := time.Until(info.ExpiresAt)
	if info.RemainingTTLMS > 0 {
		duration = time.Duration(info.RemainingTTLMS) * time.Millisecond
	}
	s.deadline = time.Now().Add(duration)
	if s.timer != nil {
		s.timer.Reset(duration)
	}
}
func (s *apiSession) expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return true
	}
	if !time.Now().Before(s.deadline) {
		s.closing = true
		return true
	}
	return false
}
func (a *API) currentSessionInfo(s *apiSession) (SessionInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := s.handle.Info(ctx)
	if err != nil {
		return SessionInfo{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return SessionInfo{}, ErrSessionClosed
	}
	s.updateInfoLocked(info)
	return s.info, nil
}
func (a *API) setSessionTimeout(w http.ResponseWriter, r *http.Request) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	var request SessionTimeoutRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if request.TTLMS < sessionMinTTLMS || request.TTLMS > sessionMaxTTLMS {
		writeJobError(w, 400, "invalid_request", "ttl_ms must be in [1000,300000]", true)
		return
	}
	s.mu.Lock()
	if s.closing || !time.Now().Before(s.deadline) {
		s.mu.Unlock()
		s.close(a)
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	info, err := s.handle.SetTimeout(ctx, request.TTLMS)
	cancel()
	if err == nil {
		s.updateInfoLocked(info)
	}
	s.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrSessionClosed) || errors.Is(err, ErrUnavailable) {
			s.close(a)
			writeJobError(w, 404, "not_found", "session not found", true)
		} else {
			writeSessionError(w, err)
		}
		return
	}
	writeJSON(w, 200, info)
}
func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFromRequest(r)
	if tenant == nil {
		writeJobError(w, 401, "unauthorized", "unauthorized", true)
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if (key != "limit" && key != "order" && key != "cursor") || len(values) != 1 {
			writeJobError(w, 400, "invalid_request", "unsupported or repeated session list option", true)
			return
		}
	}
	limit := 20
	if text := q.Get("limit"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 100 {
			writeJobError(w, 400, "invalid_request", "limit must be in [1,100]", true)
			return
		}
		limit = value
	}
	order := q.Get("order")
	if order == "" {
		order = "desc"
	}
	if order != "asc" && order != "desc" {
		writeJobError(w, 400, "invalid_request", "order must be asc or desc", true)
		return
	}
	var snapshot *sessionListSnapshot
	offset := 0
	if cursor := q.Get("cursor"); cursor != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		parts := strings.Split(string(data), ":")
		if len(cursor) > 128 || err != nil || len(parts) != 2 || !validSessionID(parts[0]) {
			writeJobError(w, 400, "invalid_cursor", "invalid session cursor", true)
			return
		}
		offset, err = strconv.Atoi(parts[1])
		if err != nil || offset < 0 {
			writeJobError(w, 400, "invalid_cursor", "invalid session cursor offset", true)
			return
		}
		a.sessionPagesMu.Lock()
		snapshot = a.sessionPages[parts[0]]
		a.sessionPagesMu.Unlock()
		if snapshot == nil || snapshot.tenant != tenant.policy.ID || time.Since(snapshot.created) > 30*time.Second {
			writeJobError(w, 404, "not_found", "session cursor not found or expired", true)
			return
		}
		if snapshot.order != order || offset > len(snapshot.ids) {
			writeJobError(w, 400, "invalid_cursor", "session cursor order or offset mismatch", true)
			return
		}
	} else {
		a.sessionsMu.Lock()
		var sessions []*apiSession
		for _, s := range a.sessions {
			if s.tenant == tenant {
				sessions = append(sessions, s)
			}
		}
		a.sessionsMu.Unlock()
		rows := make([]SessionInfo, 0, len(sessions))
		for _, s := range sessions {
			if !s.expired() {
				rows = append(rows, s.snapshotInfo())
			}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
				if order == "asc" {
					return rows[i].ID < rows[j].ID
				}
				return rows[i].ID > rows[j].ID
			}
			if order == "asc" {
				return rows[i].CreatedAt.Before(rows[j].CreatedAt)
			}
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		})
		id, err := randomID()
		if err != nil {
			writeJobError(w, 503, "unavailable", "session pagination unavailable", true)
			return
		}
		snapshot = &sessionListSnapshot{id: id, tenant: tenant.policy.ID, order: order, created: time.Now()}
		for _, row := range rows {
			snapshot.ids = append(snapshot.ids, row.ID)
		}
		a.sessionPagesMu.Lock()
		if a.sessionPages == nil {
			a.sessionPages = map[string]*sessionListSnapshot{}
		}
		for key, page := range a.sessionPages {
			if time.Since(page.created) > 30*time.Second {
				delete(a.sessionPages, key)
			}
		}
		for {
			count := 0
			var oldest *sessionListSnapshot
			for _, page := range a.sessionPages {
				if page.tenant == tenant.policy.ID {
					count++
					if oldest == nil || page.created.Before(oldest.created) {
						oldest = page
					}
				}
			}
			if count < 8 {
				break
			}
			delete(a.sessionPages, oldest.id)
		}
		for len(a.sessionPages) >= 128 {
			var oldest *sessionListSnapshot
			for _, page := range a.sessionPages {
				if oldest == nil || page.created.Before(oldest.created) {
					oldest = page
				}
			}
			delete(a.sessionPages, oldest.id)
		}
		a.sessionPages[id] = snapshot
		a.sessionPagesMu.Unlock()
	}
	page := SessionListPage{Sessions: []SessionInfo{}}
	for offset < len(snapshot.ids) && len(page.Sessions) < limit {
		id := snapshot.ids[offset]
		offset++
		a.sessionsMu.Lock()
		s := a.sessions[id]
		a.sessionsMu.Unlock()
		if s == nil || s.tenant != tenant || s.expired() {
			continue
		}
		info, err := a.currentSessionInfo(s)
		if err != nil {
			if errors.Is(err, ErrBusy) {
				writeSessionError(w, err)
				return
			}
			s.close(a)
			continue
		}
		page.Sessions = append(page.Sessions, info)
	}
	if offset < len(snapshot.ids) {
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(snapshot.id + ":" + strconv.Itoa(offset)))
	}
	writeJSON(w, 200, page)
}
