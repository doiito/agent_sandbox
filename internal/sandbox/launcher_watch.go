package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"time"
)

const launcherWatchProtocol = "osv-sandbox-launcher-watch/v1"

type launcherWatchRequest struct {
	Protocol  string               `json:"protocol"`
	Operation string               `json:"operation"`
	Tenant    string               `json:"tenant"`
	SessionID string               `json:"session_id"`
	WatchID   string               `json:"watch_id,omitempty"`
	Watch     *SessionWatchRequest `json:"watch,omitempty"`
	After     int                  `json:"after,omitempty"`
}

func (r launcherWatchRequest) validate() error {
	if r.Protocol != launcherWatchProtocol || !safeTenantID(r.Tenant) || !validSessionID(r.SessionID) {
		return errors.New("invalid watch owner")
	}
	switch r.Operation {
	case "start":
		if r.Watch != nil && r.WatchID == "" && r.After == 0 {
			return r.Watch.Validate()
		}
	case "list", "session-info":
		if r.Watch == nil && r.WatchID == "" && r.After == 0 {
			return nil
		}
	case "poll", "stop":
		if r.Watch == nil && validSessionID(r.WatchID) && r.After >= 0 && r.After <= 1<<31-1 && (r.Operation == "poll" || r.After == 0) {
			return nil
		}
	}
	return errors.New("invalid watch operation")
}

type launcherWatchResponse struct {
	Session  *SessionInfo        `json:"session,omitempty"`
	Protocol string              `json:"protocol"`
	Info     *SessionWatchInfo   `json:"info,omitempty"`
	Page     *SessionWatchPage   `json:"page,omitempty"`
	Watches  *[]SessionWatchInfo `json:"watches,omitempty"`
	Stopped  *bool               `json:"stopped,omitempty"`
	Error    string              `json:"error,omitempty"`
	Code     string              `json:"code,omitempty"`
}

// Each request has its own connection. A synchronous Run owns the persistent
// session connection, but must not block event observation or watcher cleanup.
func (h *LauncherSessionClient) watchExchange(ctx context.Context, request launcherWatchRequest) (launcherWatchResponse, error) {
	var response launcherWatchResponse
	if h.closed.Load() {
		return response, ErrSessionClosed
	}
	request.Protocol, request.Tenant, request.SessionID = launcherWatchProtocol, h.tenant, h.id
	if err := request.validate(); err != nil {
		return response, err
	}
	if !filepath.IsAbs(h.socketPath) {
		return response, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", h.socketPath)
	if err != nil {
		return response, fmt.Errorf("%w: connect watch launcher", ErrUnavailable)
	}
	defer connection.Close()
	stop := context.AfterFunc(bounded, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	_ = connection.SetDeadline(deadline)
	if err = json.NewEncoder(connection).Encode(request); err != nil {
		return response, ErrUnavailable
	}
	frame, err := readLauncherFrame(bufio.NewReaderSize(connection, 32<<10), 128<<10)
	if err != nil {
		return response, ErrUnavailable
	}
	if err = decodeLauncherFrame(frame, &response); err != nil || response.Protocol != launcherWatchProtocol {
		return response, ErrUnavailable
	}
	if response.Error != "" {
		return response, launcherSessionError(launcherSessionResponse{Error: response.Error, Code: response.Code})
	}
	return response, nil
}

func (h *LauncherSessionClient) StartFileWatch(ctx context.Context, request SessionWatchRequest) (SessionWatchInfo, error) {
	r, err := h.watchExchange(ctx, launcherWatchRequest{Operation: "start", Watch: &request})
	if err != nil {
		return SessionWatchInfo{}, err
	}
	if r.Info == nil || r.Info.SessionID != h.id || !validSessionID(r.Info.ID) || r.Info.Path != request.Path || r.Info.Recursive != request.Recursive || r.Info.IncludeEntry != request.IncludeEntry {
		return SessionWatchInfo{}, ErrUnavailable
	}
	return *r.Info, nil
}

func (h *LauncherSessionClient) PollFileWatch(ctx context.Context, id string, after int) (SessionWatchPage, error) {
	r, err := h.watchExchange(ctx, launcherWatchRequest{Operation: "poll", WatchID: id, After: after})
	if err != nil {
		return SessionWatchPage{}, err
	}
	if r.Page == nil || r.Page.Info.SessionID != h.id || r.Page.Info.ID != id || len(r.Page.Events) > sessionWatchPageLimit || r.Page.NextSequence != after+len(r.Page.Events) {
		return SessionWatchPage{}, ErrUnavailable
	}
	for n, event := range r.Page.Events {
		request := SessionWatchRequest{Path: r.Page.Info.Path, Recursive: r.Page.Info.Recursive, IncludeEntry: r.Page.Info.IncludeEntry}
		if event.validate(request, after+n) != nil {
			return SessionWatchPage{}, ErrUnavailable
		}
	}
	return *r.Page, nil
}

func (h *LauncherSessionClient) StopFileWatch(ctx context.Context, id string) (bool, error) {
	r, err := h.watchExchange(ctx, launcherWatchRequest{Operation: "stop", WatchID: id})
	if err != nil {
		return false, err
	}
	if r.Stopped == nil {
		return false, ErrUnavailable
	}
	return *r.Stopped, nil
}

func (h *LauncherSessionClient) ListFileWatches(ctx context.Context) ([]SessionWatchInfo, error) {
	r, err := h.watchExchange(ctx, launcherWatchRequest{Operation: "list"})
	if err != nil {
		return nil, err
	}
	if r.Watches == nil || len(*r.Watches) > sessionWatchHistoryLimit {
		return nil, ErrUnavailable
	}
	for _, info := range *r.Watches {
		if info.SessionID != h.id || !validSessionID(info.ID) {
			return nil, ErrUnavailable
		}
	}
	return *r.Watches, nil
}

// Called only after the launcher's existing Unix peer credential check.
func handleLauncherWatchConnection(parent context.Context, conn *net.UnixConn, first []byte, manager *Manager, options LauncherOptions, peer syscall.Ucred) {
	response := launcherWatchResponse{Protocol: launcherWatchProtocol}
	write := func() error {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		return json.NewEncoder(conn).Encode(response)
	}
	var request launcherWatchRequest
	if decodeLauncherFrame(first, &request) != nil || request.validate() != nil {
		response.Error, response.Code = "invalid watch request", "invalid"
		_ = write()
		return
	}
	session, err := manager.ownedSession(request.SessionID, request.Tenant)
	if err != nil {
		response.Error, response.Code = launcherSessionErrorFields(err)
		_ = write()
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	stopDisconnect := watchSessionCreateDisconnect(conn, cancel)
	defer stopDisconnect()
	audit := func(kind, code string) error {
		if options.Audit == nil {
			return nil
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		if err := options.Audit.Append(AuditEvent{RequestID: id, Tenant: request.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid, JobID: request.SessionID, Event: kind, Code: code}); err != nil {
			return errAuditUnavailable
		}
		return nil
	}
	created := ""
	committed := false
	defer func() {
		if created != "" && !committed {
			_, _ = session.StopFileWatch(created)
		}
	}()
	switch request.Operation {
	case "start":
		if err = audit("session.watch.admitted", ""); err == nil {
			var info SessionWatchInfo
			info, err = session.StartFileWatch(ctx, *request.Watch)
			if err == nil {
				response.Info = &info
				created = info.ID
			}
		}
		if err == nil {
			err = audit("session.watch.started", "")
		}
	case "poll":
		var page SessionWatchPage
		page, err = session.PollFileWatch(request.WatchID, request.After)
		if err == nil {
			response.Page = &page
		}
	case "stop":
		var stopped bool
		stopped, err = session.StopFileWatch(request.WatchID)
		if err == nil {
			response.Stopped = &stopped
			err = audit("session.watch.stopped", "")
		}
	case "list":
		infos := session.ListFileWatches()
		response.Watches = &infos
	case "session-info":
		info := session.Info()
		response.Session = &info
	}
	if err == nil && ctx.Err() != nil {
		err = ErrUnavailable
	}
	if err != nil {
		response = launcherWatchResponse{Protocol: launcherWatchProtocol}
		response.Error, response.Code = launcherSessionErrorFields(err)
	}
	if write() == nil && err == nil {
		committed = true
	}
}
