package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const launcherSessionProtocol = "osv-sandbox-launcher-session/v1"

type launcherSessionRequest struct {
	TTLMS         int                         `json:"ttl_ms,omitempty"`
	Input         *SessionCommandInputRequest `json:"input,omitempty"`
	InputSequence int                         `json:"input_sequence,omitempty"`
	Protocol      string                      `json:"protocol"`
	Operation     string                      `json:"operation"`
	Tenant        string                      `json:"tenant"`
	SessionID     string                      `json:"session_id,omitempty"`
	Create        *SessionCreateRequest       `json:"create,omitempty"`
	Command       *SessionCommandRequest      `json:"command,omitempty"`
	File          *SessionFileRequest         `json:"file,omitempty"`
	CommandID     string                      `json:"command_id,omitempty"`
	After         int                         `json:"after,omitempty"`
}

type launcherSessionResponse struct {
	InputReceipt *SessionCommandInputReceipt `json:"input_receipt,omitempty"`
	Protocol     string                      `json:"protocol"`
	Info         *SessionInfo                `json:"info,omitempty"`
	Result       *SessionCommandResult       `json:"result,omitempty"`
	File         *SessionFileResult          `json:"file,omitempty"`
	Error        string                      `json:"error,omitempty"`
	Code         string                      `json:"code,omitempty"`
	CommandInfo  *SessionCommandInfo         `json:"command_info,omitempty"`
	Commands     *[]SessionCommandInfo       `json:"commands,omitempty"`
	CommandPage  *SessionCommandPage         `json:"command_page,omitempty"`
	Killed       *bool                       `json:"killed,omitempty"`
}

type LauncherSessionClient struct {
	conn          net.Conn
	reader        *bufio.Reader
	id            string
	tenant        string
	mu            sync.Mutex
	closed        atomic.Bool
	socketPath    string
	codeMu        sync.Mutex
	codeLanguages map[string]string
}

func (c LauncherClient) CreateSession(ctx context.Context, req SessionCreateRequest, tenant string) (*LauncherSessionClient, SessionInfo, error) {
	if !safeTenantID(tenant) {
		return nil, SessionInfo{}, errors.New("invalid tenant session owner")
	}
	if !filepath.IsAbs(c.SocketPath) {
		return nil, SessionInfo{}, errors.New("launcher socket must be absolute")
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, SessionInfo{}, fmt.Errorf("%w: connect session launcher: %v", ErrUnavailable, err)
	}
	closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer closeOnCancel()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := launcherSessionRequest{
		Protocol: launcherSessionProtocol, Operation: "create", Tenant: tenant, Create: &req,
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		_ = conn.Close()
		return nil, SessionInfo{}, fmt.Errorf("%w: send session create: %v", ErrUnavailable, err)
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	response, err := readLauncherSessionResponse(reader)
	if err != nil {
		_ = conn.Close()
		return nil, SessionInfo{}, fmt.Errorf("%w: read session create: %v", ErrUnavailable, err)
	}
	if response.Error != "" {
		_ = conn.Close()
		return nil, SessionInfo{}, launcherSessionError(response)
	}
	if response.Info == nil || response.Info.ID == "" || response.Info.State != "running" {
		_ = conn.Close()
		return nil, SessionInfo{}, fmt.Errorf("%w: invalid session create response", ErrUnavailable)
	}
	_ = conn.SetDeadline(time.Time{})
	handle := &LauncherSessionClient{conn: conn, reader: reader, id: response.Info.ID, tenant: tenant, socketPath: c.SocketPath}
	return handle, *response.Info, nil
}

func (h *LauncherSessionClient) Run(ctx context.Context, request SessionCommandRequest) (SessionCommandResult, error) {
	response, err := h.exchange(ctx, launcherSessionRequest{
		Protocol: launcherSessionProtocol, Operation: "run", Tenant: h.tenant,
		SessionID: h.id, Command: &request,
	})
	if err != nil {
		return SessionCommandResult{}, err
	}
	if response.Error != "" {
		return SessionCommandResult{}, launcherSessionError(response)
	}
	if response.Result == nil || response.Result.SessionID != h.id || !response.Result.RunResult.ProtocolOK {
		h.closed.Store(true)
		_ = h.conn.Close()
		return SessionCommandResult{}, fmt.Errorf("%w: invalid session command response", ErrUnavailable)
	}
	return *response.Result, nil
}

func (h *LauncherSessionClient) File(ctx context.Context, request SessionFileRequest) (SessionFileResult, error) {
	response, err := h.exchange(ctx, launcherSessionRequest{
		Protocol: launcherSessionProtocol, Operation: "file", Tenant: h.tenant,
		SessionID: h.id, File: &request,
	})
	if err != nil {
		return SessionFileResult{}, err
	}
	if response.Error != "" {
		return SessionFileResult{}, launcherSessionError(response)
	}
	valid := response.File != nil && response.File.SessionID == h.id && response.File.Action == request.Action && response.File.Path == request.Path
	if valid {
		valid = (request.Destination == nil && response.File.Destination == nil) ||
			(request.Destination != nil && response.File.Destination != nil && *request.Destination == *response.File.Destination)
	}
	if !valid {
		h.closed.Store(true)
		_ = h.conn.Close()
		return SessionFileResult{}, fmt.Errorf("%w: invalid session file response", ErrUnavailable)
	}
	return *response.File, nil
}

func (h *LauncherSessionClient) Info(ctx context.Context) (SessionInfo, error) {
	if filepath.IsAbs(h.socketPath) {
		r, err := h.watchExchange(ctx, launcherWatchRequest{Operation: "session-info"})
		if err != nil {
			return SessionInfo{}, err
		}
		if r.Session == nil || r.Session.ID != h.id || r.Session.State != "running" {
			return SessionInfo{}, ErrSessionClosed
		}
		return *r.Session, nil
	}
	response, err := h.commandRPCExchange(ctx, launcherSessionRequest{Protocol: launcherSessionProtocol, Operation: "ping", Tenant: h.tenant, SessionID: h.id})
	if err != nil {
		return SessionInfo{}, err
	}
	if response.Info == nil || response.Info.ID != h.id || response.Info.State != "running" {
		return SessionInfo{}, ErrSessionClosed
	}
	return *response.Info, nil
}
func (h *LauncherSessionClient) Ping(ctx context.Context) error { _, err := h.Info(ctx); return err }
func (h *LauncherSessionClient) SetTimeout(ctx context.Context, ttlMS int) (SessionInfo, error) {
	response, err := h.commandRPCExchange(ctx, launcherSessionRequest{Protocol: launcherSessionProtocol, Operation: "timeout", Tenant: h.tenant, SessionID: h.id, TTLMS: ttlMS})
	if err != nil {
		return SessionInfo{}, err
	}
	if response.Info == nil || response.Info.ID != h.id || response.Info.State != "running" {
		return SessionInfo{}, ErrSessionClosed
	}
	return *response.Info, nil
}

func (h *LauncherSessionClient) exchange(ctx context.Context, request launcherSessionRequest) (launcherSessionResponse, error) {
	if !h.mu.TryLock() {
		return launcherSessionResponse{}, ErrBusy
	}
	defer h.mu.Unlock()
	if h.closed.Load() {
		return launcherSessionResponse{}, ErrSessionClosed
	}
	deadline := time.Now().Add(310 * time.Second)
	if userDeadline, ok := ctx.Deadline(); ok && userDeadline.Before(deadline) {
		deadline = userDeadline
	}
	_ = h.conn.SetDeadline(deadline)
	stopClosing := context.AfterFunc(ctx, func() {
		h.closed.Store(true)
		_ = h.conn.Close()
	})
	defer stopClosing()
	defer h.conn.SetDeadline(time.Time{})
	if err := json.NewEncoder(h.conn).Encode(request); err != nil {
		h.closed.Store(true)
		_ = h.conn.Close()
		return launcherSessionResponse{}, fmt.Errorf("%w: send session command: %v", ErrUnavailable, err)
	}
	response, err := readLauncherSessionResponse(h.reader)
	if err != nil {
		h.closed.Store(true)
		_ = h.conn.Close()
		return launcherSessionResponse{}, fmt.Errorf("%w: read session command: %v", ErrUnavailable, err)
	}
	if response.Code == "closed" {
		h.closed.Store(true)
		_ = h.conn.Close()
	}
	return response, nil
}

func (h *LauncherSessionClient) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return ErrSessionClosed
	}
	if !h.mu.TryLock() {
		_ = h.conn.Close()
		return ErrBusy
	}
	defer h.mu.Unlock()
	defer h.conn.Close()
	_ = h.conn.SetDeadline(time.Now().Add(12 * time.Second))
	if err := json.NewEncoder(h.conn).Encode(launcherSessionRequest{
		Protocol: launcherSessionProtocol, Operation: "close", Tenant: h.tenant, SessionID: h.id,
	}); err != nil {
		return fmt.Errorf("%w: send session close: %v", ErrUnavailable, err)
	}
	response, err := readLauncherSessionResponse(h.reader)
	if err != nil {
		return fmt.Errorf("%w: read session close: %v", ErrUnavailable, err)
	}
	if response.Error != "" {
		return launcherSessionError(response)
	}
	return nil
}

func readLauncherSessionResponse(reader *bufio.Reader) (launcherSessionResponse, error) {
	frame, err := readLauncherFrame(reader, launcherResponseLimit)
	if err != nil {
		return launcherSessionResponse{}, err
	}
	var response launcherSessionResponse
	if err := decodeLauncherFrame(frame, &response); err != nil {
		return launcherSessionResponse{}, err
	}
	if response.Protocol != launcherSessionProtocol {
		return launcherSessionResponse{}, errors.New("unexpected launcher session protocol")
	}
	return response, nil
}

func launcherSessionError(response launcherSessionResponse) error {
	switch response.Code {
	case "artifacts-unsupported":
		return ErrArtifactsUnsupported
	case "artifact-limit":
		return ErrArtifactLimit
	case "artifact-too-large":
		return ErrArtifactTooLarge
	case "artifact-not-found":
		return ErrArtifactNotFound
	case "artifact-range":
		return ErrArtifactRange
	case "artifact-changed":
		return ErrArtifactChanged
	case "watch-unsupported":
		return ErrWatchUnsupported
	case "watch-not-found":
		return ErrWatchNotFound
	case "watch-cursor":
		return ErrWatchCursor
	case "timeout-lifetime":
		return ErrTimeoutBeyondLifetime
	case "stdin-closed":
		return ErrStdinClosed
	case "stdin-unavailable":
		return ErrStdinUnavailable
	case "stdin-limit":
		return ErrStdinLimit
	case "busy":
		return ErrBusy
	case "unavailable":
		return fmt.Errorf("%w: %s", ErrUnavailable, response.Error)
	case "template-mismatch":
		return ErrTemplateMismatch
	case "invalid-selector":
		return ErrInvalidSelector
	case "closed":
		return ErrSessionClosed
	case "file-not-found":
		return ErrFileNotFound
	case "command-not-found":
		return ErrCommandNotFound
	case "file-denied":
		return ErrFileDenied
	case "file-too-large":
		return ErrFileTooLarge
	case "file-operation-limit":
		return ErrFileOperationLimit
	case "file-conflict":
		return ErrFileConflict
	case "invalid-path":
		return ErrInvalidFilePath
	case "file-io":
		return ErrFileIO
	default:
		return errors.New(response.Error)
	}
}

func readLauncherFrame(reader *bufio.Reader, limit int) ([]byte, error) {
	frame := make([]byte, 0, 4096)
	for len(frame) < limit {
		fragment, err := reader.ReadSlice('\n')
		frame = append(frame, fragment...)
		if len(frame) > limit {
			return nil, errors.New("launcher frame exceeds limit")
		}
		if err == nil {
			return frame, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
	return nil, errors.New("launcher frame exceeds limit")
}

func decodeLauncherFrame(frame []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("launcher frame must contain exactly one JSON object")
	}
	return nil
}

func writeLauncherSessionResponse(conn net.Conn, response launcherSessionResponse) error {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := json.NewEncoder(conn).Encode(response)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func handleLauncherSessionConnection(parent context.Context, conn *net.UnixConn, reader *bufio.Reader, first []byte, manager *Manager, options LauncherOptions, logger *slog.Logger, peer syscall.Ucred) {
	response := launcherSessionResponse{Protocol: launcherSessionProtocol}
	var create launcherSessionRequest
	if err := decodeLauncherFrame(first, &create); err != nil || create.Protocol != launcherSessionProtocol || create.Operation != "create" || create.Create == nil || create.Command != nil || create.File != nil || create.CommandID != "" || create.After != 0 || create.SessionID != "" || !safeTenantID(create.Tenant) {
		response.Error, response.Code = "invalid session create request", "invalid"
		_ = writeLauncherSessionResponse(conn, response)
		return
	}
	requestID, err := randomID()
	if err != nil {
		return
	}
	event := AuditEvent{RequestID: requestID, Tenant: create.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid}
	record := func(kind, code, jobID, state string, duration time.Duration) error {
		if options.Audit == nil {
			return nil
		}
		event.Event, event.Code, event.JobID, event.State, event.DurationMS = kind, code, jobID, state, duration.Milliseconds()
		return options.Audit.Append(event)
	}
	create.Create.startupStarted = time.Now()
	if err := record("session.create.admitted", "", "", "", 0); err != nil {
		response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
		_ = writeLauncherSessionResponse(conn, response)
		return
	}
	create.Create.tenantID = create.Tenant
	started := time.Now()
	createCtx, stopCreate := context.WithTimeout(parent, 15*time.Second)
	stopDisconnect := watchSessionCreateDisconnect(conn, stopCreate)
	session, err := manager.StartSession(createCtx, *create.Create)
	stopDisconnect()
	if err == nil && createCtx.Err() != nil {
		_ = session.Close()
		err = createCtx.Err()
	}
	stopCreate()
	if err != nil {
		response.Error, response.Code = launcherSessionErrorFields(err)
		_ = record("session.create.rejected", response.Code, "", "", time.Since(started))
		_ = writeLauncherSessionResponse(conn, response)
		return
	}
	defer func() {
		closeErr := session.Close()
		code := ""
		if closeErr != nil {
			code = "cleanup-failed"
			logger.Error("session cleanup failed", "session_id", session.info.ID, "error", closeErr)
		}
		if closingID, err := randomID(); err == nil {
			event.RequestID = closingID
		}
		if err := record("session.closed", code, session.info.ID, "closed", time.Since(started)); err != nil {
			logger.Error("session close audit failed", "session_id", session.info.ID, "error", err)
		}
	}()
	if err := manager.registerOwnedSession(session, create.Tenant); err != nil {
		response.Error, response.Code = launcherSessionErrorFields(err)
		_ = writeLauncherSessionResponse(conn, response)
		return
	}
	if err := record("session.create.completed", "", session.info.ID, "running", time.Since(started)); err != nil {
		response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
		_ = writeLauncherSessionResponse(conn, response)
		return
	}
	session.commandAudit = func(id, state string, duration time.Duration) error {
		if options.Audit == nil {
			return nil
		}
		auditID, err := randomID()
		if err != nil {
			return err
		}
		return options.Audit.Append(AuditEvent{RequestID: auditID, Tenant: create.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid,
			Event: "session.command.completed", JobID: id, State: state, DurationMS: duration.Milliseconds()})
	}
	info := session.Info()
	session.artifactAudit = func(id, state string, value *SessionArtifactInfo, duration time.Duration) error {
		if options.Audit == nil {
			return errors.New("trusted audit recorder is unavailable")
		}
		record := AuditEvent{RequestID: id, Tenant: create.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid,
			Event: "session.artifact." + state, ArtifactID: id, JobID: session.info.ID, State: state, DurationMS: duration.Milliseconds()}
		if value != nil {
			record.ArtifactBytes, record.ArtifactEntries = value.Size, value.Entries
		}
		return options.Audit.Append(record)
	}
	response.Info = &info
	if err := writeLauncherSessionResponse(conn, response); err != nil {
		return
	}
	connectionCtx, stopConnection := context.WithCancel(parent)
	defer stopConnection()
	var clientClosing atomic.Bool
	go func() {
		select {
		case <-session.ctx.Done():
			_ = session.Close()
			if clientClosing.Load() {
				return
			}
		case <-connectionCtx.Done():
			return
		}
		stopConnection()
		_ = conn.Close()
	}()
	type incomingFrame struct {
		request launcherSessionRequest
		err     error
	}
	incoming := make(chan incomingFrame, 1)
	go func() {
		for {
			frame, err := readLauncherFrame(reader, 1<<20)
			if err != nil {
				stopConnection()
				return
			}
			var request launcherSessionRequest
			err = decodeLauncherFrame(frame, &request)
			select {
			case incoming <- incomingFrame{request: request, err: err}:
			case <-connectionCtx.Done():
				return
			}
			if err != nil {
				stopConnection()
				return
			}
		}
	}()
	for {
		select {
		case <-connectionCtx.Done():
			return
		case item := <-incoming:
			operationID, err := randomID()
			if err != nil {
				return
			}
			event.RequestID = operationID
			response = launcherSessionResponse{Protocol: launcherSessionProtocol}
			request := item.request
			if item.err != nil || request.Protocol != launcherSessionProtocol || request.Tenant != create.Tenant || request.SessionID != session.info.ID || request.Create != nil {
				response.Error, response.Code = "invalid session operation or owner", "invalid"
				_ = record("session.rpc.rejected", response.Code, session.info.ID, "", 0)
				_ = writeLauncherSessionResponse(conn, response)
				return
			}
			if (request.TTLMS != 0 && request.Operation != "timeout") || request.Operation == "timeout" && (request.Command != nil || request.File != nil || request.Input != nil || request.InputSequence != 0 || request.CommandID != "" || request.After != 0) {
				response.Error, response.Code = "invalid timeout operation", "invalid"
				_ = writeLauncherSessionResponse(conn, response)
				continue
			}
			if request.Operation == "timeout" {
				if err := record("session.timeout.admitted", "", session.info.ID, "", 0); err != nil {
					return
				}
				info, err := session.SetTimeout(request.TTLMS)
				if err != nil {
					response.Error, response.Code = launcherSessionErrorFields(err)
				} else {
					response.Info = &info
				}
				if err := record("session.timeout.completed", response.Code, session.info.ID, "", 0); err != nil {
					return
				}
				if err := writeLauncherSessionResponse(conn, response); err != nil {
					return
				}
				continue
			}
			if strings.HasPrefix(request.Operation, "command-") {
				if request.Operation == "command-start" {
					if err := record("session.command.admitted", "", session.info.ID, "", 0); err != nil {
						return
					}
				}
				response = session.commandRPC(request)
				if request.Operation == "command-start" {
					state := "rejected"
					if response.CommandInfo != nil {
						state = "running"
					}
					if err := record("session.command.started", response.Code, session.info.ID, state, 0); err != nil {
						return
					}
				}
				if err := writeLauncherSessionResponse(conn, response); err != nil {
					return
				}
				continue
			}
			if request.CommandID != "" || request.After != 0 {
				return
			}
			if request.Operation == "ping" {
				if request.Command != nil || request.File != nil {
					response.Error, response.Code = "ping does not accept a command", "invalid"
				} else {
					info := session.Info()
					response.Info = &info
				}
				if err := writeLauncherSessionResponse(conn, response); err != nil {
					return
				}
				continue
			}
			if request.Operation == "close" {
				if request.Command != nil || request.File != nil {
					response.Error, response.Code = "close does not accept a command", "invalid"
				} else {
					clientClosing.Store(true)
					if err := session.Close(); err != nil {
						response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
					}
				}
				_ = writeLauncherSessionResponse(conn, response)
				return
			}
			if request.Operation == "file" && request.File != nil && request.Command == nil {
				if err := record("session.file.admitted", "", session.info.ID, "", 0); err != nil {
					response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
					_ = writeLauncherSessionResponse(conn, response)
					return
				}
				fileStarted := time.Now()
				result, fileErr := session.File(connectionCtx, *request.File)
				if fileErr != nil {
					response.Error, response.Code = launcherSessionErrorFields(fileErr)
				} else {
					response.File = &result
				}
				state := "rejected"
				if response.File != nil {
					state = "succeeded"
				}
				if err := record("session.file.completed", response.Code, session.info.ID, state, time.Since(fileStarted)); err != nil {
					response = launcherSessionResponse{Protocol: launcherSessionProtocol, Error: errAuditUnavailable.Error(), Code: "unavailable"}
					_ = writeLauncherSessionResponse(conn, response)
					return
				}
				if err := writeLauncherSessionResponse(conn, response); err != nil || errors.Is(fileErr, ErrUnavailable) || errors.Is(fileErr, ErrSessionClosed) {
					return
				}
				continue
			}
			if request.Operation != "run" || request.Command == nil || request.File != nil {
				response.Error, response.Code = "unsupported session operation", "invalid"
				_ = record("session.rpc.rejected", response.Code, session.info.ID, "", 0)
				_ = writeLauncherSessionResponse(conn, response)
				continue
			}
			if err := record("session.run.admitted", "", session.info.ID, "", 0); err != nil {
				response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
				_ = writeLauncherSessionResponse(conn, response)
				return
			}
			runStarted := time.Now()
			result, runErr := session.Run(connectionCtx, *request.Command)
			if runErr != nil {
				response.Error, response.Code = launcherSessionErrorFields(runErr)
			} else {
				response.Result = &result
			}
			state := "rejected"
			jobID := session.info.ID
			if response.Result != nil {
				state, jobID = result.RunResult.State, result.RunResult.ID
			}
			if err := record("session.run.completed", response.Code, jobID, state, time.Since(runStarted)); err != nil {
				response = launcherSessionResponse{Protocol: launcherSessionProtocol, Error: errAuditUnavailable.Error(), Code: "unavailable"}
				_ = writeLauncherSessionResponse(conn, response)
				return
			}
			if err := writeLauncherSessionResponse(conn, response); err != nil || errors.Is(runErr, ErrUnavailable) || errors.Is(runErr, ErrSessionClosed) {
				return
			}
		}
	}
}

// Before the create response, a valid client sends no further frame. Monitor
// EOF while boot/prepare runs, then interrupt only this read before handing
// the connection to the normal session reader. No command byte is consumed.
func watchSessionCreateDisconnect(conn net.Conn, cancel context.CancelFunc) func() {
	var stopping atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		var data [1]byte
		n, _ := conn.Read(data[:])
		if n > 0 || !stopping.Load() {
			cancel()
		}
	}()
	return func() {
		stopping.Store(true)
		_ = conn.SetReadDeadline(time.Now())
		<-done
		_ = conn.SetReadDeadline(time.Time{})
	}
}

func launcherSessionErrorFields(err error) (string, string) {
	switch {
	case errors.Is(err, ErrArtifactsUnsupported):
		return ErrArtifactsUnsupported.Error(), "artifacts-unsupported"
	case errors.Is(err, ErrArtifactLimit):
		return ErrArtifactLimit.Error(), "artifact-limit"
	case errors.Is(err, ErrArtifactTooLarge):
		return ErrArtifactTooLarge.Error(), "artifact-too-large"
	case errors.Is(err, ErrArtifactNotFound):
		return ErrArtifactNotFound.Error(), "artifact-not-found"
	case errors.Is(err, ErrArtifactRange):
		return ErrArtifactRange.Error(), "artifact-range"
	case errors.Is(err, ErrArtifactChanged):
		return ErrArtifactChanged.Error(), "artifact-changed"
	case errors.Is(err, ErrWatchUnsupported):
		return ErrWatchUnsupported.Error(), "watch-unsupported"
	case errors.Is(err, ErrWatchNotFound):
		return ErrWatchNotFound.Error(), "watch-not-found"
	case errors.Is(err, ErrWatchCursor):
		return ErrWatchCursor.Error(), "watch-cursor"
	case errors.Is(err, errAuditUnavailable):
		return errAuditUnavailable.Error(), "unavailable"
	case errors.Is(err, ErrTimeoutBeyondLifetime):
		return err.Error(), "timeout-lifetime"
	case errors.Is(err, ErrStdinClosed):
		return ErrStdinClosed.Error(), "stdin-closed"
	case errors.Is(err, ErrStdinUnavailable):
		return ErrStdinUnavailable.Error(), "stdin-unavailable"
	case errors.Is(err, ErrStdinLimit):
		return ErrStdinLimit.Error(), "stdin-limit"
	case errors.Is(err, ErrBusy):
		return ErrBusy.Error(), "busy"
	case errors.Is(err, ErrUnavailable):
		return "session backend unavailable", "unavailable"
	case errors.Is(err, ErrTemplateMismatch):
		return ErrTemplateMismatch.Error(), "template-mismatch"
	case errors.Is(err, ErrInvalidSelector):
		return ErrInvalidSelector.Error(), "invalid-selector"
	case errors.Is(err, ErrSessionClosed):
		return ErrSessionClosed.Error(), "closed"
	case errors.Is(err, ErrCommandNotFound):
		return ErrCommandNotFound.Error(), "command-not-found"
	case errors.Is(err, ErrFileNotFound):
		return ErrFileNotFound.Error(), "file-not-found"
	case errors.Is(err, ErrFileDenied):
		return ErrFileDenied.Error(), "file-denied"
	case errors.Is(err, ErrFileTooLarge):
		return ErrFileTooLarge.Error(), "file-too-large"
	case errors.Is(err, ErrFileOperationLimit):
		return ErrFileOperationLimit.Error(), "file-operation-limit"
	case errors.Is(err, ErrFileConflict):
		return ErrFileConflict.Error(), "file-conflict"
	case errors.Is(err, ErrInvalidFilePath):
		return ErrInvalidFilePath.Error(), "invalid-path"
	case errors.Is(err, ErrFileIO):
		return ErrFileIO.Error(), "file-io"
	default:
		return "invalid session request", "invalid"
	}
}
