package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Session holds one tenant lease and active reservation for an owned VM.
// The launcher, not the API process, holds this object and cleans it up when
// the long-lived controlling Unix connection ends.
type Session struct {
	lifecycleMu    sync.Mutex
	leaseDeadline  time.Time
	hardDeadline   time.Time
	leaseTimer     *time.Timer
	manager        *Manager
	backend        FirecrackerLinuxBackend
	info           SessionInfo
	workdir        string
	memory         int
	vcpus          int
	instance       *vmInstance
	ctx            context.Context
	cancel         context.CancelFunc
	active         *activeReservation
	binding        *linuxGuestBinding
	opMu           sync.Mutex
	closeOne       sync.Once
	closed         atomic.Bool
	closeErr       error
	commandsMu     sync.Mutex
	commands       map[string]*commandRecord
	commandOrder   []string
	commandAudit   func(string, string, time.Duration) error
	watchesMu      sync.Mutex
	watches        map[string]*watchRecord
	watchOrder     []string
	codeMu         sync.Mutex
	codeContexts   map[string]string
	codeExecutions map[string]codeExecutionBinding
	portsMu        sync.Mutex
	ports          map[string]*sessionPortRecord
	artifacts      artifactCache
	artifactAudit  func(string, string, *SessionArtifactInfo, time.Duration) error
}

func (m *Manager) StartSession(ctx context.Context, req SessionCreateRequest) (*Session, error) {
	if m.catalog != nil && m.owner == nil {
		selected, err := m.selectTemplate(req.Backend, req.ArtifactManifestSHA256)
		if err != nil {
			return nil, err
		}
		if selected != m {
			return selected.StartSession(ctx, req)
		}
	}
	if m.cleanupFailed.Load() || m.isStopping() {
		return nil, fmt.Errorf("%w: prior sandbox cleanup failed", ErrUnavailable)
	}
	if err := m.artifactAvailability(time.Now()); err != nil {
		return nil, err
	}
	req.Normalize(m.config)
	if err := req.Validate(m.config); err != nil {
		return nil, err
	}
	if req.Network == "proxy" && !m.hasLinuxProxyFeature() {
		return nil, errors.New("network=proxy requires a signed Linux vsock-proxy-v1 template")
	}
	if err := m.validateTemplateSelector(req.asRunRequest(m.config)); err != nil {
		return nil, err
	}
	backend, ok := m.backend.(FirecrackerLinuxBackend)
	if !ok {
		return nil, errors.New("session backend is unavailable")
	}
	if m.pool != nil {
		return m.startPreparedSession(ctx, req)
	}
	physical, active, err := m.reserveCold(req.MemoryMiB, req.VCPUs, ctx)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		physical.release()
		active.release()
		return nil, err
	}
	created := time.Now()
	hardDeadline := created.Add(time.Duration(sessionLifetimeMS(m.config)) * time.Millisecond)
	lifetimeCtx, stopLifetime := context.WithDeadline(context.Background(), hardDeadline)
	sessionCtx, stopSession := context.WithCancel(lifetimeCtx)
	cancel := func() { stopSession(); stopLifetime() }
	var instance *vmInstance
	var session *Session
	success := false
	defer func() {
		if success {
			return
		}
		cancel()
		if session != nil {
			_ = session.Close()
		} else if instance == nil || instance.Destroy() == nil {
			physical.release()
			active.release()
		}
	}()
	// Creation cancellation applies during boot and readiness, then the
	// independent tenant lease owns the lifetime after successful handoff.
	stopCreateCancel := context.AfterFunc(ctx, cancel)
	defer stopCreateCancel()
	bootRequest := req.asRunRequest(m.config)
	bootRequest.jobID = id
	instance, err = m.startVM(lifetimeCtx, backend, bootRequest, physical)
	if err != nil {
		return nil, err
	}
	session = &Session{
		manager: m, backend: backend, workdir: instance.workdir, instance: instance,
		memory: req.MemoryMiB, vcpus: req.VCPUs,
		ctx: sessionCtx, cancel: cancel, active: active,
		info: SessionInfo{
			Network: req.Network, StartupMode: "cold",
			ID: id, State: "running", Backend: m.config.Backend,
			ArtifactManifestSHA256: req.ArtifactManifestSHA256,
			CreatedAt:              created.UTC(), ExpiresAt: created.Add(time.Duration(req.TTLMS) * time.Millisecond).UTC(),
			MemoryMiB: req.MemoryMiB, VCPUs: req.VCPUs, GuestProtocol: linuxSessionProtocol,
		},
	}
	session.startLeaseWatch(created.Add(time.Duration(req.TTLMS)*time.Millisecond), hardDeadline)

	pingTimeout := 10 * time.Second
	if backend.CodeContexts {
		pingTimeout = 40 * time.Second
	}
	pingCtx, stopPing := context.WithTimeout(ctx, pingTimeout)
	defer stopPing()
	pingID, err := randomID()
	if err != nil {
		return nil, err
	}
	_, guestOK, err := backend.ExchangeSession(pingCtx, linuxJobRequest{JobID: pingID, Operation: "ping", requireCodeReady: backend.CodeContexts}, session.workdir)
	if err != nil {
		return nil, fmt.Errorf("session guest readiness: %w", err)
	}
	if !guestOK {
		return nil, errors.New("session guest rejected readiness ping")
	}
	if !stopCreateCancel() || ctx.Err() != nil || session.closed.Load() || instance.activate() != nil {
		return nil, ErrSessionClosed
	}
	success = true
	return session, nil
}

func (s *Session) Info() SessionInfo {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	info := s.infoSnapshotLocked()
	if s.closed.Load() || s.ctx.Err() != nil || s.instance.ctx.Err() != nil || !s.leaseDeadline.IsZero() && !time.Now().Before(s.leaseDeadline) {
		info.State = "closed"
	}
	return info
}

func (s *Session) Run(ctx context.Context, request SessionCommandRequest) (SessionCommandResult, error) {
	if request.InteractiveStdin {
		return SessionCommandResult{}, fmt.Errorf("interactive stdin requires background command start")
	}
	if !s.opMu.TryLock() {
		return SessionCommandResult{}, ErrBusy
	}
	defer s.opMu.Unlock()
	if s.closed.Load() || s.ctx.Err() != nil {
		return SessionCommandResult{}, ErrSessionClosed
	}
	request.Normalize(s.manager.config)
	if err := request.Validate(s.manager.config, s.memory, s.vcpus); err != nil {
		return SessionCommandResult{}, err
	}
	id, err := randomID()
	if err != nil {
		return SessionCommandResult{}, err
	}
	started := time.Now()
	commandCtx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutMS+1000)*time.Millisecond)
	stopSessionCancel := context.AfterFunc(s.ctx, cancel)
	defer stopSessionCancel()
	defer cancel()
	result, guestOK, err := s.backend.ExchangeSession(commandCtx, linuxJobRequest{
		JobID: id, Operation: "run", Binding: s.binding,
		Environment: request.Environment, Cwd: request.Cwd,
		Argv: append([]string{request.Entrypoint}, request.Args...), TimeoutMS: request.TimeoutMS,
	}, s.workdir)
	if err != nil {
		_ = s.Close()
		return SessionCommandResult{}, fmt.Errorf("%w: session guest exchange: %v", ErrUnavailable, err)
	}
	var guest struct {
		ExitCode        int  `json:"exit_code"`
		TimedOut        bool `json:"timed_out"`
		OutputTruncated bool `json:"output_truncated"`
	}
	if err := json.Unmarshal(result, &guest); err != nil {
		_ = s.Close()
		return SessionCommandResult{}, fmt.Errorf("%w: decode session result: %v", ErrUnavailable, err)
	}
	state := "succeeded"
	if guest.TimedOut {
		state = "timed_out"
	} else if !guestOK {
		state = "guest_error"
	}
	duration := time.Since(started)
	return SessionCommandResult{SessionID: s.info.ID, RunResult: RunResult{
		ID: id, State: state, Backend: s.backend.Name(), ExitCode: guest.ExitCode,
		TimedOut: guest.TimedOut, Duration: duration, DurationMS: duration.Milliseconds(),
		Output: linuxResultPrefix + string(result), OutputTruncated: guest.OutputTruncated,
		ProtocolOK: true, GuestResult: result,
	}}, nil
}

func (s *Session) File(ctx context.Context, request SessionFileRequest) (SessionFileResult, error) {
	if !s.opMu.TryLock() {
		return SessionFileResult{}, ErrBusy
	}
	defer s.opMu.Unlock()
	if s.closed.Load() || s.ctx.Err() != nil {
		return SessionFileResult{}, ErrSessionClosed
	}
	if err := request.Validate(); err != nil {
		return SessionFileResult{}, err
	}
	id, err := randomID()
	if err != nil {
		return SessionFileResult{}, err
	}
	fileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopSessionCancel := context.AfterFunc(s.ctx, cancel)
	defer stopSessionCancel()
	defer cancel()
	result, guestOK, err := s.backend.ExchangeSession(fileCtx, linuxJobRequest{
		JobID: id, Operation: "file", File: &request, Binding: s.binding,
	}, s.workdir)
	if err != nil {
		_ = s.Close()
		return SessionFileResult{}, fmt.Errorf("%w: session file exchange: %v", ErrUnavailable, err)
	}
	var guest struct {
		FileResult *struct {
			Action      string             `json:"action"`
			Path        string             `json:"path"`
			Destination *string            `json:"destination,omitempty"`
			Size        int                `json:"size"`
			DataBase64  *string            `json:"data_base64"`
			Kind        string             `json:"kind"`
			Entries     *[]string          `json:"entries"`
			Created     *bool              `json:"created"`
			Info        *SessionFileInfo   `json:"info"`
			EntryInfos  *[]SessionFileInfo `json:"entry_infos"`
		} `json:"file_result"`
		FileErrorCode string `json:"file_error_code"`
	}
	if err := json.Unmarshal(result, &guest); err != nil {
		_ = s.Close()
		return SessionFileResult{}, fmt.Errorf("%w: decode session file result: %v", ErrUnavailable, err)
	}
	if !guestOK {
		switch guest.FileErrorCode {
		case "not_found":
			return SessionFileResult{}, ErrFileNotFound
		case "denied":
			return SessionFileResult{}, ErrFileDenied
		case "too_large":
			return SessionFileResult{}, ErrFileTooLarge
		case "operation_limit":
			return SessionFileResult{}, ErrFileOperationLimit
		case "conflict":
			return SessionFileResult{}, ErrFileConflict
		case "invalid_path":
			return SessionFileResult{}, ErrInvalidFilePath
		case "io_error":
			return SessionFileResult{}, ErrFileIO
		default:
			_ = s.Close()
			return SessionFileResult{}, fmt.Errorf("%w: invalid session file error", ErrUnavailable)
		}
	}
	if guest.FileResult == nil || guest.FileErrorCode != "" ||
		guest.FileResult.Action != request.Action || guest.FileResult.Path != request.Path ||
		guest.FileResult.Size < 0 {
		_ = s.Close()
		return SessionFileResult{}, fmt.Errorf("%w: invalid session file result binding", ErrUnavailable)
	}
	value := SessionFileResult{SessionID: s.info.ID, Action: request.Action,
		Path: request.Path, Destination: guest.FileResult.Destination, Size: guest.FileResult.Size, DataBase64: guest.FileResult.DataBase64,
		Kind: guest.FileResult.Kind, Entries: guest.FileResult.Entries,
		Created: guest.FileResult.Created, Info: guest.FileResult.Info,
		EntryInfos: guest.FileResult.EntryInfos}
	valid := true
	switch request.Action {
	case "rename":
		valid = value.Destination != nil && request.Destination != nil && *value.Destination == *request.Destination &&
			value.Info != nil && value.DataBase64 == nil && value.Entries == nil && value.Created == nil && value.EntryInfos == nil
		if valid {
			valid = validSessionFileInfo(*value.Info, *request.Destination, filepath.Base(*request.Destination)) &&
				value.Info.Type == value.Kind && ((value.Kind == "file" && value.Info.Size == int64(value.Size)) ||
				(value.Kind != "file" && value.Size == 0))
		}
	case "write":
		decoded, _ := base64.StdEncoding.Strict().DecodeString(*request.DataBase64)
		valid = value.DataBase64 == nil && value.Kind == "" && value.Entries == nil && value.Created == nil &&
			value.Info == nil && value.EntryInfos == nil &&
			value.Size <= sessionFileLimit && value.Size == len(decoded)
	case "read":
		if value.DataBase64 == nil || value.Kind != "" || value.Entries != nil || value.Created != nil ||
			value.Info != nil || value.EntryInfos != nil || value.Size > sessionFileLimit {
			valid = false
		} else {
			decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(*value.DataBase64)
			valid = decodeErr == nil && base64.StdEncoding.EncodeToString(decoded) == *value.DataBase64 && len(decoded) == value.Size
		}
	case "list":
		valid = value.DataBase64 == nil && value.Kind == "" && value.Entries != nil && value.Created == nil &&
			value.Info == nil && value.Size == len(*value.Entries) && validateSessionFileEntries(*value.Entries) == nil
		if valid && value.EntryInfos != nil {
			valid = validateSessionFileInfoList(request.Path, *value.Entries, *value.EntryInfos)
		}
	case "stat", "info":
		valid = value.DataBase64 == nil && value.Entries == nil && value.Created == nil && value.EntryInfos == nil &&
			((value.Kind == "file" && value.Size <= 1<<40) || (value.Kind == "directory" && value.Size == 0) ||
				(request.Action == "info" && (value.Kind == "symlink" || value.Kind == "other") && value.Size == 0))
		if request.Action == "info" && value.Info == nil {
			valid = false
		}
		if valid && value.Info != nil {
			name := filepath.Base(request.Path)
			valid = validSessionFileInfo(*value.Info, request.Path, name) &&
				value.Info.Type == value.Kind &&
				(value.Kind != "file" || value.Info.Size == int64(value.Size))
		}
	case "delete", "remove":
		valid = value.DataBase64 == nil && value.Entries == nil && value.Kind == "" && value.Created == nil &&
			value.Info == nil && value.EntryInfos == nil && value.Size == 0
	case "mkdir":
		valid = value.DataBase64 == nil && value.Entries == nil && value.Kind == "" && value.Created != nil &&
			value.Info == nil && value.EntryInfos == nil && value.Size == 0
	default:
		valid = false
	}
	if request.Action != "rename" && value.Destination != nil {
		valid = false
	}
	if valid && (request.Action == "list" || request.Action == "stat" || request.Action == "info") &&
		(value.Info != nil || value.EntryInfos != nil) {
		encoded, encodeErr := json.Marshal(guest.FileResult)
		valid = encodeErr == nil && len(encoded) <= 256*1024
	}
	if !valid {
		_ = s.Close()
		return SessionFileResult{}, fmt.Errorf("%w: invalid session file result", ErrUnavailable)
	}
	return value, nil
}

func (s *Session) Close() error {
	s.closeOne.Do(func() {
		s.lifecycleMu.Lock()
		s.closed.Store(true)
		if s.leaseTimer != nil {
			s.leaseTimer.Stop()
		}
		s.lifecycleMu.Unlock()
		s.unregisterOwnedSession()
		s.closePortTransports()
		artifactErr := s.artifacts.close()
		watchErr := s.closeFileWatches()
		if (watchErr != nil || artifactErr != nil) && s.manager != nil {
			s.manager.markCleanupFailed()
		}
		if s.ctx.Err() == nil && s.instance.ctx.Err() == nil && s.opMu.TryLock() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			id, err := randomID()
			if err == nil {
				_, _, _ = s.backend.ExchangeSession(ctx, linuxJobRequest{JobID: id, Operation: "shutdown", Binding: s.binding}, s.workdir)
			}
			cancel()
			s.opMu.Unlock()
		}
		s.cancel()
		destroyErr := s.instance.Destroy()
		s.closeErr = errors.Join(artifactErr, watchErr, destroyErr)
		if destroyErr == nil {
			s.finishPortsAfterDestroy()
		}
		if s.closeErr == nil {
			s.active.release()
		}
	})
	return s.closeErr
}
