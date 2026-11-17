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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const launcherProtocol = "osv-sandbox-launcher/v1"

// A 1 MiB raw VMM output can expand to six bytes per control character during
// JSON escaping and is also present in the parsed guest envelope. Keep the RPC
// limit bounded but large enough for that worst-case production response.
const launcherResponseLimit = 16 << 20

type launcherRequest struct {
	Backend                string      `json:"backend,omitempty"`
	ArtifactManifestSHA256 string      `json:"artifact_manifest_sha256,omitempty"`
	Protocol               string      `json:"protocol"`
	Operation              string      `json:"operation"`
	Tenant                 string      `json:"tenant,omitempty"`
	Run                    *RunRequest `json:"run,omitempty"`
}

type launcherResponse struct {
	Templates    *TemplateCatalogReport `json:"templates,omitempty"`
	Protocol     string                 `json:"protocol"`
	Result       *RunResult             `json:"result,omitempty"`
	Doctor       *DoctorReport          `json:"doctor,omitempty"`
	Capabilities *CapabilityReport      `json:"capabilities,omitempty"`
	WarmPool     *WarmPoolSnapshot      `json:"warm_pool,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Code         string                 `json:"code,omitempty"`
}

type LauncherClient struct {
	SocketPath string
	Timeout    time.Duration
}

func (c LauncherClient) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "run", Tenant: request.tenantID, Run: &request})
	if err != nil {
		return RunResult{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if response.Error != "" {
		if response.Code == "busy" {
			return RunResult{}, ErrBusy
		}
		if response.Code == "unavailable" {
			return RunResult{}, fmt.Errorf("%w: %s", ErrUnavailable, response.Error)
		}
		if response.Code == "template-mismatch" {
			return RunResult{}, ErrTemplateMismatch
		}
		if response.Code == "invalid-selector" {
			return RunResult{}, ErrInvalidSelector
		}
		return RunResult{}, errors.New(response.Error)
	}
	if response.Result == nil {
		return RunResult{}, fmt.Errorf("%w: launcher omitted run result", ErrUnavailable)
	}
	return *response.Result, nil
}

func (c LauncherClient) Doctor() DoctorReport {
	timeout := c.Timeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "doctor"})
	if err != nil || response.Error != "" || response.Doctor == nil {
		detail := response.Error
		if err != nil {
			detail = err.Error()
		}
		if detail == "" {
			detail = "launcher omitted doctor report"
		}
		return DoctorReport{Checks: []DoctorCheck{{Name: "launcher", Detail: detail}}}
	}
	return *response.Doctor
}

func (c LauncherClient) Capabilities() (CapabilityReport, error) {
	return c.CapabilitiesFor("", "")
}

func (c LauncherClient) CapabilitiesFor(backend, digest string) (CapabilityReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "capabilities", Backend: backend, ArtifactManifestSHA256: digest})
	if err != nil {
		return CapabilityReport{}, err
	}
	if response.Error != "" {
		return CapabilityReport{}, launcherSessionError(launcherSessionResponse{Code: response.Code, Error: response.Error})
	}
	if response.Capabilities == nil || response.Capabilities.Protocol != "osv-sandbox-capabilities/v1" {
		return CapabilityReport{}, errors.New("launcher omitted a valid capabilities report")
	}
	return *response.Capabilities, nil
}

func (c LauncherClient) TemplateCatalog() (TemplateCatalogReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "templates"})
	if err != nil {
		return TemplateCatalogReport{}, err
	}
	if response.Error != "" {
		return TemplateCatalogReport{}, ErrUnavailable
	}
	if response.Templates == nil || response.Templates.Protocol != "osv-sandbox-template-catalog/v1" {
		return TemplateCatalogReport{}, errors.New("launcher omitted a valid template catalog")
	}
	return *response.Templates, nil
}

func (c LauncherClient) exchange(ctx context.Context, request launcherRequest) (launcherResponse, error) {
	if !filepath.IsAbs(c.SocketPath) {
		return launcherResponse{}, errors.New("launcher socket must be absolute")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 310 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return launcherResponse{}, fmt.Errorf("connect launcher: %w", err)
	}
	defer conn.Close()
	// Deadlines alone do not interrupt I/O when an HTTP client disconnects.
	stopClosing := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClosing()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		if ctx.Err() != nil {
			return launcherResponse{}, fmt.Errorf("send launcher request: %w", ctx.Err())
		}
		return launcherResponse{}, fmt.Errorf("send launcher request: %w", err)
	}
	var response launcherResponse
	decoder := json.NewDecoder(io.LimitReader(conn, launcherResponseLimit))
	if err := decoder.Decode(&response); err != nil {
		if ctx.Err() != nil {
			return launcherResponse{}, fmt.Errorf("read launcher response: %w", ctx.Err())
		}
		return launcherResponse{}, fmt.Errorf("read launcher response: %w", err)
	}
	if response.Protocol != launcherProtocol {
		return launcherResponse{}, errors.New("unexpected launcher protocol")
	}
	return response, nil
}

type LauncherOptions struct {
	PortAuth   *Authenticator
	AllowedUID int
	SocketUID  int
	SocketGID  int
	SocketMode os.FileMode
	Logger     *slog.Logger
	Audit      AuditRecorder
}

func ListenLauncher(socketPath string, options LauncherOptions) (*net.UnixListener, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("launcher socket must be absolute")
	}
	parent := filepath.Dir(socketPath)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("launcher socket parent: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("launcher socket parent must be a directory not writable by group or other")
	}
	if existing, err := os.Lstat(socketPath); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket launcher path")
		}
		probe, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return nil, errors.New("launcher socket is already active")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale launcher socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	mode := options.SocketMode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Chown(socketPath, options.SocketUID, options.SocketGID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func ServeLauncher(ctx context.Context, listener *net.UnixListener, manager *Manager, options LauncherOptions) (serveErr error) {
	if manager.config.Production && options.Audit == nil {
		return errAuditUnavailable
	}
	if options.PortAuth == nil {
		for _, member := range manager.templateMembers() {
			if !member.hasLinuxPortFeature() {
				continue
			}
			path := manager.config.AuthPolicyPath
			if path == "" {
				return errors.New("port-enabled launcher requires auth_policy_path")
			}
			if manager.config.Production {
				if err := trustedProductionConfigPath(path); err != nil {
					return err
				}
			}
			var err error
			options.PortAuth, err = LoadAuthenticator(path)
			if err != nil {
				return err
			}
			break
		}
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	var connections sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		_ = listener.Close()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		serveErr = errors.Join(serveErr, manager.Shutdown(shutdownCtx))
		connections.Wait()
	}()
	if err := manager.StartWarmPool(ctx, options.Audit); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		connections.Add(1)
		go func(conn *net.UnixConn) {
			defer connections.Done()
			handleLauncherConnection(ctx, conn, manager, options, logger)
		}(conn)
	}
}

func handleLauncherConnection(parent context.Context, conn *net.UnixConn, manager *Manager, options LauncherOptions, logger *slog.Logger) {
	defer conn.Close()
	credential, err := unixPeerCredential(conn)
	if err != nil || options.AllowedUID < 0 || int(credential.Uid) != options.AllowedUID {
		logger.Warn("launcher peer rejected", "error", err, "peer_uid", credential.Uid, "peer_pid", credential.Pid)
		if options.Audit != nil {
			_ = options.Audit.Append(AuditEvent{Event: "peer.rejected", PeerUID: credential.Uid, PeerPID: credential.Pid})
		}
		return
	}
	reader := bufio.NewReaderSize(conn, 1<<20)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := reader.ReadSlice('\n')
	if err != nil {
		return
	}
	var header struct {
		Protocol string `json:"protocol"`
	}
	if json.Unmarshal(frame, &header) != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if header.Protocol == launcherPortProtocol {
		handleLauncherPortConnection(parent, conn, reader, frame, manager, options, credential)
		return
	}
	if header.Protocol == launcherCodeProtocol {
		handleLauncherCodeConnection(parent, conn, frame, manager, options, credential)
		return
	}
	if header.Protocol == launcherInferenceProtocol {
		handleLauncherInferenceConnection(parent, conn, frame, manager, options, credential)
		return
	}
	if header.Protocol == launcherWatchProtocol {
		handleLauncherWatchConnection(parent, conn, frame, manager, options, credential)
		return
	}
	if header.Protocol == launcherArtifactProtocol {
		handleLauncherArtifactConnection(parent, conn, frame, manager, options, credential)
		return
	}
	if header.Protocol == launcherSessionProtocol {
		handleLauncherSessionConnection(parent, conn, reader, frame, manager, options, logger, credential)
		return
	}
	requestID, err := randomID()
	if err != nil {
		return
	}
	event := AuditEvent{RequestID: requestID, PeerUID: credential.Uid, PeerPID: credential.Pid}
	record := func(kind, code string) error {
		if options.Audit == nil {
			return nil
		}
		event.Event, event.Code = kind, code
		return options.Audit.Append(event)
	}
	var request launcherRequest
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Protocol != launcherProtocol {
		_ = record("rpc.rejected", "invalid")
		writeLauncherResponse(conn, launcherResponse{Protocol: launcherProtocol, Error: "invalid launcher request", Code: "invalid"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		_ = record("rpc.rejected", "invalid")
		writeLauncherResponse(conn, launcherResponse{Protocol: launcherProtocol, Error: "invalid launcher request", Code: "invalid"})
		return
	}
	requestCtx, cancel := context.WithCancel(parent)
	defer cancel()
	// Closing the client connection cancels the VMM even if the API process is
	// killed while a job is active.
	go func() {
		one := make([]byte, 1)
		_, _ = conn.Read(one)
		cancel()
	}()
	response := launcherResponse{Protocol: launcherProtocol}
	if request.Operation == "run" && manager.config.Production && !safeTenantID(request.Tenant) {
		_ = record("run.rejected", "invalid-tenant")
		writeLauncherResponse(conn, launcherResponse{Protocol: launcherProtocol, Error: "invalid tenant audit identity", Code: "invalid"})
		return
	}
	if safeTenantID(request.Tenant) {
		event.Tenant = request.Tenant
	}
	switch request.Operation {
	case "warm-status":
		status, _ := manager.WarmPoolStatus()
		response.WarmPool = &status
	case "doctor":
		report := manager.Doctor()
		if options.Audit != nil || manager.config.Production {
			check := auditAvailability(options.Audit)
			report.Checks = append(report.Checks, check)
			report.Ready = report.Ready && check.OK
		}
		response.Doctor = &report
	case "capabilities":
		report, capabilityErr := manager.CapabilitiesFor(request.Backend, request.ArtifactManifestSHA256)
		if capabilityErr != nil {
			response.Error, response.Code = launcherSessionErrorFields(capabilityErr)
		} else {
			response.Capabilities = &report
		}
	case "templates":
		report, err := manager.TemplateCatalog()
		if err != nil {
			response.Error, response.Code = "template catalog unavailable", "unavailable"
		} else {
			response.Templates = &report
		}
	case "run":
		if request.Run == nil {
			response.Error, response.Code = "run request is required", "invalid"
			_ = record("run.rejected", "invalid")
			break
		}
		request.Run.startupStarted = time.Now()
		request.Run.tenantID = request.Tenant
		if err := record("run.admitted", ""); err != nil {
			logger.Error("audit admission failed", "request_id", requestID, "error", err)
			response.Error, response.Code = errAuditUnavailable.Error(), "unavailable"
			break
		}
		started := time.Now()
		result, runErr := manager.Run(requestCtx, *request.Run)
		if runErr != nil {
			response.Error, response.Code = "launcher rejected request", "invalid"
			if errors.Is(runErr, ErrBusy) {
				response.Error, response.Code = ErrBusy.Error(), "busy"
			}
			if errors.Is(runErr, ErrUnavailable) {
				response.Error, response.Code = "signed artifact policy unavailable", "unavailable"
			}
			if errors.Is(runErr, ErrTemplateMismatch) {
				response.Error, response.Code = ErrTemplateMismatch.Error(), "template-mismatch"
			}
			if errors.Is(runErr, ErrInvalidSelector) {
				response.Error, response.Code = ErrInvalidSelector.Error(), "invalid-selector"
			}
			logger.Warn("sandbox launch rejected", "tenant", request.Tenant, "peer_uid", credential.Uid, "peer_pid", credential.Pid, "error", runErr)
		} else {
			response.Result = &result
			logger.Info("sandbox launch completed", "tenant", request.Tenant, "peer_uid", credential.Uid, "peer_pid", credential.Pid,
				"job_id", result.ID, "state", result.State, "duration_ms", time.Since(started).Milliseconds())
		}
		event.DurationMS = time.Since(started).Milliseconds()
		kind := "run.rejected"
		if response.Result != nil {
			kind = "run.completed"
			event.JobID, event.State = result.ID, result.State
		}
		if err := record(kind, response.Code); err != nil {
			logger.Error("audit completion failed", "request_id", requestID, "error", err)
			response = launcherResponse{Protocol: launcherProtocol, Error: errAuditUnavailable.Error(), Code: "unavailable"}
		}
	default:
		response.Error, response.Code = "unsupported launcher operation", "invalid"
		_ = record("rpc.rejected", "invalid")
	}
	writeLauncherResponse(conn, response)
}

func writeLauncherResponse(conn net.Conn, response launcherResponse) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = json.NewEncoder(conn).Encode(response)
}

func unixPeerCredential(conn *net.UnixConn) (syscall.Ucred, error) {
	var credential *syscall.Ucred
	raw, err := conn.SyscallConn()
	if err != nil {
		return syscall.Ucred{}, err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return syscall.Ucred{}, err
	}
	if socketErr != nil {
		return syscall.Ucred{}, socketErr
	}
	if credential == nil {
		return syscall.Ucred{}, errors.New("missing peer credential")
	}
	return *credential, nil
}

func LauncherSocketSecure(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("launcher socket %s must be a private Unix socket", strings.TrimSpace(path))
	}
	return nil
}
