package sandbox

import (
	"bufio"
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
	Protocol  string      `json:"protocol"`
	Operation string      `json:"operation"`
	Tenant    string      `json:"tenant,omitempty"`
	Run       *RunRequest `json:"run,omitempty"`
}

type launcherResponse struct {
	Protocol string        `json:"protocol"`
	Result   *RunResult    `json:"result,omitempty"`
	Doctor   *DoctorReport `json:"doctor,omitempty"`
	Error    string        `json:"error,omitempty"`
	Code     string        `json:"code,omitempty"`
}

type LauncherClient struct {
	SocketPath string
	Timeout    time.Duration
}

func (c LauncherClient) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	response, err := c.exchange(ctx, launcherRequest{Protocol: launcherProtocol, Operation: "run", Tenant: request.tenantID, Run: &request})
	if err != nil {
		return RunResult{}, err
	}
	if response.Error != "" {
		if response.Code == "busy" {
			return RunResult{}, ErrBusy
		}
		return RunResult{}, errors.New(response.Error)
	}
	if response.Result == nil {
		return RunResult{}, errors.New("launcher omitted run result")
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

func (c LauncherClient) exchange(ctx context.Context, request launcherRequest) (launcherResponse, error) {
	if !filepath.IsAbs(c.SocketPath) {
		return launcherResponse{}, errors.New("launcher socket must be absolute")
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return launcherResponse{}, fmt.Errorf("connect launcher: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return launcherResponse{}, fmt.Errorf("send launcher request: %w", err)
	}
	var response launcherResponse
	decoder := json.NewDecoder(io.LimitReader(conn, launcherResponseLimit))
	if err := decoder.Decode(&response); err != nil {
		return launcherResponse{}, fmt.Errorf("read launcher response: %w", err)
	}
	if response.Protocol != launcherProtocol {
		return launcherResponse{}, errors.New("unexpected launcher protocol")
	}
	return response, nil
}

type LauncherOptions struct {
	AllowedUID int
	SocketUID  int
	SocketGID  int
	SocketMode os.FileMode
	Logger     *slog.Logger
	AuditSync  func() error
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

func ServeLauncher(ctx context.Context, listener *net.UnixListener, manager *Manager, options LauncherOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	var connections sync.WaitGroup
	defer connections.Wait()
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
			handleLauncherConnection(ctx, conn, manager, options.AllowedUID, logger, options.AuditSync)
		}(conn)
	}
}

func handleLauncherConnection(parent context.Context, conn *net.UnixConn, manager *Manager, allowedUID int, logger *slog.Logger, auditSync func() error) {
	defer conn.Close()
	credential, err := unixPeerCredential(conn)
	if err != nil || allowedUID < 0 || int(credential.Uid) != allowedUID {
		logger.Warn("launcher peer rejected", "error", err, "peer_uid", credential.Uid, "peer_pid", credential.Pid)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var request launcherRequest
	decoder := json.NewDecoder(io.LimitReader(bufio.NewReader(conn), 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Protocol != launcherProtocol {
		writeLauncherResponse(conn, launcherResponse{Protocol: launcherProtocol, Error: "invalid launcher request", Code: "invalid"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
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
		writeLauncherResponse(conn, launcherResponse{Protocol: launcherProtocol, Error: "invalid tenant audit identity", Code: "invalid"})
		return
	}
	switch request.Operation {
	case "doctor":
		report := manager.Doctor()
		response.Doctor = &report
	case "run":
		if request.Run == nil {
			response.Error, response.Code = "run request is required", "invalid"
			break
		}
		started := time.Now()
		result, runErr := manager.Run(requestCtx, *request.Run)
		if runErr != nil {
			response.Error, response.Code = "launcher rejected request", "invalid"
			if errors.Is(runErr, ErrBusy) {
				response.Error, response.Code = ErrBusy.Error(), "busy"
			}
			logger.Warn("sandbox launch rejected", "tenant", request.Tenant, "peer_uid", credential.Uid, "peer_pid", credential.Pid, "error", runErr)
		} else {
			response.Result = &result
			logger.Info("sandbox launch completed", "tenant", request.Tenant, "peer_uid", credential.Uid, "peer_pid", credential.Pid,
				"job_id", result.ID, "state", result.State, "duration_ms", time.Since(started).Milliseconds())
		}
	default:
		response.Error, response.Code = "unsupported launcher operation", "invalid"
	}
	if auditSync != nil {
		if err := auditSync(); err != nil {
			logger.Error("audit durability failure", "tenant", request.Tenant, "peer_uid", credential.Uid, "peer_pid", credential.Pid, "error", err)
			response = launcherResponse{Protocol: launcherProtocol, Error: "audit durability failure", Code: "internal"}
		}
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
