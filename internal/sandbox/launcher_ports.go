package sandbox

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"syscall"
	"time"
)

const launcherPortProtocol = "osv-sandbox-launcher-port/v1"

type launcherPortRequest struct {
	PreviewID string             `json:"preview_id,omitempty"`
	Protocol  string             `json:"protocol"`
	Tenant    string             `json:"tenant"`
	SessionID string             `json:"session_id"`
	Nonce     string             `json:"nonce"`
	Operation string             `json:"operation"`
	ID        string             `json:"id"`
	Port      uint16             `json:"port"`
	Limits    *SessionPortLimits `json:"limits,omitempty"`
}

func (r launcherPortRequest) validate() error {
	if r.Protocol != launcherPortProtocol || !safeTenantID(r.Tenant) || !validSessionID(r.SessionID) || !validSHA256Hex(r.Nonce) || !validSessionID(r.ID) || r.Port == 0 || r.PreviewID != "" && !validSessionID(r.PreviewID) {
		return errPortProtocol
	}
	switch r.Operation {
	case "open":
		if r.Limits != nil && r.Limits.valid() {
			return nil
		}
	case "cancel", "info":
		if r.Limits == nil && r.PreviewID == "" {
			return nil
		}
	}
	return errPortProtocol
}

type launcherPortResponse struct {
	Protocol  string            `json:"protocol"`
	SessionID string            `json:"session_id"`
	Nonce     string            `json:"nonce"`
	ID        string            `json:"id"`
	Port      uint16            `json:"port"`
	Info      *SessionPortInfo  `json:"info,omitempty"`
	Error     *PortRequestError `json:"error,omitempty"`
}

func portRPCError(err error) *PortRequestError {
	var typed *PortRequestError
	if errors.As(err, &typed) {
		return typed
	}
	code := "unavailable"
	switch {
	case errors.Is(err, ErrSessionClosed):
		code = "closed"
	case errors.Is(err, ErrPortUnsupported):
		code = "unsupported"
	case errors.Is(err, ErrBusy):
		code = "quota"
	case errors.Is(err, errPortProtocol):
		code = "invalid_request"
	}
	return &PortRequestError{Code: code}
}

func (h *LauncherSessionClient) connectPortRPC(start, lifetime context.Context, request launcherPortRequest) (net.Conn, *bufio.Reader, SessionPortInfo, error) {
	var info SessionPortInfo
	if h.closed.Load() {
		return nil, nil, info, ErrSessionClosed
	}
	identity, err := newLinuxGuestBinding(h.id)
	if err != nil {
		return nil, nil, info, err
	}
	request.Protocol, request.Tenant, request.SessionID, request.Nonce = launcherPortProtocol, h.tenant, h.id, identity.Nonce
	if request.validate() != nil || !filepath.IsAbs(h.socketPath) {
		return nil, nil, info, errPortProtocol
	}
	ctx, cancel := context.WithTimeout(start, 5*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(lifetime, cancel)
	defer stopLifetime()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", h.socketPath)
	if err != nil {
		return nil, nil, info, portTransportError(err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return nil, nil, info, portTransportError(err)
	}
	reader := bufio.NewReaderSize(conn, portHandshakeLimit)
	frame, err := readLauncherFrame(reader, portHandshakeLimit)
	if err != nil {
		return nil, nil, info, portTransportError(err)
	}
	var reply launcherPortResponse
	if codeDecode(frame, &reply) != nil || reply.Protocol != launcherPortProtocol || reply.SessionID != h.id || reply.Nonce != request.Nonce || reply.ID != request.ID || reply.Port != request.Port || (reply.Info == nil) == (reply.Error == nil) {
		return nil, nil, info, errPortProtocol
	}
	if reply.Error != nil {
		code := reply.Error.Code
		if !validPortError(code) && code != "denied" && code != "closed" {
			return nil, nil, info, errPortProtocol
		}
		return nil, nil, info, reply.Error
	}
	info = *reply.Info
	if info.validate(request.ID, request.Port, portByteLimit) != nil || request.Operation == "open" && (info.Status != "open" && info.Status != "cancelling" || info.SentBytes != 0 || info.ReceivedBytes != 0) {
		return nil, nil, SessionPortInfo{}, errPortProtocol
	}
	if !stop() || ctx.Err() != nil || lifetime.Err() != nil || h.closed.Load() {
		return nil, nil, SessionPortInfo{}, context.Canceled
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, SessionPortInfo{}, portTransportError(err)
	}
	success = true
	return conn, reader, info, nil
}

func (h *LauncherSessionClient) OpenPort(start, lifetime context.Context, request SessionPortRequest) (*linuxPortStream, error) {
	return h.openPort(start, lifetime, request, "")
}

func (h *LauncherSessionClient) OpenPreviewPort(start, lifetime context.Context, request SessionPortRequest, previewID string) (*linuxPortStream, error) {
	if !validSessionID(previewID) {
		return nil, errPortProtocol
	}
	return h.openPort(start, lifetime, request, previewID)
}

func (h *LauncherSessionClient) openPort(start, lifetime context.Context, request SessionPortRequest, previewID string) (*linuxPortStream, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(lifetime, time.Duration(request.Limits.TimeoutMS)*time.Millisecond)
	conn, reader, _, err := h.connectPortRPC(start, bounded, launcherPortRequest{Operation: "open", ID: request.ID, Port: request.Port, Limits: &request.Limits, PreviewID: previewID})
	if err != nil {
		cancel()
		return nil, err
	}
	s := &linuxPortStream{connection: conn, reader: reader, cancel: cancel, request: linuxPortRequest{ID: request.ID, Port: request.Port, Limits: &request.Limits}}
	s.stop = context.AfterFunc(bounded, func() { _ = conn.Close() })
	if bounded.Err() != nil {
		s.Close()
		return nil, bounded.Err()
	}
	return s, nil
}

func (h *LauncherSessionClient) PortControl(ctx context.Context, id string, port uint16, operation string) (SessionPortInfo, error) {
	if operation != "cancel" && operation != "info" {
		return SessionPortInfo{}, errPortProtocol
	}
	conn, _, info, err := h.connectPortRPC(ctx, ctx, launcherPortRequest{Operation: operation, ID: id, Port: port})
	if conn != nil {
		_ = conn.Close()
	}
	return info, err
}

// The common launcher entry has already verified the Unix peer. Keep its
// reader: DATA may have arrived in the same read as the first JSON line.
func handleLauncherPortConnection(parent context.Context, conn *net.UnixConn, reader *bufio.Reader, first []byte, manager *Manager, options LauncherOptions, peer syscall.Ucred) {
	var request launcherPortRequest
	if len(first) > portHandshakeLimit || codeDecode(first, &request) != nil || request.validate() != nil {
		return
	}
	response := launcherPortResponse{Protocol: launcherPortProtocol, SessionID: request.SessionID, Nonce: request.Nonce, ID: request.ID, Port: request.Port}
	write := func() error {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err := json.NewEncoder(conn).Encode(response)
		_ = conn.SetWriteDeadline(time.Time{})
		return err
	}
	s, err := manager.ownedSession(request.SessionID, request.Tenant)
	if err != nil {
		response.Error = portRPCError(err)
		_ = write()
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	audit := func(kind string, info *SessionPortInfo, code string) error {
		if options.Audit == nil {
			return nil
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		event := AuditEvent{RequestID: id, Tenant: request.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid, JobID: request.SessionID, PreviewID: request.PreviewID,
			Event: "session.port." + kind, ConnectionID: request.ID, Port: request.Port, Code: code}
		if info != nil {
			event.State, event.SentBytes, event.ReceivedBytes = info.Status, info.SentBytes, info.ReceivedBytes
			if info.Error != nil {
				event.Code = *info.Error
			}
		}
		return options.Audit.Append(event)
	}
	if request.Operation != "open" {
		info, err := s.sessionPortControl(ctx, request.ID, request.Port, request.Operation)
		if request.Operation == "cancel" {
			if auditErr := audit("cancel", func() *SessionPortInfo {
				if err == nil {
					return &info
				}
				return nil
			}(), func() string {
				if err != nil {
					return portRPCError(err).Code
				}
				return ""
			}()); auditErr != nil {
				err = errAuditUnavailable
			}
		}
		if err != nil {
			response.Error = portRPCError(err)
		} else {
			response.Info = &info
		}
		_ = write()
		return
	}
	tenant := options.PortAuth.portTenant(request.Tenant)
	if request.PreviewID != "" && (tenant == nil || tenant.policy.Ports == nil || !tenant.policy.Ports.Preview) {
		response.Error = &PortRequestError{Code: "denied"}
		_ = audit("rejected", nil, "denied")
		_ = write()
		return
	}
	if err = audit("admitted", nil, ""); err != nil {
		response.Error = portRPCError(errAuditUnavailable)
		_ = write()
		return
	}
	stopDisconnect, err := watchPortPeerClose(conn, cancel)
	if err != nil {
		response.Error = portRPCError(ErrUnavailable)
		_ = write()
		return
	}
	defer stopDisconnect()
	p, err := s.openSessionPort(ctx, SessionPortRequest{ID: request.ID, Port: request.Port, Limits: *request.Limits}, tenant)
	stopDisconnect()
	if err == nil && ctx.Err() != nil {
		p.Close()
		err = ErrUnavailable
	}
	if err != nil {
		response.Error = portRPCError(err)
		_ = audit("rejected", nil, response.Error.Code)
		_ = write()
		return
	}
	defer p.Close()
	p.observeFinish(func(info *SessionPortInfo) {
		kind := "terminal"
		if info == nil {
			kind = "owner_destroyed"
		}
		if audit(kind, info, "") != nil {
			go func() { _ = s.Close() }()
		}
	})
	info := SessionPortInfo{ID: request.ID, Port: request.Port, Status: "open"}
	response.Info = &info
	if audit("opened", &info, "") != nil {
		response.Info = nil
		response.Error = portRPCError(errAuditUnavailable)
		_ = write()
		return
	}
	if write() != nil {
		return
	}
	cancel()
	// ctx is negotiation-only; parent and the original session own this stream.
	stopParent := context.AfterFunc(parent, func() { _ = conn.Close(); p.Close() })
	defer stopParent()
	bridgePortFrames(conn, reader, p)
}

type portFrameEndpoint interface {
	Write([]byte) (int, error)
	CloseWrite() error
	Next() (linuxPortFrame, error)
	Close()
}

func bridgePortFrames(conn net.Conn, reader *bufio.Reader, p portFrameEndpoint) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer p.Close()
		defer conn.Close()
		inputEOF := false
		for {
			var header [5]byte
			if _, err := io.ReadFull(reader, header[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(header[1:])
			switch header[0] {
			case portDataFrame:
				if inputEOF || size == 0 || size > portDataLimit {
					return
				}
				data := make([]byte, int(size))
				if _, err := io.ReadFull(reader, data); err != nil {
					return
				}
				if _, err := p.Write(data); err != nil {
					return
				}
			case portEOFFrame:
				if inputEOF || size != 0 || p.CloseWrite() != nil {
					return
				}
				inputEOF = true
			case 3:
				return
			default:
				return
			}
		}
	}()
	defer func() { _ = conn.Close(); p.Close(); <-done }()
	for {
		frame, err := p.Next()
		if err != nil {
			return
		}
		data := frame.Data
		if frame.Info != nil {
			data, err = json.Marshal(frame.Info)
			if err != nil {
				return
			}
		}
		var header [5]byte
		header[0] = frame.Kind
		binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if writePortBytes(conn, header[:]) != nil || writePortBytes(conn, data) != nil {
			return
		}
		if frame.Info != nil {
			return
		}
	}
}
