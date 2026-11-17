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

const launcherArtifactProtocol = "osv-sandbox-launcher-artifact/v1"

type launcherArtifactRequest struct {
	Protocol   string                        `json:"protocol"`
	Operation  string                        `json:"operation"`
	Tenant     string                        `json:"tenant"`
	SessionID  string                        `json:"session_id"`
	Nonce      string                        `json:"nonce"`
	ArtifactID string                        `json:"artifact_id,omitempty"`
	Create     *SessionArtifactCreateRequest `json:"create,omitempty"`
	Read       *SessionArtifactReadRequest   `json:"read,omitempty"`
}

func (r launcherArtifactRequest) validate() error {
	if r.Protocol != launcherArtifactProtocol || !safeTenantID(r.Tenant) || !validSessionID(r.SessionID) || !validSHA256Hex(r.Nonce) {
		return errors.New("invalid artifact RPC owner")
	}
	switch r.Operation {
	case "create":
		if r.Create != nil && r.Read == nil && r.ArtifactID == "" {
			return r.Create.Validate()
		}
	case "read":
		if r.Create == nil && r.Read != nil && validSessionID(r.ArtifactID) {
			return r.Read.Validate()
		}
	case "delete":
		if r.Create == nil && r.Read == nil && validSessionID(r.ArtifactID) {
			return nil
		}
	}
	return errors.New("invalid artifact RPC operation")
}

type launcherArtifactResponse struct {
	Protocol  string                `json:"protocol"`
	SessionID string                `json:"session_id"`
	Nonce     string                `json:"nonce"`
	Info      *SessionArtifactInfo  `json:"info,omitempty"`
	Chunk     *SessionArtifactChunk `json:"chunk,omitempty"`
	Deleted   *bool                 `json:"deleted,omitempty"`
	Error     string                `json:"error,omitempty"`
	Code      string                `json:"code,omitempty"`
}

func (h *LauncherSessionClient) artifactExchange(ctx context.Context, request launcherArtifactRequest) (launcherArtifactResponse, error) {
	var response launcherArtifactResponse
	if h.closed.Load() {
		return response, ErrSessionClosed
	}
	identity, err := newLinuxGuestBinding(h.id)
	if err != nil {
		return response, err
	}
	request.Protocol, request.Tenant, request.SessionID, request.Nonce = launcherArtifactProtocol, h.tenant, h.id, identity.Nonce
	if err := request.validate(); err != nil {
		return response, err
	}
	if !filepath.IsAbs(h.socketPath) {
		return response, ErrUnavailable
	}
	limit := 5 * time.Second
	if request.Operation == "create" {
		limit = 34 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", h.socketPath)
	if err != nil {
		return response, artifactRPCTransportError(bounded)
	}
	defer connection.Close()
	stop := context.AfterFunc(bounded, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	_ = connection.SetDeadline(deadline)
	if json.NewEncoder(connection).Encode(request) != nil {
		return response, artifactRPCTransportError(bounded)
	}
	frame, err := readLauncherFrame(bufio.NewReaderSize(connection, 32<<10), 1<<20)
	if err != nil {
		return response, artifactRPCTransportError(bounded)
	}
	if decodeLauncherFrame(frame, &response) != nil || response.Protocol != launcherArtifactProtocol || response.SessionID != h.id || response.Nonce != request.Nonce {
		return response, ErrUnavailable
	}
	if response.Error != "" {
		if response.Info != nil || response.Chunk != nil || response.Deleted != nil || !validArtifactRPCError(response.Code) {
			return response, ErrUnavailable
		}
		return response, launcherSessionError(launcherSessionResponse{Code: response.Code, Error: response.Error})
	}
	if response.Code != "" {
		return response, ErrUnavailable
	}
	valid := false
	switch request.Operation {
	case "create":
		valid = response.Info != nil && response.Info.valid() && response.Info.SessionID == h.id && response.Info.Path == request.Create.Path && response.Chunk == nil && response.Deleted == nil
	case "read":
		valid = response.Chunk != nil && response.Chunk.valid(h.id, request.ArtifactID, *request.Read) && response.Info == nil && response.Deleted == nil
	case "delete":
		valid = response.Deleted != nil && *response.Deleted && response.Info == nil && response.Chunk == nil
	}
	if !valid {
		return response, ErrUnavailable
	}
	return response, nil
}

func artifactRPCTransportError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

func validArtifactRPCError(code string) bool {
	switch code {
	case "artifacts-unsupported", "artifact-limit", "artifact-too-large", "artifact-not-found", "artifact-range", "artifact-changed",
		"file-not-found", "file-denied", "file-io", "invalid-path", "busy", "closed", "invalid", "unavailable":
		return true
	}
	return false
}

func (h *LauncherSessionClient) CreateArtifact(ctx context.Context, request SessionArtifactCreateRequest) (SessionArtifactInfo, error) {
	r, err := h.artifactExchange(ctx, launcherArtifactRequest{Operation: "create", Create: &request})
	if err != nil {
		return SessionArtifactInfo{}, err
	}
	return *r.Info, nil
}
func (h *LauncherSessionClient) ReadArtifact(ctx context.Context, id string, request SessionArtifactReadRequest) (SessionArtifactChunk, error) {
	r, err := h.artifactExchange(ctx, launcherArtifactRequest{Operation: "read", ArtifactID: id, Read: &request})
	if err != nil {
		return SessionArtifactChunk{}, err
	}
	return *r.Chunk, nil
}
func (h *LauncherSessionClient) DeleteArtifact(ctx context.Context, id string) error {
	_, err := h.artifactExchange(ctx, launcherArtifactRequest{Operation: "delete", ArtifactID: id})
	return err
}

// Called after the same peer UID check as the persistent session owner. This
// connection carries a single RPC; read cancellation never closes that owner.
func handleLauncherArtifactConnection(parent context.Context, conn *net.UnixConn, first []byte, manager *Manager, options LauncherOptions, peer syscall.Ucred) {
	var request launcherArtifactRequest
	response := launcherArtifactResponse{Protocol: launcherArtifactProtocol}
	write := func() error {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		return json.NewEncoder(conn).Encode(response)
	}
	if decodeLauncherFrame(first, &request) != nil || request.validate() != nil {
		response.Error, response.Code = "invalid artifact RPC request", "invalid"
		_ = write()
		return
	}
	response.SessionID, response.Nonce = request.SessionID, request.Nonce
	session, err := manager.ownedSession(request.SessionID, request.Tenant)
	if err != nil {
		response.Error, response.Code = launcherSessionErrorFields(err)
		_ = write()
		return
	}
	limit := 4 * time.Second
	if request.Operation == "create" {
		limit = 32 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	stopDisconnect := watchSessionCreateDisconnect(conn, cancel)
	defer stopDisconnect()
	audit := func(state, code string) error {
		if options.Audit == nil {
			return nil
		}
		id, e := randomID()
		if e != nil {
			return e
		}
		if options.Audit.Append(AuditEvent{RequestID: id, Tenant: request.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid, JobID: request.SessionID,
			ArtifactID: request.ArtifactID, Event: "session.artifact.rpc." + request.Operation + "." + state, Code: code}) != nil {
			return errAuditUnavailable
		}
		return nil
	}
	created := ""
	committed := false
	defer func() {
		if created != "" && !committed {
			_ = session.artifacts.delete(created)
		}
	}()
	if err = audit("admitted", ""); err == nil {
		switch request.Operation {
		case "create":
			var info SessionArtifactInfo
			info, err = session.CreateArtifact(ctx, *request.Create)
			if err == nil {
				response.Info = &info
				created = info.ID
			}
		case "read":
			var chunk SessionArtifactChunk
			chunk, err = session.ReadArtifact(ctx, request.ArtifactID, *request.Read)
			if err == nil {
				response.Chunk = &chunk
			}
		case "delete":
			err = session.DeleteArtifact(ctx, request.ArtifactID)
			if err == nil {
				deleted := true
				response.Deleted = &deleted
			}
		}
	}
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("%w: artifact RPC interrupted", ErrUnavailable)
	}
	_, code := launcherSessionErrorFields(err)
	if err == nil {
		code = ""
	}
	if auditErr := audit("completed", code); auditErr != nil {
		err = auditErr
		_ = session.Close()
	}
	if err != nil {
		response.Info, response.Chunk, response.Deleted = nil, nil, nil
		response.Error, response.Code = launcherSessionErrorFields(err)
		if request.Operation == "create" && (ctx.Err() != nil || errors.Is(err, ErrUnavailable) || errors.Is(err, errAuditUnavailable)) {
			_ = session.Close()
		}
	}
	if write() == nil && err == nil {
		committed = true
	}
}
