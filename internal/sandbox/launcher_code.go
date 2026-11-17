package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"time"
)

const launcherCodeProtocol = "osv-sandbox-launcher-code/v1"

type launcherCodeRequest struct {
	Protocol  string      `json:"protocol"`
	Tenant    string      `json:"tenant"`
	SessionID string      `json:"session_id"`
	Nonce     string      `json:"nonce"`
	Request   CodeCommand `json:"request"`
}

func (r launcherCodeRequest) validate() error {
	if r.Protocol != launcherCodeProtocol || !safeTenantID(r.Tenant) || !validSessionID(r.SessionID) || !validSHA256Hex(r.Nonce) {
		return errCodeProtocol
	}
	return r.Request.Validate()
}

type launcherCodeResponse struct {
	Protocol  string            `json:"protocol"`
	SessionID string            `json:"session_id"`
	Nonce     string            `json:"nonce"`
	Response  *CodeResponse     `json:"response,omitempty"`
	Error     *CodeRequestError `json:"error,omitempty"`
}

func (h *LauncherSessionClient) Code(ctx context.Context, command CodeCommand) (CodeResponse, error) {
	var result CodeResponse
	if h.closed.Load() {
		return result, ErrSessionClosed
	}
	identity, err := newLinuxGuestBinding(h.id)
	if err != nil {
		return result, err
	}
	request := launcherCodeRequest{launcherCodeProtocol, h.tenant, h.id, identity.Nonce, command}
	if err = request.validate(); err != nil {
		return result, err
	}
	if !filepath.IsAbs(h.socketPath) {
		return result, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", h.socketPath)
	if err != nil {
		return result, codeTransportError(bounded)
	}
	defer connection.Close()
	stop := context.AfterFunc(bounded, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	_ = connection.SetDeadline(deadline)
	encoder := json.NewEncoder(connection)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(request) != nil {
		return result, codeTransportError(bounded)
	}
	frame, err := readLauncherFrame(bufio.NewReaderSize(connection, 32<<10), codeFrameLimit)
	if err != nil {
		return result, codeTransportError(bounded)
	}
	var response launcherCodeResponse
	if codeDecode(frame, &response) != nil || response.Protocol != launcherCodeProtocol || response.SessionID != h.id || response.Nonce != identity.Nonce || (response.Response == nil) == (response.Error == nil) {
		_ = h.Close()
		return result, ErrUnavailable
	}
	if response.Error != nil {
		if !validCodeError(response.Error) {
			_ = h.Close()
			return result, ErrUnavailable
		}
		return result, response.Error
	}
	result = *response.Response
	if result.validate(h.id, command) != nil {
		_ = h.Close()
		return CodeResponse{}, ErrUnavailable
	}
	h.codeMu.Lock()
	if h.codeLanguages == nil {
		h.codeLanguages = map[string]string{}
	}
	contexts := result.Contexts
	if result.Context != nil {
		contexts = append(contexts, *result.Context)
	}
	for _, context := range contexts {
		if old := h.codeLanguages[context.ID]; old != "" && old != context.Language || len(h.codeLanguages) >= 256 && h.codeLanguages[context.ID] == "" {
			h.codeMu.Unlock()
			_ = h.Close()
			return CodeResponse{}, ErrUnavailable
		}
		h.codeLanguages[context.ID] = context.Language
	}
	h.codeMu.Unlock()
	return result, nil
}
func (h *LauncherSessionClient) codeLanguage(ctx context.Context, id string) (string, error) {
	h.codeMu.Lock()
	language := h.codeLanguages[id]
	h.codeMu.Unlock()
	if language != "" {
		return language, nil
	}
	response, err := h.Code(ctx, CodeCommand{Operation: "info", ContextID: id})
	if err != nil {
		return "", err
	}
	return response.Context.Language, nil
}
func codeError(err error) *CodeRequestError {
	var typed *CodeRequestError
	if errors.As(err, &typed) {
		return typed
	}
	code, message := "unavailable", "code response unavailable; query the known ID"
	switch {
	case errors.Is(err, ErrCodeUnsupported):
		code, message = "unsupported", ErrCodeUnsupported.Error()
	case errors.Is(err, ErrSessionClosed):
		code, message = "closed", "session not available"
	case errors.Is(err, ErrBusy):
		code, message = "busy", "code control is busy"
	}
	return &CodeRequestError{code, message}
}

// The common launcher entry has already verified the Unix peer credentials.
func handleLauncherCodeConnection(parent context.Context, connection *net.UnixConn, first []byte, manager *Manager, options LauncherOptions, peer syscall.Ucred) {
	var request launcherCodeRequest
	if codeDecode(first, &request) != nil || request.validate() != nil {
		return
	}
	response := launcherCodeResponse{Protocol: launcherCodeProtocol, SessionID: request.SessionID, Nonce: request.Nonce}
	write := func() {
		_ = connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
		encoder := json.NewEncoder(connection)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(response)
	}
	session, err := manager.ownedSession(request.SessionID, request.Tenant)
	if err != nil {
		response.Error = codeError(err)
		write()
		return
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	stopDisconnect := watchSessionCreateDisconnect(connection, cancel)
	defer stopDisconnect()
	mutating := request.Request.Operation != "list" && request.Request.Operation != "info" && request.Request.Operation != "execution"
	audit := func(state, code string) error {
		if options.Audit == nil || !mutating {
			return nil
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		return options.Audit.Append(AuditEvent{RequestID: id, Tenant: request.Tenant, PeerUID: peer.Uid, PeerPID: peer.Pid, JobID: request.SessionID, Event: "session.code." + request.Request.Operation + "." + state, Code: code})
	}
	if err = audit("admitted", ""); err != nil {
		_ = session.Close()
		response.Error = codeError(errAuditUnavailable)
		write()
		return
	}
	result, err := session.Code(ctx, request.Request)
	if auditErr := audit("completed", func() string {
		if err != nil {
			return codeError(err).Code
		}
		return ""
	}()); auditErr != nil {
		_ = session.Close()
		err = errAuditUnavailable
	}
	if err != nil {
		response.Error = codeError(err)
	} else {
		response.Response = &result
	}
	// ACK loss preserves the known-ID journal and the original owning session.
	write()
}
