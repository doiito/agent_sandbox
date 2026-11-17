package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"syscall"
	"time"
)

const launcherInferenceProtocol = "osv-sandbox-launcher-inference/v1"

type launcherInferenceRequest struct {
	Protocol   string                 `json:"protocol"`
	Tenant     string                 `json:"tenant"`
	SessionID  string                 `json:"session_id"`
	Nonce      string                 `json:"nonce"`
	Invocation InferenceInvokeRequest `json:"invocation"`
}
type launcherInferenceResponse struct {
	ErrorStatus int                    `json:"error_status,omitempty"`
	Protocol    string                 `json:"protocol"`
	SessionID   string                 `json:"session_id"`
	Nonce       string                 `json:"nonce"`
	Result      *InferenceInvokeResult `json:"result,omitempty"`
	Error       *InferenceError        `json:"error,omitempty"`
}

func (h *LauncherSessionClient) InvokeInference(ctx context.Context, invocation InferenceInvokeRequest) (InferenceInvokeResult, error) {
	if err := invocation.Validate(); err != nil {
		return InferenceInvokeResult{}, err
	}
	if h.closed.Load() {
		return InferenceInvokeResult{}, ErrSessionClosed
	}
	identity, err := newLinuxGuestBinding(h.id)
	if err != nil || !filepath.IsAbs(h.socketPath) {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_unavailable"), invocation.ID)
	}
	call, cancel := context.WithTimeout(ctx, 43*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(call, "unix", h.socketPath)
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_unavailable"), invocation.ID)
	}
	defer conn.Close()
	peer, err := unixPeerCredential(conn.(*net.UnixConn))
	if err != nil || peer.Uid != 0 {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_peer"), invocation.ID)
	}
	stop := context.AfterFunc(call, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := call.Deadline()
	_ = conn.SetDeadline(deadline)
	request := launcherInferenceRequest{launcherInferenceProtocol, h.tenant, h.id, identity.Nonce, invocation}
	encoder := json.NewEncoder(conn)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(request) != nil {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_unavailable"), invocation.ID)
	}
	// JSON encoding can double the bytes of literal U+2028/U+2029 in a
	// provider response. Preserve the advertised provider body limit.
	frame, err := readLauncherFrame(bufio.NewReaderSize(conn, 32<<10), 2*egressResponseLimit+(64<<10))
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_unavailable"), invocation.ID)
	}
	var response launcherInferenceResponse
	if decodeInferenceJSON(frame, &response) != nil || response.Protocol != launcherInferenceProtocol || response.SessionID != h.id || response.Nonce != identity.Nonce || (response.Result == nil) == (response.Error == nil) {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_protocol"), invocation.ID)
	}
	if response.Error != nil {
		if !safeEgressCode(response.Error.Code) || response.ErrorStatus < 400 || response.ErrorStatus > 599 || response.Error.InvocationID != "" && response.Error.InvocationID != invocation.ID {
			return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_protocol"), invocation.ID)
		}
		response.Error.Status = response.ErrorStatus
		return InferenceInvokeResult{}, inferenceFailure(response.Error, invocation.ID)
	}
	result := *response.Result
	if response.ErrorStatus != 0 || result.ValidateForTask(h.id, invocation.ID, invocation.Endpoint) != nil {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_protocol"), invocation.ID)
	}
	return result, nil
}

// The common entry has already authenticated the API's kernel Unix UID.
func handleLauncherInferenceConnection(parent context.Context, conn *net.UnixConn, first []byte, manager *Manager, options LauncherOptions, peer syscall.Ucred) {
	var request launcherInferenceRequest
	if decodeInferenceJSON(first, &request) != nil || request.Protocol != launcherInferenceProtocol || !safeTenantID(request.Tenant) || !canonicalJobID(request.SessionID) || !validSHA256Hex(request.Nonce) || request.Invocation.Validate() != nil {
		return
	}
	response := launcherInferenceResponse{Protocol: launcherInferenceProtocol, SessionID: request.SessionID, Nonce: request.Nonce}
	write := func() {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		encoder := json.NewEncoder(conn)
		encoder.SetEscapeHTML(false)
		if response.Error != nil {
			response.ErrorStatus = response.Error.Status
		}
		_ = encoder.Encode(response)
	}
	session, err := manager.ownedSession(request.SessionID, request.Tenant)
	if err != nil {
		response.Error = apiInferenceFailure(err, request.Invocation.ID)
		write()
		return
	}
	call, cancel := context.WithTimeout(parent, 42*time.Second)
	defer cancel()
	stop := watchSessionCreateDisconnect(conn, cancel)
	defer stop()
	audit := func(event, code string) error {
		if options.Audit == nil {
			return nil
		}
		return options.Audit.Append(AuditEvent{RequestID: request.Invocation.ID, Tenant: request.Tenant, JobID: request.SessionID,
			PeerUID: peer.Uid, PeerPID: peer.Pid, Event: "session.inference." + event, Code: code})
	}
	if audit("admitted", "") != nil {
		_ = session.Close()
		response.Error = inferenceFailure(inferenceError(503, "inference_audit"), request.Invocation.ID)
		write()
		return
	}
	result, err := session.invokeInference(call, request.Invocation, request.Tenant)
	code := ""
	if err != nil {
		code = apiInferenceFailure(err, request.Invocation.ID).Code
	}
	if audit("completed", code) != nil {
		_ = session.Close()
		err = inferenceError(503, "inference_audit")
	}
	if err != nil {
		response.Error = apiInferenceFailure(err, request.Invocation.ID)
	} else {
		response.Result = &result
	}
	write()
}
