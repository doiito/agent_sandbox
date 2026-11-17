package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const linuxCodeProtocol = "fc-code/v1"
const linuxCodePrefix = "FC_CODE_REPLY "
const linuxCodePort = 5003

type linuxCodeRequest struct {
	Protocol  string             `json:"protocol"`
	SessionID string             `json:"session_id"`
	Nonce     string             `json:"nonce"`
	Binding   *linuxGuestBinding `json:"binding,omitempty"`
	Request   CodeCommand        `json:"request"`
}
type linuxCodeReply struct {
	Protocol  string             `json:"protocol"`
	SessionID string             `json:"session_id"`
	Nonce     string             `json:"nonce"`
	Binding   *linuxGuestBinding `json:"binding,omitempty"`
	Response  *CodeResponse      `json:"response,omitempty"`
	Error     *CodeRequestError  `json:"error,omitempty"`
}

func sameCodeBinding(a, b *linuxGuestBinding) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func validCodeError(err *CodeRequestError) bool {
	if err == nil || err.Code == "" || len(err.Code) > 64 || len(err.Message) > 4096 {
		return false
	}
	for _, b := range []byte(err.Code) {
		if !(b >= 'a' && b <= 'z' || b == '_') {
			return false
		}
	}
	return true
}
func (b FirecrackerLinuxBackend) exchangeCode(ctx, lifetime context.Context, request linuxCodeRequest, workdir string) (CodeResponse, error) {
	var response CodeResponse
	if !b.CodeContexts {
		return response, ErrCodeUnsupported
	}
	if !validSessionID(request.SessionID) || !validSHA256Hex(request.Nonce) || b.Pristine != (request.Binding != nil) ||
		request.Binding != nil && (!request.Binding.valid() || request.Binding.SessionID != request.SessionID) {
		return response, errCodeProtocol
	}
	if err := request.Request.Validate(); err != nil {
		return response, err
	}
	request.Protocol = linuxCodeProtocol
	bytes, err := codeJSON(request)
	if err != nil {
		return response, err
	}
	if len(bytes)+1 > 128*1024 {
		return response, &CodeRequestError{Code: "invalid_request", Message: "encoded code request exceeds guest limit"}
	}
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(lifetime, cancel)
	defer stopLifetime()
	if lifetime.Err() != nil {
		return response, ErrSessionClosed
	}
	socket, err := b.vsockPath(workdir)
	if err != nil {
		return response, err
	}
	connection, reader, stop, err := dialFirecrackerVsock(bounded, socket, linuxCodePort)
	if err != nil {
		return response, codeTransportError(bounded)
	}
	defer stop()
	defer connection.Close()
	if _, err = connection.Write(append(bytes, '\n')); err != nil {
		return response, codeTransportError(bounded)
	}
	frame, err := readLauncherFrame(reader, codeFrameLimit)
	if err != nil {
		return response, codeTransportError(bounded)
	}
	if !strings.HasPrefix(string(frame), linuxCodePrefix) {
		return response, errCodeProtocol
	}
	var reply linuxCodeReply
	if codeDecode(frame[len(linuxCodePrefix):], &reply) != nil || reply.Protocol != linuxCodeProtocol || reply.SessionID != request.SessionID || reply.Nonce != request.Nonce ||
		!sameCodeBinding(reply.Binding, request.Binding) || (reply.Error == nil) == (reply.Response == nil) {
		return response, errCodeProtocol
	}
	if reply.Error != nil {
		if !validCodeError(reply.Error) {
			return response, errCodeProtocol
		}
		return response, reply.Error
	}
	response = *reply.Response
	if response.validate("", request.Request) != nil {
		return CodeResponse{}, errCodeProtocol
	}
	return response, nil
}
func codeTransportError(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: code response unavailable; query the known ID: %w", ErrUnavailable, ctx.Err())
	}
	return fmt.Errorf("%w: code response unavailable; query the known ID", ErrUnavailable)
}

type codeReadiness struct {
	Revision        int    `json:"revision"`
	KernelProtocol  string `json:"kernel_protocol"`
	PrewarmLanguage string `json:"prewarm_language"`
}

func (b FirecrackerLinuxBackend) validateCodeReadiness(request linuxJobRequest, result json.RawMessage) error {
	if !b.CodeContexts || !(request.requireCodeReady || request.Operation == "prepare") {
		return nil
	}
	var envelope struct {
		OK   bool           `json:"ok"`
		Code *codeReadiness `json:"code_service"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return errCodeProtocol
	}
	if !envelope.OK {
		return nil
	}
	if request.Prepare != nil && request.Prepare.Mode == "job" {
		if envelope.Code != nil {
			return errCodeProtocol
		}
		return nil
	}
	if envelope.Code == nil || envelope.Code.Revision != 1 || envelope.Code.KernelProtocol != "osv-code-kernel/v2" || envelope.Code.PrewarmLanguage != b.CodePrewarm {
		return errors.New("guest did not prove signed code prewarm readiness")
	}
	return nil
}
