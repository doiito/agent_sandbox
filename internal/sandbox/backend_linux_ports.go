package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const linuxPortProtocol = "fc-port/v1"
const linuxPortServicePort = 5004
const portHandshakeLimit = 4096
const portDataLimit = 16 * 1024
const portByteLimit = 64 * 1024 * 1024
const portDurationLimitMS = 300000
const portDataFrame byte = 1
const portEOFFrame byte = 2
const portFinishedFrame byte = 4

var ErrPortUnsupported = errors.New("port forwarding requires a signed Linux port-forward-v1 template")
var errPortProtocol = errors.New("invalid port relay protocol")

type PortRequestError struct {
	Code string `json:"code"`
}

func (e *PortRequestError) Error() string { return "port relay: " + e.Code }

// SessionPortLimits apply independently to each byte direction. Opening a port
// never extends the owning VM's hard lease.
type SessionPortLimits struct {
	MaxBytes      uint64 `json:"max_bytes"`
	TimeoutMS     uint64 `json:"timeout_ms"`
	IdleTimeoutMS uint64 `json:"idle_timeout_ms"`
}

func (l SessionPortLimits) valid() bool {
	return l.MaxBytes > 0 && l.MaxBytes <= portByteLimit && l.TimeoutMS > 0 &&
		l.TimeoutMS <= portDurationLimitMS && l.IdleTimeoutMS > 0 && l.IdleTimeoutMS <= portDurationLimitMS
}

type SessionPortInfo struct {
	ID            string  `json:"id"`
	Port          uint16  `json:"port"`
	Status        string  `json:"status"`
	SentBytes     uint64  `json:"sent_bytes"`
	ReceivedBytes uint64  `json:"received_bytes"`
	Error         *string `json:"error"`
}

func (i *SessionPortInfo) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 6 {
		return errPortProtocol
	}
	for _, key := range []string{"id", "port", "status", "sent_bytes", "received_bytes", "error"} {
		value, ok := fields[key]
		if !ok || key != "error" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errPortProtocol
		}
	}
	type plain SessionPortInfo
	var decoded plain
	if codeDecode(data, &decoded) != nil {
		return errPortProtocol
	}
	*i = SessionPortInfo(decoded)
	return nil
}

func (i SessionPortInfo) terminal() bool {
	return i.Status == "completed" || i.Status == "cancelled" || i.Status == "failed"
}

func validPortError(code string) bool {
	switch code {
	case "invalid_request", "invalid_binding", "unsupported", "unavailable", "expired", "not_found", "quota", "conflict",
		"cancelled", "service_closed", "connection_refused", "timeout", "idle_timeout", "connection_lost", "byte_limit", "protocol_error", "io_error":
		return true
	}
	return false
}

func (i SessionPortInfo) validate(id string, port uint16, maxBytes uint64) error {
	if i.ID != id || i.Port != port || i.SentBytes > maxBytes || i.ReceivedBytes > maxBytes {
		return errPortProtocol
	}
	switch i.Status {
	case "opening", "open", "cancelling", "completed":
		if i.Error == nil {
			return nil
		}
	case "cancelled":
		if i.Error != nil && (*i.Error == "cancelled" || *i.Error == "service_closed") {
			return nil
		}
	case "failed":
		if i.Error != nil {
			switch *i.Error {
			case "connection_refused", "timeout", "idle_timeout", "connection_lost", "byte_limit", "protocol_error", "io_error":
				return nil
			}
		}
	}
	return errPortProtocol
}

type linuxPortRequest struct {
	Protocol  string             `json:"protocol"`
	SessionID string             `json:"session_id"`
	Nonce     string             `json:"nonce"`
	Binding   *linuxGuestBinding `json:"binding,omitempty"`
	Operation string             `json:"operation"`
	ID        string             `json:"id"`
	Port      uint16             `json:"port"`
	Limits    *SessionPortLimits `json:"limits,omitempty"`
}

func (b FirecrackerLinuxBackend) validatePortRequest(r linuxPortRequest) error {
	if !b.PortForward {
		return ErrPortUnsupported
	}
	if !validSessionID(r.SessionID) || !validSessionID(r.ID) || !validSHA256Hex(r.Nonce) || r.Port == 0 ||
		b.Pristine != (r.Binding != nil) || r.Binding != nil && (!r.Binding.valid() || r.Binding.SessionID != r.SessionID) {
		return errPortProtocol
	}
	switch r.Operation {
	case "open":
		if r.Limits != nil && r.Limits.valid() {
			return nil
		}
	case "cancel", "info":
		if r.Limits == nil {
			return nil
		}
	}
	return errPortProtocol
}

type linuxPortReply struct {
	Protocol  string             `json:"protocol"`
	SessionID string             `json:"session_id"`
	Nonce     string             `json:"nonce"`
	Binding   *linuxGuestBinding `json:"binding"`
	ID        string             `json:"id"`
	Port      uint16             `json:"port"`
	Response  *SessionPortInfo   `json:"response"`
	Error     *string            `json:"error"`
}

func writePortBytes(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readPortJSON(reader io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > portHandshakeLimit {
		return errPortProtocol
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	if err := codeDecode(data, value); err != nil {
		return errPortProtocol
	}
	return nil
}

func portTransportError(err error) error {
	if errors.Is(err, errPortProtocol) {
		return errPortProtocol
	}
	return fmt.Errorf("%w: port transport ended without a verified response; query the known ID: %w", ErrUnavailable, err)
}

// connectPort negotiates only. No TCP payload is ever retried after this point.
func (b FirecrackerLinuxBackend) connectPort(start, lifetime context.Context, request linuxPortRequest, workdir string) (net.Conn, *bufio.Reader, SessionPortInfo, error) {
	var info SessionPortInfo
	if err := b.validatePortRequest(request); err != nil {
		return nil, nil, info, err
	}
	if lifetime.Err() != nil {
		return nil, nil, info, ErrSessionClosed
	}
	request.Protocol = linuxPortProtocol
	data, err := json.Marshal(request)
	if err != nil || len(data) > portHandshakeLimit {
		return nil, nil, info, errPortProtocol
	}
	socket, err := b.vsockPath(workdir)
	if err != nil {
		return nil, nil, info, err
	}
	handshake, cancel := context.WithTimeout(start, 3*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(lifetime, cancel)
	defer stopLifetime()
	connection, reader, stop, err := dialFirecrackerVsock(handshake, socket, linuxPortServicePort)
	if err != nil {
		return nil, nil, info, portTransportError(err)
	}
	defer stop()
	success := false
	defer func() {
		if !success {
			_ = connection.Close()
		}
	}()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err = writePortBytes(connection, header[:]); err == nil {
		err = writePortBytes(connection, data)
	}
	if err != nil {
		return nil, nil, info, portTransportError(err)
	}
	var reply linuxPortReply
	if err = readPortJSON(reader, &reply); err != nil {
		return nil, nil, info, portTransportError(err)
	}
	if reply.Protocol != linuxPortProtocol || reply.SessionID != request.SessionID || reply.Nonce != request.Nonce ||
		reply.ID != request.ID || reply.Port != request.Port || !sameCodeBinding(reply.Binding, request.Binding) || (reply.Response == nil) == (reply.Error == nil) {
		return nil, nil, info, errPortProtocol
	}
	if reply.Error != nil {
		if !validPortError(*reply.Error) {
			return nil, nil, info, errPortProtocol
		}
		return nil, nil, info, &PortRequestError{Code: *reply.Error}
	}
	info = *reply.Response
	if info.validate(request.ID, request.Port, portByteLimit) != nil || request.Operation == "open" &&
		(info.Status != "open" && info.Status != "cancelling" || info.SentBytes != 0 || info.ReceivedBytes != 0) {
		return nil, nil, SessionPortInfo{}, errPortProtocol
	}
	if !stop() || handshake.Err() != nil || start.Err() != nil || lifetime.Err() != nil {
		return nil, nil, SessionPortInfo{}, context.Canceled
	}
	if err = connection.SetDeadline(time.Time{}); err != nil {
		return nil, nil, SessionPortInfo{}, portTransportError(err)
	}
	success = true
	return connection, reader, info, nil
}

func (b FirecrackerLinuxBackend) exchangePortControl(ctx, lifetime context.Context, request linuxPortRequest, workdir string) (SessionPortInfo, error) {
	if request.Operation != "cancel" && request.Operation != "info" {
		return SessionPortInfo{}, errPortProtocol
	}
	connection, _, info, err := b.connectPort(ctx, lifetime, request, workdir)
	if connection != nil {
		_ = connection.Close()
	}
	return info, err
}

type linuxPortFrame struct {
	Kind byte
	Data []byte
	Info *SessionPortInfo
}

type linuxPortStream struct {
	connection io.ReadWriteCloser
	reader     *bufio.Reader
	request    linuxPortRequest
	stop       func() bool
	cancel     context.CancelFunc
	closeOnce  sync.Once
	readMu     sync.Mutex
	writeMu    sync.Mutex
	written    atomic.Uint64
	writeEOF   atomic.Bool
	readBytes  uint64
	readEOF    bool
	finished   bool
}

func (b FirecrackerLinuxBackend) openPort(start, lifetime context.Context, request linuxPortRequest, workdir string) (*linuxPortStream, error) {
	if request.Operation != "open" {
		return nil, errPortProtocol
	}
	if err := b.validatePortRequest(request); err != nil {
		return nil, err
	}
	limits := *request.Limits
	request.Limits = &limits
	if request.Binding != nil {
		binding := *request.Binding
		request.Binding = &binding
	}
	// Include negotiation time in the host's absolute upper bound. A cancelled
	// create request must not become the successful tunnel's lifetime context.
	bounded, cancel := context.WithTimeout(lifetime, time.Duration(request.Limits.TimeoutMS)*time.Millisecond)
	connection, reader, _, err := b.connectPort(start, bounded, request, workdir)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &linuxPortStream{connection: connection, reader: reader, request: request, cancel: cancel}
	s.stop = context.AfterFunc(bounded, func() { _ = connection.Close() })
	if bounded.Err() != nil {
		s.Close()
		return nil, bounded.Err()
	}
	return s, nil
}

func (s *linuxPortStream) Close() {
	s.closeOnce.Do(func() {
		s.stop()
		s.cancel()
		_ = s.connection.Close()
	})
}

func (s *linuxPortStream) writeFrame(kind byte, payload []byte) error {
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if err := writePortBytes(s.connection, header[:]); err != nil {
		s.Close()
		return err
	}
	if err := writePortBytes(s.connection, payload); err != nil {
		s.Close()
		return err
	}
	return nil
}

func (s *linuxPortStream) Write(data []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF.Load() {
		return 0, io.ErrClosedPipe
	}
	if uint64(len(data)) > s.request.Limits.MaxBytes-s.written.Load() {
		return 0, &PortRequestError{Code: "byte_limit"}
	}
	written := 0
	for len(data) != 0 {
		size := min(len(data), portDataLimit)
		// Reserve before sending: the peer can finish before this goroutine is
		// scheduled again after Write. Failed writes retain an uncertain outcome.
		s.written.Add(uint64(size))
		if err := s.writeFrame(portDataFrame, data[:size]); err != nil {
			return written, portTransportError(err)
		}
		written += size
		data = data[size:]
	}
	return written, nil
}

func (s *linuxPortStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeEOF.Swap(true) {
		return nil
	}
	if err := s.writeFrame(portEOFFrame, nil); err != nil {
		return portTransportError(err)
	}
	return nil
}

// Next preserves application EOF separately from FINISHED. A missing terminal
// frame, including an interrupted DATA frame, is never reported as success.
func (s *linuxPortStream) Next() (linuxPortFrame, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var frame linuxPortFrame
	if s.finished {
		return frame, io.EOF
	}
	fail := func(err error) (linuxPortFrame, error) {
		s.Close()
		return linuxPortFrame{}, portTransportError(err)
	}
	var header [5]byte
	if _, err := io.ReadFull(s.reader, header[:]); err != nil {
		return fail(err)
	}
	frame.Kind = header[0]
	size := binary.BigEndian.Uint32(header[1:])
	switch frame.Kind {
	case portDataFrame:
		if s.readEOF || size == 0 || size > portDataLimit || uint64(size) > s.request.Limits.MaxBytes-s.readBytes {
			return fail(errPortProtocol)
		}
	case portEOFFrame:
		if s.readEOF || size != 0 {
			return fail(errPortProtocol)
		}
	case portFinishedFrame:
		if size == 0 || size > portHandshakeLimit {
			return fail(errPortProtocol)
		}
	default:
		return fail(errPortProtocol)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(s.reader, data); err != nil {
		return fail(err)
	}
	switch frame.Kind {
	case portDataFrame:
		frame.Data = data
		s.readBytes += uint64(size)
	case portEOFFrame:
		s.readEOF = true
	case portFinishedFrame:
		var info SessionPortInfo
		if codeDecode(data, &info) != nil || info.validate(s.request.ID, s.request.Port, s.request.Limits.MaxBytes) != nil ||
			!info.terminal() || info.ReceivedBytes != s.readBytes || info.SentBytes > s.written.Load() ||
			info.Status == "completed" && (!s.readEOF || !s.writeEOF.Load() || info.SentBytes != s.written.Load()) {
			return fail(errPortProtocol)
		}
		frame.Info = &info
		s.finished = true
		s.Close()
	}
	return frame, nil
}
