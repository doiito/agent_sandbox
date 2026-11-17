package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const linuxWatchProtocol = "fc-watch/v1"
const linuxWatchPrefix = "FC_WATCH_EVENT "

var errWatchProtocol = errors.New("invalid directory watch protocol")

type linuxWatchRequest struct {
	Protocol     string             `json:"protocol"`
	SessionID    string             `json:"session_id"`
	WatchID      string             `json:"watch_id"`
	Nonce        string             `json:"nonce"`
	Path         string             `json:"path"`
	Recursive    bool               `json:"recursive,omitempty"`
	IncludeEntry bool               `json:"include_entry,omitempty"`
	TimeoutMS    int                `json:"timeout_ms,omitempty"`
	Binding      *linuxGuestBinding `json:"binding,omitempty"`
}

type linuxWatchFrame struct {
	Protocol  string             `json:"protocol"`
	SessionID string             `json:"session_id"`
	WatchID   string             `json:"watch_id"`
	Nonce     string             `json:"nonce"`
	Binding   *linuxGuestBinding `json:"binding,omitempty"`
	Kind      string             `json:"kind"`
	Event     *SessionWatchEvent `json:"event,omitempty"`
	Code      string             `json:"code,omitempty"`
}

type linuxWatchStream struct {
	connection net.Conn
	reader     *bufio.Reader
	request    linuxWatchRequest
	sequence   int
	stop       func() bool
	closeOnce  sync.Once
}

func (b FirecrackerLinuxBackend) openFileWatch(startCtx, lifetime context.Context, request linuxWatchRequest, workdir string) (*linuxWatchStream, error) {
	if !b.FileWatch {
		return nil, ErrWatchUnsupported
	}
	if !validSessionID(request.SessionID) || !validSessionID(request.WatchID) || !validSHA256Hex(request.Nonce) ||
		b.Pristine != (request.Binding != nil) || request.Binding != nil && (!request.Binding.valid() || request.Binding.SessionID != request.SessionID) {
		return nil, errors.New("invalid directory watch identity or prepared binding")
	}
	if err := (SessionWatchRequest{Path: request.Path, Recursive: request.Recursive, IncludeEntry: request.IncludeEntry, TimeoutMS: request.TimeoutMS}).Validate(); err != nil {
		return nil, err
	}
	request.Protocol = linuxWatchProtocol
	socket, err := b.vsockPath(workdir)
	if err != nil {
		return nil, err
	}
	handshake, cancel := context.WithTimeout(startCtx, 3*time.Second)
	defer cancel()
	stopLifetimeHandshake := context.AfterFunc(lifetime, cancel)
	defer stopLifetimeHandshake()
	connection, reader, stop, err := dialFirecrackerVsock(handshake, socket, linuxWatchPort)
	if err != nil {
		return nil, fmt.Errorf("%w: connect directory watch", ErrUnavailable)
	}
	success := false
	defer func() {
		if !success {
			stop()
			_ = connection.Close()
		}
	}()
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(payload)+1 > 8192 {
		return nil, errors.New("directory watch request exceeds guest limit")
	}
	if _, err = connection.Write(append(payload, '\n')); err != nil {
		return nil, fmt.Errorf("%w: send directory watch request", ErrUnavailable)
	}
	stream := &linuxWatchStream{connection: connection, reader: reader, request: request}
	first, err := stream.readFrame()
	if err != nil {
		if errors.Is(err, errWatchProtocol) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: directory watch transport closed before readiness", ErrUnavailable)
	}
	if first.Kind == "end" && first.Event == nil && validWatchEndCode(first.Code) {
		return nil, watchStartError(first.Code)
	}
	if first.Kind != "ready" || first.Code != "" || first.Event != nil {
		return nil, errWatchProtocol
	}
	if !stop() || handshake.Err() != nil || startCtx.Err() != nil {
		return nil, context.Canceled
	}
	if err = connection.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: directory watch transport deadline", ErrUnavailable)
	}
	stream.stop = context.AfterFunc(lifetime, func() { _ = connection.Close() })
	if lifetime.Err() != nil {
		stream.Close()
		return nil, lifetime.Err()
	}
	success = true
	return stream, nil
}

func watchStartError(code string) error {
	switch code {
	case "invalid_binding":
		return errWatchProtocol
	case "unsupported":
		return ErrWatchUnsupported
	case "not_found":
		return ErrFileNotFound
	case "denied":
		return ErrFileDenied
	case "too_large":
		return ErrFileTooLarge
	case "operation_limit":
		return ErrFileOperationLimit
	case "expired":
		return ErrSessionClosed
	}
	return fmt.Errorf("%w: directory watch initialization failed", ErrUnavailable)
}

func (s *linuxWatchStream) readFrame() (linuxWatchFrame, error) {
	var frame linuxWatchFrame
	line, err := readLauncherFrame(s.reader, sessionWatchFrameLimit)
	if err != nil {
		return frame, err
	}
	if !strings.HasPrefix(string(line), linuxWatchPrefix) {
		return frame, errWatchProtocol
	}
	if err = decodeLauncherFrame(line[len(linuxWatchPrefix):], &frame); err != nil {
		return frame, fmt.Errorf("%w: invalid frame", errWatchProtocol)
	}
	if frame.Protocol != linuxWatchProtocol || frame.SessionID != s.request.SessionID || frame.WatchID != s.request.WatchID || frame.Nonce != s.request.Nonce ||
		(frame.Binding == nil) != (s.request.Binding == nil) || frame.Binding != nil && *frame.Binding != *s.request.Binding {
		return frame, errWatchProtocol
	}
	return frame, nil
}

func (s *linuxWatchStream) Next() (*SessionWatchEvent, string, error) {
	frame, err := s.readFrame()
	if err != nil {
		return nil, "", err
	}
	if frame.Kind == "end" && frame.Event == nil && validWatchEndCode(frame.Code) {
		return nil, frame.Code, nil
	}
	if frame.Kind != "event" || frame.Event == nil || frame.Code != "" {
		return nil, "", errWatchProtocol
	}
	request := SessionWatchRequest{Path: s.request.Path, Recursive: s.request.Recursive, IncludeEntry: s.request.IncludeEntry}
	if err = frame.Event.validate(request, s.sequence); err != nil {
		return nil, "", fmt.Errorf("%w: invalid event", errWatchProtocol)
	}
	s.sequence = frame.Event.Sequence
	return frame.Event, "", nil
}

func (s *linuxWatchStream) Close() {
	s.closeOnce.Do(func() {
		if s.stop != nil {
			s.stop()
		}
		_ = s.connection.Close()
	})
}
