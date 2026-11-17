package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const commandOutputLimit = 64 * 1024
const commandHistoryLimit = 32

var ErrCommandNotFound = errors.New("session command not found")

type linuxCommandOutput struct {
	Protocol   string             `json:"protocol"`
	JobID      string             `json:"job_id"`
	Sequence   int                `json:"sequence"`
	Stream     string             `json:"stream"`
	DataBase64 string             `json:"data_base64"`
	Binding    *linuxGuestBinding `json:"binding,omitempty"`
}
type linuxCommandStarted struct {
	Protocol string             `json:"protocol"`
	JobID    string             `json:"job_id"`
	PID      int                `json:"pid"`
	Binding  *linuxGuestBinding `json:"binding,omitempty"`
}

func sameLinuxBinding(a, b *linuxGuestBinding) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

type SessionOutputEvent struct {
	Sequence   int    `json:"sequence"`
	Stream     string `json:"stream"`
	DataBase64 string `json:"data_base64"`
}
type SessionCommandInfo struct {
	InteractiveStdin bool              `json:"interactive_stdin"`
	StdinClosed      bool              `json:"stdin_closed"`
	ID               string            `json:"id"`
	SessionID        string            `json:"session_id"`
	State            string            `json:"state"`
	Entrypoint       string            `json:"entrypoint"`
	Args             []string          `json:"args"`
	StartedAt        time.Time         `json:"started_at"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	Error            string            `json:"error,omitempty"`
	PID              int               `json:"pid,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	Cwd              string            `json:"cwd,omitempty"`
}
type SessionCommandPage struct {
	Info         SessionCommandInfo    `json:"info"`
	Events       []SessionOutputEvent  `json:"events"`
	NextSequence int                   `json:"next_sequence"`
	Complete     bool                  `json:"complete"`
	Result       *SessionCommandResult `json:"result,omitempty"`
}
type commandRecord struct {
	input         chan linuxCommandInput
	inputPending  int
	inputBytes    int
	inputReceipts []SessionCommandInputReceipt
	mu            sync.Mutex
	info          SessionCommandInfo
	events        []SessionOutputEvent
	result        *SessionCommandResult
	finished      bool
	cancel        chan struct{}
	cancelled     bool
}

func (s *Session) StartCommand(request SessionCommandRequest) (SessionCommandInfo, error) {
	request.Normalize(s.manager.config)
	if err := request.Validate(s.manager.config, s.memory, s.vcpus); err != nil {
		return SessionCommandInfo{}, err
	}
	request.Args = append([]string(nil), request.Args...)
	request.Environment = copyCommandEnvironment(request.Environment)
	if !s.opMu.TryLock() {
		return SessionCommandInfo{}, ErrBusy
	}
	if s.closed.Load() || s.ctx.Err() != nil {
		s.opMu.Unlock()
		return SessionCommandInfo{}, ErrSessionClosed
	}
	id, err := randomID()
	if err != nil {
		s.opMu.Unlock()
		return SessionCommandInfo{}, err
	}
	record := &commandRecord{info: SessionCommandInfo{ID: id, SessionID: s.info.ID, State: "running", Entrypoint: request.Entrypoint, InteractiveStdin: request.InteractiveStdin, StdinClosed: !request.InteractiveStdin,
		Args: append([]string{}, request.Args...), Environment: copyCommandEnvironment(request.Environment), Cwd: request.Cwd, StartedAt: time.Now().UTC()}, events: []SessionOutputEvent{}, cancel: make(chan struct{}), input: make(chan linuxCommandInput, 1)}
	s.commandsMu.Lock()
	if s.commands == nil {
		s.commands = make(map[string]*commandRecord)
	}
	if len(s.commandOrder) >= commandHistoryLimit {
		delete(s.commands, s.commandOrder[0])
		s.commandOrder = s.commandOrder[1:]
	}
	s.commands[id] = record
	s.commandOrder = append(s.commandOrder, id)
	s.commandsMu.Unlock()
	info := record.info
	go s.executeCommand(record, request)
	return info, nil
}

func (s *Session) executeCommand(record *commandRecord, request SessionCommandRequest) {
	commandCtx, cancel := context.WithTimeout(s.ctx, time.Duration(request.TimeoutMS+2000)*time.Millisecond)
	defer cancel()
	raw, guestOK, err := s.backend.ExchangeSession(commandCtx, linuxJobRequest{JobID: record.info.ID, Operation: "run_stream", Binding: s.binding,
		Environment: request.Environment, Cwd: request.Cwd, InteractiveStdin: request.InteractiveStdin, commandInput: record.input, onInputAck: record.acknowledgeInput,
		onStarted: func(pid int) error { record.mu.Lock(); defer record.mu.Unlock(); record.info.PID = pid; return nil },
		Argv:      append([]string{request.Entrypoint}, request.Args...), TimeoutMS: request.TimeoutMS, commandCancel: record.cancel,
		onOutput: func(event SessionOutputEvent) error {
			record.mu.Lock()
			defer record.mu.Unlock()
			record.events = append(record.events, event)
			return nil
		}}, s.workdir)
	var guest struct {
		ExitCode        int  `json:"exit_code"`
		TimedOut        bool `json:"timed_out"`
		OutputTruncated bool `json:"output_truncated"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &guest)
	}
	if err != nil {
		_ = s.Close()
	}
	record.mu.Lock()
	defer func() { s.opMu.Unlock(); record.mu.Unlock() }()
	end := time.Now().UTC()
	record.info.CompletedAt = &end
	record.finished = true
	record.finishInput()
	if err != nil {
		record.info.State = "failed"
		record.info.Error = "command transport unavailable"
		return
	}
	state := "succeeded"
	if guest.TimedOut {
		state = "timed_out"
	} else if record.cancelled {
		state = "cancelled"
	} else if !guestOK {
		state = "guest_error"
	}
	elapsed := end.Sub(record.info.StartedAt)
	record.info.State = state
	result := SessionCommandResult{SessionID: s.info.ID, RunResult: RunResult{ID: record.info.ID, State: state, Backend: s.backend.Name(),
		ExitCode: guest.ExitCode, TimedOut: guest.TimedOut, Duration: elapsed, DurationMS: elapsed.Milliseconds(),
		Output: linuxResultPrefix + string(raw), OutputTruncated: guest.OutputTruncated, ProtocolOK: true, GuestResult: raw}}
	if s.commandAudit != nil {
		if err := s.commandAudit(record.info.ID, state, elapsed); err != nil {
			record.info.State = "failed"
			record.info.Error = "command audit unavailable"
			_ = s.Close()
			return
		}
	}
	record.result = &result
}

func (s *Session) command(id string) (*commandRecord, error) {
	if !validSessionID(id) {
		return nil, ErrCommandNotFound
	}
	s.commandsMu.Lock()
	record := s.commands[id]
	s.commandsMu.Unlock()
	if record == nil {
		return nil, ErrCommandNotFound
	}
	return record, nil
}
func (s *Session) ListCommands() []SessionCommandInfo {
	s.commandsMu.Lock()
	defer s.commandsMu.Unlock()
	infos := []SessionCommandInfo{}
	for _, id := range s.commandOrder {
		r := s.commands[id]
		r.mu.Lock()
		info := r.info
		info.Args = append([]string{}, info.Args...)
		info.Environment = copyCommandEnvironment(info.Environment)
		r.mu.Unlock()
		infos = append(infos, info)
	}
	return infos
}
func (s *Session) PollCommand(id string, after int) (SessionCommandPage, error) {
	r, err := s.command(id)
	if err != nil {
		return SessionCommandPage{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if after < 0 || after > len(r.events) {
		return SessionCommandPage{}, fmt.Errorf("invalid command output cursor")
	}
	end := after + 64
	if end > len(r.events) {
		end = len(r.events)
	}
	page := SessionCommandPage{Info: r.info, Events: append([]SessionOutputEvent{}, r.events[after:end]...), NextSequence: end, Complete: r.finished && end == len(r.events)}
	page.Info.Args = append([]string{}, page.Info.Args...)
	page.Info.Environment = copyCommandEnvironment(page.Info.Environment)
	if page.Complete {
		page.Result = r.result
	}
	return page, nil
}

func copyCommandEnvironment(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}
func (s *Session) CancelCommand(id string) (bool, error) {
	r, err := s.command(id)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished || r.cancelled {
		return false, nil
	}
	r.cancelled = true
	close(r.cancel)
	return true, nil
}
