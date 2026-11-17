package sandbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const codeFrameLimit = 256 * 1024
const codeSourceLimit = 64 * 1024
const codeOutputLimit = 64 * 1024
const codeResultLimit = 32 * 1024

var ErrCodeUnsupported = errors.New("code contexts require a signed Linux code-contexts-v1 template")
var errCodeProtocol = errors.New("invalid code control protocol")

type CodeRequestError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *CodeRequestError) Error() string { return e.Code + ": " + e.Message }

// CodeCommand is a closed union. Its JSON preserves required zero-valued
// timeout/cursor fields and rejects fields belonging to another operation.
type CodeCommand struct {
	Operation   string            `json:"operation"`
	ContextID   string            `json:"context_id,omitempty"`
	Generation  uint64            `json:"generation,omitempty"`
	ExecutionID string            `json:"execution_id,omitempty"`
	Language    string            `json:"language,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Code        string            `json:"code,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	TimeoutMS   uint64            `json:"timeout_ms,omitempty"`
	After       uint64            `json:"after,omitempty"`
}

func codeFields(operation string) []string {
	switch operation {
	case "create":
		return []string{"operation", "context_id", "language", "cwd"}
	case "default":
		return []string{"operation", "language"}
	case "list":
		return []string{"operation"}
	case "info":
		return []string{"operation", "context_id"}
	case "execute":
		return []string{"operation", "context_id", "generation", "execution_id", "code", "environment", "timeout_ms"}
	case "execution":
		return []string{"operation", "execution_id", "after"}
	case "cancel":
		return []string{"operation", "context_id", "generation", "execution_id"}
	case "restart", "remove":
		return []string{"operation", "context_id", "generation"}
	}
	return nil
}
func codeLanguage(value string) bool {
	return value == "python" || value == "javascript" || value == "typescript"
}
func codeCwd(value string) bool {
	return utf8.ValidString(value) && len(value) <= 1024 && path.IsAbs(value) &&
		(value == "/workspace" || strings.HasPrefix(value, "/workspace/")) && path.Clean(value) == value && strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) < 0
}
func (r CodeCommand) Validate() error {
	invalid := func() error {
		return &CodeRequestError{Code: "invalid_request", Message: "invalid code operation or fields"}
	}
	if codeFields(r.Operation) == nil {
		return invalid()
	}
	switch r.Operation {
	case "create":
		if !validSessionID(r.ContextID) || !codeLanguage(r.Language) || !codeCwd(r.Cwd) {
			return invalid()
		}
	case "default":
		if !codeLanguage(r.Language) {
			return invalid()
		}
	case "info", "restart", "remove", "execute", "cancel":
		if !validSessionID(r.ContextID) {
			return invalid()
		}
	}
	if r.Operation == "restart" || r.Operation == "remove" || r.Operation == "execute" || r.Operation == "cancel" {
		if r.Generation == 0 || r.Generation > 1<<53-1 {
			return invalid()
		}
	}
	if r.Operation == "execute" || r.Operation == "execution" || r.Operation == "cancel" {
		if !validSessionID(r.ExecutionID) {
			return invalid()
		}
	}
	if r.Operation == "execution" && r.After > 256 {
		return invalid()
	}
	if r.Operation == "execute" {
		if !utf8.ValidString(r.Code) || len(r.Code) > codeSourceLimit || strings.ContainsRune(r.Code, 0) || r.TimeoutMS > 300000 || len(r.Environment) > 64 {
			return invalid()
		}
		bytes := 0
		for key, value := range r.Environment {
			if len(key) == 0 || len(key) > 64 || len(value) > 8192 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return invalid()
			}
			for index, b := range []byte(key) {
				if !(b == '_' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || index > 0 && b >= '0' && b <= '9') {
					return invalid()
				}
			}
			bytes += len(key) + len(value)
		}
		if bytes > 16*1024 {
			return invalid()
		}
		encoded, _ := codeJSON(map[string]any{"code": r.Code, "env": r.Environment})
		if len(encoded) > 96*1024 {
			return invalid()
		}
	}
	return nil
}
func (r CodeCommand) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	values := map[string]any{"operation": r.Operation, "context_id": r.ContextID, "generation": r.Generation,
		"execution_id": r.ExecutionID, "language": r.Language, "cwd": r.Cwd, "code": r.Code, "after": r.After, "timeout_ms": r.TimeoutMS}
	environment := r.Environment
	if environment == nil {
		environment = map[string]string{}
	}
	values["environment"] = environment
	fields := map[string]any{}
	for _, name := range codeFields(r.Operation) {
		fields[name] = values[name]
	}
	return codeJSON(fields)
}
func (r *CodeCommand) UnmarshalJSON(data []byte) error {
	var header struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(data, &header) != nil {
		return errCodeProtocol
	}
	if err := codeExactFields(data, codeFields(header.Operation)); err != nil {
		return err
	}
	type plain CodeCommand
	var decoded plain
	if err := codeDecode(data, &decoded); err != nil {
		return err
	}
	*r = CodeCommand(decoded)
	return r.Validate()
}
func codeExactFields(data []byte, names []string) error {
	var fields map[string]json.RawMessage
	if names == nil || json.Unmarshal(data, &fields) != nil || len(fields) != len(names) {
		return errCodeProtocol
	}
	for _, name := range names {
		if value, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errCodeProtocol
		}
	}
	return nil
}
func codeDecode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errCodeProtocol
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errCodeProtocol
	}
	return nil
}
func codeJSON(value any) ([]byte, error) {
	var bytes bytes.Buffer
	encoder := json.NewEncoder(&bytes)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.Bytes()[:bytes.Len()-1], nil
}

type CodeContext struct {
	SessionID           string  `json:"session_id,omitempty"`
	ID                  string  `json:"id"`
	Generation          uint64  `json:"generation"`
	Language            string  `json:"language"`
	Cwd                 string  `json:"cwd"`
	State               string  `json:"state"`
	PID                 *uint32 `json:"pid"`
	Failure             *string `json:"failure"`
	DiscardedLateEvents uint64  `json:"discarded_late_events"`
	DiscardedLateBytes  uint64  `json:"discarded_late_bytes"`
}

func (c CodeContext) validate(session string) error {
	if c.SessionID != session || !validSessionID(c.ID) || !codeLanguage(c.Language) || !codeCwd(c.Cwd) || c.Generation == 0 || c.Generation > 1<<53-1 ||
		c.PID != nil && (*c.PID < 2 || *c.PID > 1<<31-1) || c.Failure != nil && len(*c.Failure) > 4096 || c.DiscardedLateEvents > 1024 || c.DiscardedLateBytes > 256*1024 {
		return errCodeProtocol
	}
	switch c.State {
	case "starting", "idle", "running", "interrupting", "stopping", "failed":
		return nil
	}
	return errCodeProtocol
}

type CodeEvent struct {
	Type          string          `json:"type"`
	Data          json.RawMessage `json:"data,omitempty"`
	IsMainResult  *bool           `json:"is_main_result,omitempty"`
	Name          string          `json:"name,omitempty"`
	Value         string          `json:"value,omitempty"`
	Traceback     string          `json:"traceback,omitempty"`
	Status        string          `json:"status,omitempty"`
	ContextUsable *bool           `json:"context_usable,omitempty"`
}

func codeEventFields(kind string) []string {
	switch kind {
	case "started":
		return []string{"type"}
	case "stdout", "stderr":
		return []string{"type", "data"}
	case "result":
		return []string{"type", "data", "is_main_result"}
	case "error":
		return []string{"type", "name", "value", "traceback"}
	case "finished":
		return []string{"type", "status", "context_usable"}
	}
	return nil
}
func (e *CodeEvent) UnmarshalJSON(data []byte) error {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &header) != nil {
		return errCodeProtocol
	}
	if err := codeExactFields(data, codeEventFields(header.Type)); err != nil {
		return err
	}
	type plain CodeEvent
	var value plain
	if err := codeDecode(data, &value); err != nil {
		return err
	}
	*e = CodeEvent(value)
	_, err := e.size()
	return err
}
func (e CodeEvent) MarshalJSON() ([]byte, error) {
	if _, err := e.size(); err != nil {
		return nil, err
	}
	values := map[string]any{"type": e.Type, "data": e.Data, "is_main_result": e.IsMainResult, "name": e.Name, "value": e.Value, "traceback": e.Traceback, "status": e.Status, "context_usable": e.ContextUsable}
	fields := map[string]any{}
	for _, name := range codeEventFields(e.Type) {
		fields[name] = values[name]
	}
	return codeJSON(fields)
}
func codeTerminal(status string) bool {
	return status == "completed" || status == "cancelled" || status == "timed_out" || status == "failed"
}
func boundedCodeJSON(value any, depth int) bool {
	if depth > 16 {
		return false
	}
	switch v := value.(type) {
	case string:
		return len(v) <= codeResultLimit
	case []any:
		if len(v) > 1024 {
			return false
		}
		for _, child := range v {
			if !boundedCodeJSON(child, depth+1) {
				return false
			}
		}
	case map[string]any:
		if len(v) > 1024 {
			return false
		}
		for k, child := range v {
			if len(k) > 1024 || !boundedCodeJSON(child, depth+1) {
				return false
			}
		}
	}
	return true
}
func (e CodeEvent) size() (int, error) {
	switch e.Type {
	case "started":
		return 0, nil
	case "stdout", "stderr":
		var data string
		if json.Unmarshal(e.Data, &data) != nil || len(data) > base64.StdEncoding.EncodedLen(codeOutputLimit) {
			return 0, errCodeProtocol
		}
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil || len(decoded) > codeOutputLimit || base64.StdEncoding.EncodeToString(decoded) != data {
			return 0, errCodeProtocol
		}
		return len(decoded), nil
	case "result":
		var data map[string]json.RawMessage
		if e.IsMainResult == nil || len(e.Data) > codeResultLimit || json.Unmarshal(e.Data, &data) != nil || len(data) == 0 || len(data) > 16 {
			return 0, errCodeProtocol
		}
		for mime, raw := range data {
			if len(mime) > 128 || !strings.ContainsRune(mime, '/') {
				return 0, errCodeProtocol
			}
			if mime != "application/json" {
				var text string
				if json.Unmarshal(raw, &text) != nil {
					return 0, errCodeProtocol
				}
			} else {
				var value any
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				if decoder.Decode(&value) != nil || !boundedCodeJSON(value, 0) {
					return 0, errCodeProtocol
				}
			}
		}
		return len(e.Data), nil
	case "error":
		if e.Name == "" || len(e.Name) > 512 || len(e.Value) > 16*1024 || len(e.Traceback) > 32*1024 {
			return 0, errCodeProtocol
		}
		return len(e.Name) + len(e.Value) + len(e.Traceback), nil
	case "finished":
		if e.ContextUsable == nil || !codeTerminal(e.Status) {
			return 0, errCodeProtocol
		}
		return 0, nil
	}
	return 0, errCodeProtocol
}

type CodeSequencedEvent struct {
	Sequence uint64    `json:"sequence"`
	Event    CodeEvent `json:"event"`
}
type CodeExecutionPage struct {
	Language      string               `json:"language,omitempty"`
	SessionID     string               `json:"session_id,omitempty"`
	ID            string               `json:"id"`
	ContextID     string               `json:"context_id"`
	Generation    uint64               `json:"generation"`
	Status        string               `json:"status"`
	Events        []CodeSequencedEvent `json:"events"`
	LastSequence  uint64               `json:"last_sequence"`
	NextSequence  uint64               `json:"next_sequence"`
	EventsEvicted bool                 `json:"events_evicted"`
	Failure       *string              `json:"failure"`
}

func (p CodeExecutionPage) validate(session string, request CodeCommand) error {
	if p.SessionID != session || (session == "" && p.Language != "" || session != "" && !codeLanguage(p.Language)) || p.ID != request.ExecutionID || !validSessionID(p.ContextID) || p.Generation == 0 || p.Generation > 1<<53-1 || p.Status != "running" && !codeTerminal(p.Status) ||
		p.Events == nil || len(p.Events) > 64 || p.LastSequence == 0 || p.LastSequence > 256 || request.After > p.LastSequence ||
		p.NextSequence != request.After+uint64(len(p.Events)) || p.NextSequence > p.LastSequence || p.Failure != nil && len(*p.Failure) > 4096 {
		return errCodeProtocol
	}
	if p.EventsEvicted {
		if p.Status == "running" || len(p.Events) != 0 || request.After >= p.LastSequence {
			return errCodeProtocol
		}
		return nil
	}
	if len(p.Events) == 0 && p.NextSequence < p.LastSequence {
		return errCodeProtocol
	}
	preempted := p.Status == "cancelled" && p.Failure != nil && *p.Failure == "cancelled_before_submit"
	if preempted && p.LastSequence != 1 {
		return errCodeProtocol
	}
	bytes := 0
	for index, item := range p.Events {
		if item.Sequence != request.After+uint64(index)+1 || (!preempted && (item.Event.Type == "started") != (item.Sequence == 1)) || preempted && item.Event.Type != "finished" {
			return errCodeProtocol
		}
		size, err := item.Event.size()
		if err != nil {
			return err
		}
		bytes += size
		if item.Event.Type == "finished" && (item.Sequence != p.LastSequence || item.Event.Status != p.Status || p.Status == "running") {
			return errCodeProtocol
		}
	}
	if bytes > codeOutputLimit {
		return errCodeProtocol
	}
	if p.NextSequence == p.LastSequence && codeTerminal(p.Status) && len(p.Events) > 0 && p.Events[len(p.Events)-1].Event.Type != "finished" {
		return errCodeProtocol
	}
	return nil
}

type CodeResponse struct {
	Kind      string
	Context   *CodeContext
	Contexts  []CodeContext
	Execution *CodeExecutionPage
}

func (r CodeResponse) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case "context":
		return codeJSON(struct {
			Kind  string       `json:"kind"`
			Value *CodeContext `json:"value"`
		}{r.Kind, r.Context})
	case "contexts":
		return codeJSON(struct {
			Kind  string        `json:"kind"`
			Value []CodeContext `json:"value"`
		}{r.Kind, r.Contexts})
	case "execution":
		return codeJSON(struct {
			Kind  string             `json:"kind"`
			Value *CodeExecutionPage `json:"value"`
		}{r.Kind, r.Execution})
	case "accepted", "removed":
		return codeJSON(struct {
			Kind string `json:"kind"`
		}{r.Kind})
	}
	return nil, errCodeProtocol
}
func (r *CodeResponse) UnmarshalJSON(data []byte) error {
	var frame struct {
		Kind  string          `json:"kind"`
		Value json.RawMessage `json:"value"`
	}
	if codeDecode(data, &frame) != nil {
		return errCodeProtocol
	}
	*r = CodeResponse{Kind: frame.Kind}
	switch frame.Kind {
	case "context":
		return codeDecode(frame.Value, &r.Context)
	case "contexts":
		return codeDecode(frame.Value, &r.Contexts)
	case "execution":
		return codeDecode(frame.Value, &r.Execution)
	case "accepted", "removed":
		if len(frame.Value) == 0 {
			return nil
		}
	}
	return errCodeProtocol
}
func (r CodeResponse) validate(session string, request CodeCommand) error {
	switch request.Operation {
	case "create", "default", "info", "restart":
		if r.Kind != "context" || r.Context == nil || r.Context.validate(session) != nil {
			return errCodeProtocol
		}
		c := r.Context
		if request.Operation != "default" && c.ID != request.ContextID || (request.Operation == "default" || request.Operation == "create") && c.Language != request.Language || request.Operation == "create" && c.Cwd != request.Cwd {
			return errCodeProtocol
		}
		if request.Operation == "restart" && c.Generation != request.Generation && c.Generation != request.Generation+1 {
			return errCodeProtocol
		}
	case "list":
		if r.Kind != "contexts" || r.Contexts == nil || len(r.Contexts) > 4 {
			return errCodeProtocol
		}
		seen := map[string]bool{}
		for _, c := range r.Contexts {
			if seen[c.ID] || c.validate(session) != nil {
				return errCodeProtocol
			}
			seen[c.ID] = true
		}
	case "execution":
		if r.Kind != "execution" || r.Execution == nil {
			return errCodeProtocol
		}
		return r.Execution.validate(session, request)
	case "execute", "cancel":
		if r.Kind != "accepted" {
			return errCodeProtocol
		}
	case "remove":
		if r.Kind != "removed" {
			return errCodeProtocol
		}
	default:
		return fmt.Errorf("%w: unknown response operation", errCodeProtocol)
	}
	return nil
}

// ValidateForSession lets authenticated API gateways enforce the same typed
// owner and result contract without reimplementing the guest protocol parser.
func (r CodeResponse) ValidateForSession(session string, request CodeCommand) error {
	if !validSessionID(session) || request.Validate() != nil {
		return errCodeProtocol
	}
	return r.validate(session, request)
}
func (r *CodeResponse) bindSession(session string) {
	if r.Context != nil {
		r.Context.SessionID = session
	}
	for i := range r.Contexts {
		r.Contexts[i].SessionID = session
	}
	if r.Execution != nil {
		r.Execution.SessionID = session
	}
}
