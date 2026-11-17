package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var portOperations = map[string]bool{"sandbox.ports.open": true, "sandbox.ports.write": true, "sandbox.ports.read": true,
	"sandbox.ports.close_write": true, "sandbox.ports.info": true, "sandbox.ports.cancel": true, "sandbox.ports.close": true}

func portCleanupTool(name string) bool {
	// Persistent history uses the bounded observation lane even while model
	// calls occupy every normal work slot.
	return name == "sandbox.ports.info" || name == "sandbox.ports.cancel" || name == "sandbox.ports.close" || name == "sandbox.preview.info" || name == "sandbox.preview.revoke" || name == "sandbox.ml.bill"
}
func portCapable(cap sandbox.CapabilityReport) bool {
	return cap.ArtifactAuthenticated && cap.Features.Sessions && cap.Features.PortForward && cap.Backend == "firecracker-linux" && (cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v6" || cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v7" || cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v8") && digestPattern.MatchString(cap.ArtifactManifestSHA256)
}
func portToolsFor(cap sandbox.CapabilityReport) []tool {
	if !portCapable(cap) {
		return nil
	}
	identity := func() map[string]any {
		return map[string]any{"session_id": handleSchema(), "connection_id": handleSchema(), "port": integerSchema(1, 65535)}
	}
	required := []string{"session_id", "connection_id", "port"}
	open := identity()
	open["max_bytes"] = integerSchema(1, 64<<20)
	open["timeout_ms"] = integerSchema(1, 300000)
	open["idle_timeout_ms"] = integerSchema(1, 300000)
	write := identity()
	write["data_base64"] = map[string]any{"type": "string", "contentEncoding": "base64", "minLength": 4, "maxLength": 21848}
	tools := []tool{toolDefinition("sandbox.ports.open", "Open one native duplex TCP tunnel to this VM's loopback port with a caller-known ID. Defaults: 64MiB each direction and 300000ms total/idle. No retry after uncertainty. MCP disconnect closes transport; guest cleanup is queried by ID.", false, open, required...),
		toolDefinition("sandbox.ports.write", "Write one 1..16384 byte DATA frame once; consumes bytes and never retries an uncertain write. One write may run concurrently with one read.", false, write, append(append([]string{}, required...), "data_base64")...)}
	for _, op := range []string{"read", "close_write", "info", "cancel", "close"} {
		description := map[string]string{"read": "Consume exactly one bounded data/eof/finished frame. EOF permits reverse writes and is not terminal proof. Cancelled/lost read cannot be replayed; query remote ID after uncertainty.",
			"close_write": "Send application EOF once without closing reverse data. This is not a TLS half-close.", "info": "Query remote connection state by known ID, including after local transport loss. No new admission discovery or data locks.",
			"cancel": "Request independent remote cancellation, including cancel-before-open. ACK may be cancelling; query info for terminal proof.", "close": "Close local data transport. Does not assert confirmed guest cleanup; use info/cancel."}[op]
		tools = append(tools, toolDefinition("sandbox.ports."+op, description, op == "info", identity(), required...))
	}
	return tools
}

type portRegistryKey struct{}
type portRecord struct {
	port             uint16
	tunnel           *sandbox.HTTPPortTunnel
	cancel           context.CancelFunc
	closed           bool
	reading, writing atomic.Bool
}
type portRegistry struct {
	ctx     context.Context
	mu      sync.Mutex
	closed  bool
	active  int
	records map[string]*portRecord
}

func newPortRegistry(ctx context.Context) *portRegistry {
	return &portRegistry{ctx: ctx, records: map[string]*portRecord{}}
}
func portKey(sid, id string) string { return sid + "/" + id }
func (r *portRegistry) closeRecord(record *portRecord) {
	r.mu.Lock()
	if record.closed {
		r.mu.Unlock()
		return
	}
	record.closed = true
	r.active--
	tunnel, cancel := record.tunnel, record.cancel
	record.tunnel, record.cancel = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if tunnel != nil {
		tunnel.Close()
	}
}
func (r *portRegistry) close() {
	r.mu.Lock()
	r.closed = true
	all := make([]*portRecord, 0, len(r.records))
	for _, p := range r.records {
		all = append(all, p)
	}
	r.mu.Unlock()
	for _, p := range all {
		r.closeRecord(p)
	}
}

type portToolRequest struct {
	Session  string  `json:"session_id"`
	ID       string  `json:"connection_id"`
	Port     uint16  `json:"port"`
	MaxBytes *uint64 `json:"max_bytes,omitempty"`
	Timeout  *uint64 `json:"timeout_ms,omitempty"`
	Idle     *uint64 `json:"idle_timeout_ms,omitempty"`
	Data     *string `json:"data_base64,omitempty"`
	decoded  []byte
}

func parsePortTool(name string, args json.RawMessage) (portToolRequest, error) {
	var value portToolRequest
	fields, ok := object(args)
	if !portOperations[name] || !ok || decodeStrict(args, &value) != nil || !handlePattern.MatchString(value.Session) || !handlePattern.MatchString(value.ID) || value.Port == 0 {
		return value, errors.New("invalid port arguments")
	}
	allowed := map[string]bool{"session_id": true, "connection_id": true, "port": true}
	if name == "sandbox.ports.open" {
		for _, key := range []string{"max_bytes", "timeout_ms", "idle_timeout_ms"} {
			allowed[key] = true
		}
	}
	if name == "sandbox.ports.write" {
		allowed["data_base64"] = true
		if value.Data == nil || len(*value.Data) > 21848 {
			return value, errors.New("invalid port DATA")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(*value.Data)
		if err != nil || len(data) < 1 || len(data) > 16384 || base64.StdEncoding.EncodeToString(data) != *value.Data {
			return value, errors.New("invalid port DATA")
		}
		value.decoded = data
	}
	for key, raw := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return value, errors.New("invalid port fields")
		}
	}
	for _, limit := range []struct {
		value *uint64
		max   uint64
	}{{value.MaxBytes, 64 << 20}, {value.Timeout, 300000}, {value.Idle, 300000}} {
		if limit.value != nil && (*limit.value == 0 || *limit.value > limit.max) {
			return value, errors.New("invalid port limits")
		}
	}
	return value, nil
}
func portToolFailure(err error, value portToolRequest, uncertain bool) outcome {
	var api *sandbox.HTTPPortError
	if errors.As(err, &api) {
		err = &apiFailure{Status: api.Status, Code: api.Code}
	}
	base := failure(err)
	var data map[string]json.RawMessage
	_ = json.Unmarshal(base.Data, &data)
	data["session_id"] = rawObject(value.Session)
	data["connection_id"] = rawObject(value.ID)
	data["port"] = rawObject(value.Port)
	data["outcome_uncertain"] = rawObject(uncertain)
	base.Data = rawObject(data)
	return base
}
func (s *Server) callPortTool(ctx context.Context, name string, args json.RawMessage) outcome {
	value, err := parsePortTool(name, args)
	if err != nil {
		return invalidArgs()
	}
	result := map[string]any{"session_id": value.Session, "connection_id": value.ID, "port": value.Port}
	path := fmt.Sprintf("/v2/sessions/%s/ports/%d/connections/%s", value.Session, value.Port, value.ID)
	if name == "sandbox.ports.info" || name == "sandbox.ports.cancel" {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		method := "GET"
		if name == "sandbox.ports.cancel" {
			method = "DELETE"
		}
		data, e := s.api.call(bounded, method, path, nil)
		if e != nil {
			return portToolFailure(e, value, method == "DELETE")
		}
		var envelope struct {
			Session    string                   `json:"session_id"`
			Connection *sandbox.SessionPortInfo `json:"connection"`
		}
		if decodeStrict(data, &envelope) != nil || envelope.Session != value.Session || envelope.Connection == nil || envelope.Connection.ValidateFor(value.ID, value.Port, 64<<20) != nil {
			return portToolFailure(errors.New("invalid port control proof"), value, false)
		}
		if envelope.Connection.Status == "completed" || envelope.Connection.Status == "cancelled" || envelope.Connection.Status == "failed" {
			if registry, ok := ctx.Value(portRegistryKey{}).(*portRegistry); ok {
				registry.mu.Lock()
				record := registry.records[portKey(value.Session, value.ID)]
				registry.mu.Unlock()
				if record != nil && record.port == value.Port {
					registry.closeRecord(record)
				}
			}
		}
		result["connection"] = envelope.Connection
		return outcome{Data: rawObject(result)}
	}
	registry, _ := ctx.Value(portRegistryKey{}).(*portRegistry)
	if registry == nil {
		return portToolFailure(errors.New("port transport requires a live MCP connection"), value, false)
	}
	key := portKey(value.Session, value.ID)
	if name == "sandbox.ports.open" {
		cap, e := s.api.ownerCapabilities(ctx, value.Session)
		if e != nil {
			return portToolFailure(e, value, false)
		}
		if !portCapable(cap) {
			return portToolFailure(errors.New("native ports unsupported by session"), value, false)
		}
		limits := sandbox.SessionPortLimits{MaxBytes: 64 << 20, TimeoutMS: 300000, IdleTimeoutMS: 300000}
		if value.MaxBytes != nil {
			limits.MaxBytes = *value.MaxBytes
		}
		if value.Timeout != nil {
			limits.TimeoutMS = *value.Timeout
		}
		if value.Idle != nil {
			limits.IdleTimeoutMS = *value.Idle
		}
		registry.mu.Lock()
		if registry.closed || registry.ctx.Err() != nil || registry.active >= 8 || len(registry.records) >= 256 || registry.records[key] != nil {
			registry.mu.Unlock()
			return portToolFailure(errors.New("local port quota or ID conflict"), value, false)
		}
		lifetime, cancel := context.WithTimeout(registry.ctx, time.Duration(limits.TimeoutMS)*time.Millisecond)
		record := &portRecord{port: value.Port, cancel: cancel}
		registry.records[key] = record
		registry.active++
		registry.mu.Unlock()
		tunnel, e := sandbox.OpenHTTPPortTunnel(ctx, lifetime, s.api.http, s.api.origin, s.api.token, value.Session, sandbox.SessionPortRequest{ID: value.ID, Port: value.Port, Limits: limits})
		if e != nil {
			registry.closeRecord(record)
			return portToolFailure(e, value, true)
		}
		registry.mu.Lock()
		closed := registry.closed || record.closed
		if !closed {
			record.tunnel = tunnel
		}
		registry.mu.Unlock()
		if closed {
			tunnel.Close()
			return portToolFailure(context.Canceled, value, true)
		}
		// Expiry reclaims only local transport capacity, never a remote VM slot.
		context.AfterFunc(lifetime, func() { registry.closeRecord(record) })
		result["transport_open"] = true
		return outcome{Data: rawObject(result), Rollback: func() { registry.closeRecord(record) }}
	}
	registry.mu.Lock()
	record := registry.records[key]
	if record == nil || record.port != value.Port {
		registry.mu.Unlock()
		return portToolFailure(errors.New("local port transport not found"), value, false)
	}
	tunnel, closed := record.tunnel, record.closed
	registry.mu.Unlock()
	if name == "sandbox.ports.close" {
		registry.closeRecord(record)
		result["transport_open"] = false
		result["cleanup_confirmed"] = false
		return outcome{Data: rawObject(result)}
	}
	if closed || tunnel == nil {
		return portToolFailure(errors.New("local port transport is closed; query known ID"), value, false)
	}
	lock := &record.writing
	if name == "sandbox.ports.read" {
		lock = &record.reading
	}
	if !lock.CompareAndSwap(false, true) {
		return portToolFailure(errors.New("port direction already in progress"), value, false)
	}
	defer lock.Store(false)
	stop := context.AfterFunc(ctx, func() { registry.closeRecord(record) })
	defer stop()
	switch name {
	case "sandbox.ports.write":
		n, e := tunnel.Write(value.decoded)
		if e != nil {
			registry.closeRecord(record)
			return portToolFailure(e, value, true)
		}
		result["written_bytes"] = n
	case "sandbox.ports.close_write":
		if e := tunnel.CloseWrite(); e != nil {
			registry.closeRecord(record)
			return portToolFailure(e, value, true)
		}
		result["write_closed"] = true
	case "sandbox.ports.read":
		frame, e := tunnel.Next()
		if e != nil {
			registry.closeRecord(record)
			return portToolFailure(e, value, true)
		}
		result["kind"] = frame.Kind
		if frame.Kind == "data" {
			result["data_base64"] = base64.StdEncoding.EncodeToString(frame.Data)
		}
		if frame.Info != nil {
			result["connection"] = frame.Info
			registry.closeRecord(record)
		}
	}
	return outcome{Data: rawObject(result)}
}
