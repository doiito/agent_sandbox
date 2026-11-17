package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"sync"
	"unicode/utf8"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

const ModernVersion = "2026-07-28"
const LegacyVersion = "2025-11-25"
const Version = "0.1.0"
const maxFrame = 1 << 20
const maxOutputFrame = 32 << 20
const versionKey = "io.modelcontextprotocol/protocolVersion"
const capabilitiesKey = "io.modelcontextprotocol/clientCapabilities"

var supportedVersions = []string{ModernVersion, LegacyVersion}
var serverInfo = map[string]any{"name": "osv-sandbox-mcp", "version": Version}

type Server struct {
	api         *apiClient
	maxInFlight int
}

func newServer(api *apiClient, maximum int) *Server { return &Server{api, maximum} }

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type activeRequest struct {
	key      string
	ctx      context.Context
	cancel   context.CancelFunc
	complete bool
	slot     chan struct{}
	released sync.Once
}
type output struct {
	data []byte
	done chan error
	task *activeRequest
}
type connection struct {
	server       *Server
	ctx          context.Context
	cancel       context.CancelFunc
	input        io.ReadCloser
	writer       io.WriteCloser
	mu           sync.Mutex
	active       map[string]*activeRequest
	slots        chan struct{}
	portControls chan struct{}
	pending      chan output
	wg           sync.WaitGroup
	writerDone   chan struct{}
	errMu        sync.Mutex
	err          error
	legacy       bool
	legacyReady  bool
}

// Serve owns its streams and closes them on EOF, cancellation or output failure.
// Persistent API handles are independent of this transport lifetime.
func (s *Server) Serve(parent context.Context, input io.ReadCloser, writer io.WriteCloser) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ports := newPortRegistry(ctx)
	defer ports.close()
	ctx = context.WithValue(ctx, portRegistryKey{}, ports)
	c := &connection{server: s, ctx: ctx, cancel: cancel, input: input, writer: writer, active: make(map[string]*activeRequest), slots: make(chan struct{}, s.maxInFlight), portControls: make(chan struct{}, 2), pending: make(chan output, 16), writerDone: make(chan struct{})}
	go func() { <-ctx.Done(); _ = input.Close(); _ = writer.Close() }()
	go c.writeLoop()
	reader := bufio.NewReaderSize(input, 64*1024)
	for {
		line, err := readFrame(reader)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				c.fail(err)
			}
			break
		}
		if !c.receive(line) {
			break
		}
	}
	cancel()
	ports.close()
	<-c.writerDone
	c.wg.Wait()
	s.api.http.CloseIdleConnections()
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}
func readFrame(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > maxFrame {
			return nil, errors.New("MCP input frame exceeds 1 MiB")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(line) > 0 {
			return nil, errors.New("MCP input ended within a frame")
		}
		return line, err
	}
}
func (c *connection) fail(err error) {
	if err != nil {
		c.errMu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.errMu.Unlock()
	}
	c.cancel()
}
func (c *connection) writeLoop() {
	defer close(c.writerDone)
	for {
		select {
		case <-c.ctx.Done():
			return
		case value := <-c.pending:
			if c.ctx.Err() != nil {
				if value.done != nil {
					value.done <- c.ctx.Err()
				}
				return
			}
			if value.task != nil && value.task.ctx.Err() != nil {
				value.done <- value.task.ctx.Err()
				continue
			}
			if value.task != nil {
				// A client may submit its next request before Write returns. The
				// completed operation must no longer occupy admission or its ID
				// when any response bytes become visible. Delivery and rollback
				// still belong to execute; queued responses retain their slots.
				c.releaseRequest(value.task)
			}
			err := writeFrame(c.writer, value.data)
			if value.done != nil {
				value.done <- err
			}
			if err != nil {
				if c.ctx.Err() == nil {
					c.fail(errors.New("MCP output transport failed"))
				}
				return
			}
		}
	}
}

func (c *connection) releaseRequest(task *activeRequest) {
	task.released.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.active[task.key] == task {
			delete(c.active, task.key)
		}
		<-task.slot
	})
}

func writeFrame(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *connection) enqueue(response rpcResponse, task *activeRequest, done chan error) bool {
	data, err := json.Marshal(response)
	if err != nil || len(data) > maxOutputFrame {
		c.fail(errors.New("MCP response exceeds bounded transport"))
		return false
	}
	data = append(data, '\n')
	select {
	case c.pending <- output{data, done, task}:
		return true
	default:
		c.fail(errors.New("MCP output backpressure limit exceeded"))
		return false
	}
}
func (c *connection) reject(id json.RawMessage, code int, message string, data any) bool {
	return c.enqueue(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{code, message, data}}, nil, nil)
}
func requestKey(id json.RawMessage) (string, bool) {
	id = bytes.TrimSpace(id)
	if len(id) == 0 || bytes.Equal(id, []byte("null")) {
		return "", false
	}
	if id[0] == '"' {
		var value string
		if json.Unmarshal(id, &value) != nil || len(value) > 1024 {
			return "", false
		}
		return "s:" + value, true
	}
	if len(id) > 64 {
		return "", false
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(id))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return "", false
	}
	var ok bool
	n, ok = value.(json.Number)
	if !ok {
		return "", false
	}
	number, err := n.Float64()
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || math.Abs(number) > 9007199254740991 {
		return "", false
	}
	if number == 0 {
		number = 0
	}
	return "n:" + strconv.FormatFloat(number, 'f', 0, 64), true
}
func object(data json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(data) == 0 {
		return map[string]json.RawMessage{}, true
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(data, &value) != nil || value == nil {
		return nil, false
	}
	return value, true
}
func (c *connection) receive(line []byte) bool {
	if !utf8.Valid(line) || !json.Valid(line) {
		return c.reject(nil, -32700, "Parse error", nil)
	}
	var req request
	if json.Unmarshal(line, &req) != nil || req.JSONRPC != "2.0" || req.Method == "" || len(req.Method) > 128 {
		return c.reject(nil, -32600, "Invalid request", nil)
	}
	params, ok := object(req.Params)
	if !ok {
		if len(req.ID) == 0 {
			return true
		}
		if _, valid := requestKey(req.ID); !valid {
			return c.reject(nil, -32600, "Invalid request ID", nil)
		}
		return c.reject(req.ID, -32602, "Params must be an object", nil)
	}
	if len(req.ID) == 0 {
		switch req.Method {
		case "notifications/initialized":
			if c.legacy {
				c.legacyReady = true
			}
		case "notifications/cancelled":
			var v struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			if json.Unmarshal(req.Params, &v) == nil {
				if key, valid := requestKey(v.RequestID); valid {
					c.mu.Lock()
					if active := c.active[key]; active != nil && !active.complete {
						active.cancel()
					}
					c.mu.Unlock()
				}
			}
		}
		return true
	}
	key, valid := requestKey(req.ID)
	if !valid {
		return c.reject(nil, -32600, "Request ID must be a bounded string or safe integer", nil)
	}
	c.mu.Lock()
	_, duplicate := c.active[key]
	c.mu.Unlock()
	if duplicate {
		return c.reject(req.ID, -32600, "Request ID is already active", nil)
	}
	modern := false
	if req.Method == "initialize" {
		if c.legacy {
			return c.reject(req.ID, -32600, "Legacy initialization already started", nil)
		}
		var version string
		var info map[string]json.RawMessage
		_, caps := object(params["capabilities"])
		if json.Unmarshal(params["protocolVersion"], &version) != nil || version == "" || len(params["capabilities"]) == 0 || !caps || json.Unmarshal(params["clientInfo"], &info) != nil || !implementationValid(info) {
			return c.reject(req.ID, -32602, "Invalid initialize parameters", nil)
		}
		c.legacy = true
		result := map[string]any{"protocolVersion": LegacyVersion, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": serverInfo, "instructions": "Use explicit API session/command IDs. Tools share the configured tenant policy; no host execution or unrestricted network access."}
		return c.enqueue(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil, nil)
	}
	if metaRaw, present := params["_meta"]; present {
		meta, valid := object(metaRaw)
		if !valid {
			return c.reject(req.ID, -32602, "Invalid request metadata", nil)
		}
		var version string
		if raw, exists := meta[versionKey]; exists && (json.Unmarshal(raw, &version) != nil || version == "") {
			return c.reject(req.ID, -32602, "Invalid protocol version metadata", nil)
		}
		if json.Unmarshal(meta[versionKey], &version) == nil && version != "" {
			if version == ModernVersion {
				modern = true
				caps, valid := object(meta[capabilitiesKey])
				if !valid || caps == nil || len(meta[capabilitiesKey]) == 0 {
					return c.reject(req.ID, -32602, "Missing client capabilities", nil)
				}
				if raw, present := meta["io.modelcontextprotocol/clientInfo"]; present {
					info, ok := object(raw)
					if !ok || !implementationValid(info) {
						return c.reject(req.ID, -32602, "Invalid client identity", nil)
					}
				}
			} else if version != LegacyVersion {
				return c.reject(req.ID, -32022, "Unsupported protocol version", map[string]any{"supported": supportedVersions, "requested": version})
			}
		} else if !c.legacyReady {
			return c.reject(req.ID, -32602, "Missing protocol version metadata", nil)
		}
	}
	if !modern && !c.legacyReady {
		if !c.legacy {
			return c.reject(req.ID, -32602, "Modern requests require protocol version and client capabilities metadata", nil)
		}
		return c.reject(req.ID, -33001, "Legacy client is not initialized", nil)
	}
	delete(params, "_meta")
	switch req.Method {
	case "server/discover":
		if !modern {
			return c.reject(req.ID, -32601, "Method not found", nil)
		}
		if len(params) != 0 {
			return c.reject(req.ID, -32602, "Discovery takes no arguments", nil)
		}
		result := map[string]any{"supportedVersions": supportedVersions, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "ttlMs": 3600000, "cacheScope": "public"}
		decorate(result, modern)
		return c.enqueue(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil, nil)
	case "ping":
		if modern {
			return c.reject(req.ID, -32601, "Method not found", nil)
		}
		return c.enqueue(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}, nil, nil)
	case "tools/list", "tools/call":
	default:
		return c.reject(req.ID, -32601, "Method not found", nil)
	}
	slot := c.slots
	var toolName string
	if req.Method == "tools/call" && json.Unmarshal(params["name"], &toolName) == nil && portCleanupTool(toolName) {
		slot = c.portControls
	}
	select {
	case slot <- struct{}{}:
	default:
		return c.reject(req.ID, -33000, "MCP concurrency limit reached", nil)
	}
	taskCtx, cancel := context.WithCancel(c.ctx)
	task := &activeRequest{key: key, ctx: taskCtx, cancel: cancel, slot: slot}
	c.mu.Lock()
	c.active[key] = task
	c.mu.Unlock()
	c.wg.Add(1)
	go c.execute(req, key, params, modern, task)
	return true
}
func implementationValid(info map[string]json.RawMessage) bool {
	var name, version string
	return json.Unmarshal(info["name"], &name) == nil && name != "" && json.Unmarshal(info["version"], &version) == nil && version != ""
}
func decorate(result map[string]any, modern bool) {
	if modern {
		result["resultType"] = "complete"
		result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": serverInfo}
	}
}
func (c *connection) execute(req request, key string, params map[string]json.RawMessage, modern bool, task *activeRequest) {
	defer c.wg.Done()
	defer func() { c.releaseRequest(task); task.cancel() }()
	response := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	var rollback func()
	var cap sandbox.CapabilityReport
	var catalog *sandbox.TemplateCatalogReport
	var err error
	var name string
	ownerPortCall := req.Method == "tools/call" && json.Unmarshal(params["name"], &name) == nil && (portOperations[name] || previewOperations[name] || inferenceOperations[name])
	if !ownerPortCall {
		cap, catalog, err = c.server.api.discovery(task.ctx)
	}
	if err != nil {
		if req.Method == "tools/call" {
			result := callResult(failure(err))
			decorate(result, modern)
			response.Result = result
		} else {
			response.Error = &rpcError{-32603, "Sandbox API capabilities unavailable", nil}
		}
	} else if req.Method == "tools/list" {
		if raw, exists := params["cursor"]; exists {
			var cursor string
			if json.Unmarshal(raw, &cursor) != nil || cursor != "" {
				response.Error = &rpcError{-32602, "This tool list has no continuation cursor", nil}
			}
			delete(params, "cursor")
		}
		if len(params) != 0 {
			response.Error = &rpcError{-32602, "Invalid tools/list params", nil}
		}
		if response.Error == nil {
			result := map[string]any{"tools": toolsFor(cap, catalog)}
			if modern {
				result["ttlMs"] = 0
				result["cacheScope"] = "private"
			}
			decorate(result, modern)
			response.Result = result
		}
	} else {
		var name string
		nameRaw := params["name"]
		args := params["arguments"]
		delete(params, "name")
		delete(params, "arguments")
		_, argsOK := object(args)
		if len(params) != 0 || json.Unmarshal(nameRaw, &name) != nil || name == "" || !argsOK {
			response.Error = &rpcError{-32602, "Invalid tools/call params", nil}
		} else if !ownerPortCall && !supported(toolsFor(cap, catalog), name) {
			response.Error = &rpcError{-32602, "Unknown or unavailable tool", nil}
		} else {
			value := c.server.callTool(task.ctx, name, args, cap, catalog)
			rollback = value.Rollback
			result := callResult(value)
			decorate(result, modern)
			response.Result = result
		}
	}
	c.mu.Lock()
	cancelled := task.ctx.Err() != nil
	if !cancelled {
		task.complete = true
	}
	c.mu.Unlock()
	if cancelled {
		if rollback != nil {
			rollback()
		}
		return
	}
	done := make(chan error, 1)
	if !c.enqueue(response, task, done) {
		if rollback != nil {
			rollback()
		}
		return
	}
	select {
	case err := <-done:
		if err != nil && rollback != nil {
			rollback()
		}
	case <-c.ctx.Done():
		// The writer publishes its current write outcome before it exits.
		// Preserve explicitly delivered handles even when EOF races the worker.
		<-c.writerDone
		select {
		case err := <-done:
			if err != nil && rollback != nil {
				rollback()
			}
		default:
			if rollback != nil {
				rollback()
			}
		}
	}
}
