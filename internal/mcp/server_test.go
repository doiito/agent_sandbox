package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(value any) *http.Response {
	data, _ := json.Marshal(value)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}
}
func testCapabilities() sandbox.CapabilityReport {
	return sandbox.CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: "firecracker-linux", ArtifactAuthenticated: true, ArtifactManifestSHA256: strings.Repeat("a", 64), AllowedEntrypoints: []string{"/bin/sh", "/bin/bash"}, Features: sandbox.CapabilityFeatures{OneShotJob: true, Argv: true, Sessions: true, SessionFiles: true, SessionListing: true, SessionTimeoutUpdate: true, BackgroundCommands: true, InteractiveStdin: true, Environment: true, WorkingDirectory: true, SessionEnvironment: true, SessionWorkingDirectory: true, InputFiles: true, Stdin: true}, Limits: sandbox.CapabilityLimits{MinMemoryMiB: 64, MaxMemoryMiB: 512, MaxVCPUs: 2, MaxTimeoutMS: 300000, MaxConcurrent: 4, MaxOutputBytes: 65536, SessionMaxTTLMS: 300000, SessionMaxLifetimeMS: 600000}}
}
func mockServer(maximum int, handler roundTrip) *Server {
	return newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/capabilities" {
			return reply(testCapabilities()), nil
		}
		return handler(r)
	})}}, maximum)
}

type rpcHarness struct {
	t       *testing.T
	input   *io.PipeWriter
	output  *io.PipeReader
	lines   chan json.RawMessage
	stopped chan error
}

func harness(t *testing.T, server *Server) *rpcHarness {
	t.Helper()
	in, send := io.Pipe()
	out, writer := io.Pipe()
	h := &rpcHarness{t: t, input: send, output: out, lines: make(chan json.RawMessage, 64), stopped: make(chan error, 1)}
	go func() { h.stopped <- server.Serve(context.Background(), in, writer) }()
	go func() {
		defer close(h.lines)
		reader := bufio.NewReader(out)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			h.lines <- line
		}
	}()
	t.Cleanup(func() { _ = send.Close(); _ = out.Close() })
	return h
}
func modern(id any, method string, params map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{versionKey: ModernVersion, capabilitiesKey: map[string]any{}}
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}
func (h *rpcHarness) send(value any) {
	h.t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.input.Write(append(data, '\n')); err != nil {
		h.t.Fatal(err)
	}
}
func (h *rpcHarness) receive() map[string]any {
	h.t.Helper()
	select {
	case line, ok := <-h.lines:
		if !ok {
			h.t.Fatal("MCP output closed before response")
		}
		var response map[string]any
		if json.Unmarshal(line, &response) != nil {
			h.t.Fatalf("invalid MCP JSON: %q", line)
		}
		return response
	case <-time.After(3 * time.Second):
		h.t.Fatal("MCP response timeout")
		return nil
	}
}
func (h *rpcHarness) close() error {
	h.t.Helper()
	_ = h.input.Close()
	select {
	case err := <-h.stopped:
		return err
	case <-time.After(3 * time.Second):
		h.t.Fatal("MCP did not stop on EOF")
		return nil
	}
}
func errorCode(t *testing.T, response map[string]any) int {
	t.Helper()
	e, ok := response["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected JSON-RPC error: %v", response)
	}
	return int(e["code"].(float64))
}

func TestModernAndLegacyProtocol(t *testing.T) {
	h := harness(t, mockServer(4, func(*http.Request) (*http.Response, error) { return reply(map[string]any{}), nil }))
	h.send(modern(1, "server/discover", nil))
	r := h.receive()["result"].(map[string]any)
	if r["resultType"] != "complete" || r["cacheScope"] != "public" || r["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"] == nil {
		t.Fatal(r)
	}
	h.send(modern(2, "tools/list", nil))
	r = h.receive()["result"].(map[string]any)
	if r["ttlMs"] != float64(0) || r["cacheScope"] != "private" {
		t.Fatal(r)
	}
	previous := ""
	for _, item := range r["tools"].([]any) {
		name := item.(map[string]any)["name"].(string)
		if name <= previous || strings.Contains(name, "net.") {
			t.Fatal("unordered or unimplemented tool", name)
		}
		previous = name
	}
	h.send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": map[string]any{"protocolVersion": LegacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}}})
	if h.receive()["result"].(map[string]any)["protocolVersion"] != LegacyVersion {
		t.Fatal("legacy negotiation")
	}
	h.send(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
	if errorCode(t, h.receive()) != -33001 {
		t.Fatal("legacy handshake bypass")
	}
	h.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	h.send(map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
	r = h.receive()["result"].(map[string]any)
	if r["resultType"] != nil || r["ttlMs"] != nil || len(r["tools"].([]any)) < 20 {
		t.Fatal(r)
	}
	// Serving legacy must not change a modern request's semantics.
	h.send(modern(6, "server/discover", nil))
	if h.receive()["result"].(map[string]any)["resultType"] != "complete" {
		t.Fatal("mixed eras inherited handshake state")
	}
	h.send(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "ping"})
	if len(h.receive()["result"].(map[string]any)) != 0 {
		t.Fatal("legacy ping")
	}
	if err := h.close(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolErrorsAndIDs(t *testing.T) {
	h := harness(t, mockServer(4, func(*http.Request) (*http.Response, error) { return reply(map[string]any{}), nil }))
	for _, test := range []struct {
		message any
		code    int
	}{
		{map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, -32602},
		{map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{"_meta": map[string]any{versionKey: ModernVersion}}}, -32602},
		{map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": map[string]any{"_meta": map[string]any{versionKey: "2099-01-01", capabilitiesKey: map[string]any{}}}}, -32022},
		{modern(nil, "server/discover", nil), -32600},
		{modern(1.5, "server/discover", nil), -32600},
		{modern(9007199254740992, "server/discover", nil), -32600},
		{modern(4, "ping", nil), -32601},
		{modern(5, "tools/call", map[string]any{"name": "sandbox.net.fetch", "arguments": map[string]any{}}), -32602},
		{modern(6, "tools/list", map[string]any{"cursor": "unavailable"}), -32602},
		{modern(7, "tools/call", map[string]any{"name": "sandbox.capabilities", "arguments": []any{}}), -32602},
	} {
		h.send(test.message)
		if got := errorCode(t, h.receive()); got != test.code {
			t.Fatalf("%v: got %d want %d", test.message, got, test.code)
		}
	}
	_, _ = h.input.Write([]byte("{broken\n"))
	if errorCode(t, h.receive()) != -32700 {
		t.Fatal("parse error")
	}
	// Notifications, including unknown or malformed ones, produce no response.
	h.send(map[string]any{"jsonrpc": "2.0", "method": "unknown", "params": []any{}})
	h.send(modern("end", "server/discover", nil))
	if h.receive()["id"] != "end" {
		t.Fatal("notification response leaked")
	}
	if request, ok := requestKey(json.RawMessage(`-0`)); !ok || request != "n:0" {
		t.Fatal("numeric identity normalization", request)
	}
	if err := h.close(); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationEOFConcurrencyAndDuplicateID(t *testing.T) {
	entered, cancelled := make(chan struct{}, 2), make(chan struct{}, 2)
	s := mockServer(1, func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
		return nil, r.Context().Err()
	})
	h := harness(t, s)
	call := func(id any) any {
		return modern(id, "tools/call", map[string]any{"name": "sandbox.exec", "arguments": map[string]any{"entrypoint": "/bin/sh"}})
	}
	h.send(call(1))
	await(t, entered)
	h.send(call(1))
	if errorCode(t, h.receive()) != -32600 {
		t.Fatal("duplicate active ID")
	}
	h.send(call(2))
	if errorCode(t, h.receive()) != -33000 {
		t.Fatal("in-flight limit not enforced")
	}
	h.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	await(t, cancelled)
	// A cancelled request emits no response; discovery proves reader responsiveness.
	h.send(modern(3, "server/discover", nil))
	if h.receive()["id"] != float64(3) {
		t.Fatal("cancelled response leaked")
	}
	// Wait for actual slot release rather than relying on goroutine scheduling.
	deadline := time.Now().Add(time.Second)
	for {
		h.send(call(4))
		select {
		case <-entered:
			if err := h.close(); err != nil {
				t.Fatal(err)
			}
			await(t, cancelled)
			return
		case response := <-h.lines:
			var value map[string]any
			_ = json.Unmarshal(response, &value)
			if errorCode(t, value) != -33000 || time.Now().After(deadline) {
				t.Fatal("slot was not released")
			}
		case <-time.After(time.Second):
			t.Fatal("second operation not admitted")
		}
	}
}
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("event timeout")
	}
}

type blockedWriter struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *blockedWriter) Write([]byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.closed
	return 0, io.ErrClosedPipe
}
func (w *blockedWriter) Close() error {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
	return nil
}

func TestUndeliveredCreateRollbackAndDeliveredHandleSurvivesEOF(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(fmt.Sprint(delivered), func(t *testing.T) {
			deleted := make(chan struct{}, 1)
			s := mockServer(1, func(r *http.Request) (*http.Response, error) {
				if r.Method == "DELETE" {
					deleted <- struct{}{}
					return reply(map[string]any{"closed": true}), nil
				}
				return reply(map[string]any{"id": strings.Repeat("1", 24), "state": "running"}), nil
			})
			message := modern(1, "tools/call", map[string]any{"name": "sandbox.session.create", "arguments": map[string]any{}})
			if delivered {
				h := harness(t, s)
				h.send(message)
				if h.receive()["result"].(map[string]any)["isError"] != false {
					t.Fatal("create failed")
				}
				if err := h.close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-deleted:
					t.Fatal("delivered persistent handle was destroyed on EOF")
				default:
				}
			} else {
				input, send := io.Pipe()
				writer := &blockedWriter{started: make(chan struct{}), closed: make(chan struct{})}
				stopped := make(chan error, 1)
				go func() { stopped <- s.Serve(context.Background(), input, writer) }()
				data, _ := json.Marshal(message)
				_, _ = send.Write(append(data, '\n'))
				await(t, writer.started)
				_ = send.Close()
				await(t, deleted)
				select {
				case err := <-stopped:
					if err != nil {
						t.Fatal("EOF must be a successful shutdown even with blocked output", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("blocked output did not stop")
				}
			}
		})
	}
}

func TestFramingAndOutputBackpressure(t *testing.T) {
	for _, data := range []string{strings.Repeat("x", maxFrame) + "\n", "{\"jsonrpc\":\"2.0\"}"} {
		if _, err := readFrame(bufio.NewReader(strings.NewReader(data))); err == nil {
			t.Fatal("unbounded or truncated frame accepted")
		}
	}
	input, send := io.Pipe()
	writer := &blockedWriter{started: make(chan struct{}), closed: make(chan struct{})}
	stopped := make(chan error, 1)
	s := mockServer(1, nil)
	go func() { stopped <- s.Serve(context.Background(), input, writer) }()
	for i := 0; i < 25; i++ {
		data, _ := json.Marshal(modern(i, "server/discover", nil))
		if _, err := send.Write(append(data, '\n')); err != nil {
			break
		}
	}
	_ = send.Close()
	select {
	case err := <-stopped:
		if err == nil || !strings.Contains(err.Error(), "backpressure") {
			t.Fatal("backpressure must close transport", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("output queue blocked cancellation")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(data []byte) (int, error) {
	return w.Buffer.Write(data[:min(3, len(data))])
}
func TestShortWrites(t *testing.T) {
	w := &shortWriter{}
	if writeFrame(w, []byte("abcdefg\n")) != nil || w.String() != "abcdefg\n" {
		t.Fatal("short writes corrupted frame")
	}
}
