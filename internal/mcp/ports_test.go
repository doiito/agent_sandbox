package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func portCapabilityForTest() sandbox.CapabilityReport {
	cap := testCapabilities()
	cap.ArtifactManifestProtocol = "osv-sandbox-artifacts/v6"
	cap.Features.PortForward = true
	return cap
}
func portArgs(n int) map[string]any {
	return map[string]any{"session_id": codeSID, "connection_id": fmt.Sprintf("%024x", n), "port": 8080}
}
func portData(value outcome) map[string]json.RawMessage {
	var data map[string]json.RawMessage
	_ = json.Unmarshal(value.Data, &data)
	return data
}

// net.Pipe exercises the actual HTTP upgrade adapter and sandbox frame codec;
// the RoundTripper/guest is scripted. Real mTLS/process coverage lives in the
// sandbox TestPortSDKMTLSAPIAndLauncher integration fixture.
func portMock(t *testing.T, serve func(net.Conn)) (*Server, *portRegistry, context.Context, *atomic.Int32) {
	t.Helper()
	var posts atomic.Int32
	var mu sync.Mutex
	var peers []net.Conn
	var wg sync.WaitGroup
	api := &apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{}}
	api.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("missing authentication")
		}
		parts := strings.Split(r.URL.Path, "/")
		if strings.HasSuffix(r.URL.Path, "/capabilities") {
			return reply(sandbox.SessionCapabilityReport{SessionID: parts[3], CapabilityReport: portCapabilityForTest()}), nil
		}
		if len(parts) != 8 || parts[4] != "ports" || parts[6] != "connections" {
			return nil, errors.New("unexpected new admission discovery")
		}
		port, _ := strconv.ParseUint(parts[5], 10, 16)
		if r.Method != "POST" {
			code := "cancelled"
			return reply(map[string]any{"session_id": parts[3], "connection": sandbox.SessionPortInfo{ID: parts[7], Port: uint16(port), Status: "cancelled", Error: &code}}), nil
		}
		posts.Add(1)
		local, peer := net.Pipe()
		mu.Lock()
		peers = append(peers, local, peer)
		mu.Unlock()
		wg.Add(1)
		go func() { defer wg.Done(); defer peer.Close(); serve(peer) }()
		return &http.Response{StatusCode: 101, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"osv-port/1"}, "X-Osv-Session-Id": {parts[3]}, "X-Osv-Connection-Id": {parts[7]}, "X-Osv-Port": {parts[5]}}, Body: local}, nil
	})
	server := newServer(api, 1)
	registry := newPortRegistry(context.Background())
	ctx := context.WithValue(context.Background(), portRegistryKey{}, registry)
	t.Cleanup(func() {
		registry.close()
		mu.Lock()
		for _, c := range peers {
			_ = c.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture workers not reaped")
		}
	})
	return server, registry, ctx, &posts
}

func TestPortMCPDiscoveryV6CompositionAndUnavailableAdmission(t *testing.T) {
	cap := portCapabilityForTest()
	if len(portToolsFor(cap)) != 7 {
		t.Fatal("native tools missing")
	}
	for _, edit := range []func(*sandbox.CapabilityReport){func(c *sandbox.CapabilityReport) { c.ArtifactAuthenticated = false }, func(c *sandbox.CapabilityReport) { c.Features.PortForward = false }, func(c *sandbox.CapabilityReport) { c.ArtifactManifestProtocol = "osv-sandbox-artifacts/v5" }, func(c *sandbox.CapabilityReport) { c.Backend = "firecracker-osv" }} {
		copy := cap
		edit(&copy)
		if len(portToolsFor(copy)) != 0 {
			t.Fatal("unsupported ports advertised")
		}
	}
	code := codeCapabilityForTest()
	code.ArtifactManifestProtocol = cap.ArtifactManifestProtocol
	code.Features.PortForward = true
	if len(codeToolsFor(code)) != 9 || len(portToolsFor(code)) != 7 {
		t.Fatal("v6 lost composed code")
	}
	code.CodeRuntime = nil
	if len(codeToolsFor(code)) != 0 {
		t.Fatal("v6 skipped runtime validation")
	}
	catalog := &sandbox.TemplateCatalogReport{Protocol: "osv-sandbox-template-catalog/v1", Templates: []sandbox.TemplateReport{{ID: "ports", Available: false, Capabilities: cap}}}
	if !supported(toolsFor(sandbox.CapabilityReport{}, catalog), "sandbox.ports.info") {
		t.Fatal("existing VM tools hidden with expired new admission")
	}
}

func TestPortMCPStrictArgumentsBeforeTransport(t *testing.T) {
	base := portArgs(1)
	for i, edit := range []map[string]any{{"session_id": "BAD"}, {"connection_id": "a"}, {"port": 0}, {"port": 65536}, {"port": true}, {"host": "127.0.0.1"}, {"max_bytes": 0}, {"max_bytes": nil}, {"timeout_ms": 300001}, {"idle_timeout_ms": -1}, {"operation": "cancel"}} {
		value := map[string]any{}
		for k, v := range base {
			value[k] = v
		}
		for k, v := range edit {
			value[k] = v
		}
		if _, err := parsePortTool("sandbox.ports.open", rawObject(value)); err == nil {
			t.Errorf("invalid open accepted %d", i)
		}
	}
	for _, data := range []any{nil, "", "*", "AB==", "YQ==\n", base64.StdEncoding.EncodeToString(make([]byte, 16385))} {
		value := portArgs(1)
		value["data_base64"] = data
		if _, err := parsePortTool("sandbox.ports.write", rawObject(value)); err == nil {
			t.Error("invalid DATA accepted")
		}
	}
	value := portArgs(1)
	value["max_bytes"] = 1
	if _, err := parsePortTool("sandbox.ports.info", rawObject(value)); err == nil {
		t.Fatal("cleanup accepted open fields")
	}
}

func TestPortMCPLocalQuotaControlReleaseAndHistoryBound(t *testing.T) {
	s, registry, ctx, posts := portMock(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	for i := 1; i <= 8; i++ {
		if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(i))); result.IsError {
			t.Fatal(string(result.Data))
		}
	}
	if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(9))); !result.IsError || posts.Load() != 8 {
		t.Fatal("active bound bypassed")
	}
	if result := s.callPortTool(ctx, "sandbox.ports.cancel", rawObject(portArgs(1))); result.IsError {
		t.Fatal(string(result.Data))
	}
	if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(9))); result.IsError || posts.Load() != 9 {
		t.Fatal("terminal control did not reclaim local transport")
	}
	registry.close()
	registry.close()
	registry.mu.Lock()
	active := registry.active
	registry.mu.Unlock()
	if active != 0 {
		t.Fatal("local capacity leaked")
	}
	full := newPortRegistry(context.Background())
	for i := 0; i < 256; i++ {
		full.records[fmt.Sprint(i)] = &portRecord{closed: true}
	}
	fullCtx := context.WithValue(context.Background(), portRegistryKey{}, full)
	if result := s.callPortTool(fullCtx, "sandbox.ports.open", rawObject(portArgs(10))); !result.IsError || posts.Load() != 9 {
		t.Fatal("history bound bypassed")
	}
}

func TestPortMCPExpiryReclaimsUnreadTransports(t *testing.T) {
	s, registry, ctx, _ := portMock(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	args := portArgs(1)
	args["timeout_ms"] = 30
	if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(args)); result.IsError {
		t.Fatal(string(result.Data))
	}
	deadline := time.Now().Add(time.Second)
	for {
		registry.mu.Lock()
		active := registry.active
		registry.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle local port slot leaked")
		}
		time.Sleep(time.Millisecond)
	}
	if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(1))); !result.IsError {
		t.Fatal("expired ID was replayed")
	}
}

func TestPortMCPBlockedDirectionsKeepControlIndependent(t *testing.T) {
	hold := make(chan struct{})
	s, registry, ctx, _ := portMock(t, func(c net.Conn) { <-hold })
	defer close(hold)
	if result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(1))); result.IsError {
		t.Fatal(string(result.Data))
	}
	write := portArgs(1)
	write["data_base64"] = "eA=="
	done := make(chan outcome, 2)
	go func() { done <- s.callPortTool(ctx, "sandbox.ports.write", rawObject(write)) }()
	registry.mu.Lock()
	record := registry.records[portKey(codeSID, fmt.Sprintf("%024x", 1))]
	registry.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for !record.writing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("writer did not enter")
		}
		time.Sleep(time.Millisecond)
	}
	if result := s.callPortTool(ctx, "sandbox.ports.write", rawObject(write)); !result.IsError {
		t.Fatal("second writer queued")
	}
	go func() { done <- s.callPortTool(ctx, "sandbox.ports.read", rawObject(portArgs(1))) }()
	started := time.Now()
	if result := s.callPortTool(ctx, "sandbox.ports.info", rawObject(portArgs(1))); result.IsError {
		t.Fatal(string(result.Data))
	}
	if time.Since(started) > time.Second {
		t.Fatal("control waited for DATA")
	}
	for i := 0; i < 2; i++ {
		select {
		case result := <-done:
			if !result.IsError {
				t.Fatal("closed DATA treated as delivered")
			}
		case <-time.After(time.Second):
			t.Fatal("blocked worker not reaped")
		}
	}
}

func TestPortMCPUncertainOpenNeverReplaysAndCleanupSkipsDiscovery(t *testing.T) {
	s, _, ctx, posts := portMock(t, func(c net.Conn) {})
	original := s.api.http.Transport
	s.api.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts.Add(1)
			return nil, errors.New("lost ACK")
		}
		return original.RoundTrip(r)
	})
	result := s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(1)))
	if !result.IsError || string(portData(result)["outcome_uncertain"]) != "true" || posts.Load() != 1 {
		t.Fatal("lost ACK identity missing")
	}
	if result = s.callPortTool(ctx, "sandbox.ports.open", rawObject(portArgs(1))); !result.IsError || posts.Load() != 1 {
		t.Fatal("open replayed")
	}
	for _, op := range []string{"info", "cancel"} {
		if result = s.callPortTool(context.Background(), "sandbox.ports."+op, rawObject(portArgs(1))); result.IsError {
			t.Fatal("control depended on local transport or new discovery")
		}
	}
}

func TestPortMCPControlRejectsWrongBindingAndTerminalSchema(t *testing.T) {
	s, _, ctx, _ := portMock(t, func(c net.Conn) {})
	for _, edit := range []map[string]any{{"id": "f"}, {"port": 8081}, {"sent_bytes": -1}, {"received_bytes": 64<<20 + 1}, {"error": "unknown"}, {"extra": 1}, {"error": nil}} {
		state := map[string]any{"id": fmt.Sprintf("%024x", 1), "port": 8080, "status": "cancelled", "sent_bytes": 0, "received_bytes": 0, "error": "cancelled"}
		for k, v := range edit {
			state[k] = v
		}
		s.api.http.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
			return reply(map[string]any{"session_id": codeSID, "connection": state}), nil
		})
		if result := s.callPortTool(ctx, "sandbox.ports.info", rawObject(portArgs(1))); !result.IsError {
			t.Fatal("bad control proof accepted", edit)
		}
	}
}
