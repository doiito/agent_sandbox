package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

const previewTestID = "bbbbbbbbbbbbbbbbbbbbbbbb"

func previewTestCapability() sandbox.CapabilityReport {
	cap := portCapabilityForTest()
	cap.Features.PortPreview = true
	return cap
}
func previewTestArgs() map[string]any {
	return map[string]any{"session_id": codeSID, "preview_id": previewTestID, "port": 8080}
}
func previewTestInfo(creating bool) sandbox.PreviewGrantInfo {
	created := time.Date(2026, 11, 7, 0, 0, 0, 123456789, time.UTC)
	i := sandbox.PreviewGrantInfo{Protocol: "osv-sandbox-preview/v1", ID: previewTestID, SessionID: codeSID, Port: 8080,
		Origin: "https://cccccccccccccccccccccccc.preview.test:9444", CreatedAt: created, ExpiresAt: created.Add(time.Minute), Status: "active"}
	if creating {
		i.BootstrapURL = i.Origin + "/.osv/authorize?token=" + strings.Repeat("d", 64)
	}
	return i
}
func previewTestServer(t *testing.T, handler roundTrip) *Server {
	t.Helper()
	return newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/sessions/"+codeSID+"/capabilities" {
			return reply(sandbox.SessionCapabilityReport{SessionID: codeSID, CapabilityReport: previewTestCapability()}), nil
		}
		return handler(r)
	})}}, 1)
}

func TestPreviewMCPDiscoveryAndUnavailableTemplate(t *testing.T) {
	cap := previewTestCapability()
	if len(previewToolsFor(cap)) != 3 {
		t.Fatal("preview tools missing")
	}
	for _, edit := range []func(*sandbox.CapabilityReport){func(c *sandbox.CapabilityReport) { c.Features.PortPreview = false }, func(c *sandbox.CapabilityReport) { c.Features.PortForward = false }, func(c *sandbox.CapabilityReport) { c.ArtifactManifestProtocol = "osv-sandbox-artifacts/v5" }, func(c *sandbox.CapabilityReport) { c.Backend = "firecracker-osv" }} {
		copy := cap
		edit(&copy)
		if len(previewToolsFor(copy)) != 0 {
			t.Fatal("unsupported preview tools advertised")
		}
	}
	catalog := sandbox.TemplateCatalogReport{Templates: []sandbox.TemplateReport{{ID: "ports", Available: false, Capabilities: cap}}}
	names := map[string]bool{}
	for _, tool := range catalogToolsFor(sandbox.CapabilityReport{}, &catalog) {
		names[tool.Name] = true
	}
	for name := range previewOperations {
		if !names[name] {
			t.Fatal("owned session preview tool lost with unavailable admission", name)
		}
	}
	if !portCleanupTool("sandbox.preview.info") || !portCleanupTool("sandbox.preview.revoke") || portCleanupTool("sandbox.preview.create") {
		t.Fatal("preview controls must have reserved slots")
	}
}

func TestPreviewMCPStrictArguments(t *testing.T) {
	for _, op := range []string{"create", "info", "revoke"} {
		name := "sandbox.preview." + op
		for _, edit := range []func(map[string]any){func(m map[string]any) { m["port"] = 0 }, func(m map[string]any) { m["port"] = 65536 }, func(m map[string]any) { m["port"] = true }, func(m map[string]any) { m["preview_id"] = "../bad" }, func(m map[string]any) { m["extra"] = 1 }, func(m map[string]any) { m["ttl_ms"] = nil }} {
			args := previewTestArgs()
			edit(args)
			if _, err := parsePreviewTool(name, rawObject(args)); err == nil {
				t.Fatal("invalid preview args accepted", op)
			}
		}
		for _, ttl := range []any{true, "1000", 999, 300001, 1000.5} {
			args := previewTestArgs()
			args["ttl_ms"] = ttl
			if _, err := parsePreviewTool(name, rawObject(args)); err == nil {
				t.Fatal("invalid TTL accepted")
			}
		}
		args := previewTestArgs()
		args["ttl_ms"] = 1000
		_, err := parsePreviewTool(name, rawObject(args))
		if (err == nil) != (op == "create") {
			t.Fatal("TTL only valid for create")
		}
	}
}

func TestPreviewMCPUncertainCreateRetainsIDWithoutReplay(t *testing.T) {
	var posts, deletes atomic.Int32
	s := previewTestServer(t, func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case "POST":
			posts.Add(1)
			return nil, errors.New("lost create acknowledgement")
		case "DELETE":
			deletes.Add(1)
			i := previewTestInfo(false)
			i.Status = "revoked"
			return reply(i), nil
		case "GET":
			if r.URL.Path != "/v2/sessions/"+codeSID+"/previews/"+previewTestID {
				t.Error("unexpected admission discovery")
			}
			return reply(previewTestInfo(false)), nil
		}
		return nil, errors.New("unexpected request")
	})
	out := s.callPreviewTool(context.Background(), "sandbox.preview.create", rawObject(previewTestArgs()))
	if !out.IsError || posts.Load() != 1 || deletes.Load() != 0 || out.Rollback != nil || string(portData(out)["preview_id"]) != `"`+previewTestID+`"` || string(portData(out)["outcome_uncertain"]) != "true" {
		t.Fatal("uncertainty lost ID or performed cleanup")
	}
	for _, op := range []string{"info", "revoke"} {
		if result := s.callPreviewTool(context.Background(), "sandbox.preview."+op, rawObject(previewTestArgs())); result.IsError || result.Rollback != nil {
			t.Fatal("independent preview control failed")
		}
	}
	if posts.Load() != 1 || deletes.Load() != 1 {
		t.Fatal("create replayed")
	}
}

func TestPreviewMCPRejectsMalformedBindingsAndSecretReissue(t *testing.T) {
	for _, op := range []string{"create", "info", "revoke"} {
		for index, edit := range []func(map[string]any){func(m map[string]any) { m["id"] = strings.Repeat("e", 24) }, func(m map[string]any) { m["session_id"] = strings.Repeat("f", 24) }, func(m map[string]any) { m["port"] = 8081 }, func(m map[string]any) { m["status"] = "unknown" }, func(m map[string]any) { m["origin"] = "https://evil.test" }, func(m map[string]any) { m["expires_at"] = m["created_at"] }, func(m map[string]any) { m["extra"] = 1 }, func(m map[string]any) { m["bootstrap_url"] = "" }} {
			t.Run(fmt.Sprintf("%s-%d", op, index), func(t *testing.T) {
				var payload map[string]any
				_ = json.Unmarshal(rawObject(previewTestInfo(op == "create")), &payload)
				if op == "revoke" {
					payload["status"] = "revoked"
				}
				edit(payload)
				s := previewTestServer(t, func(*http.Request) (*http.Response, error) { return reply(payload), nil })
				if out := s.callPreviewTool(context.Background(), "sandbox.preview."+op, rawObject(previewTestArgs())); !out.IsError {
					t.Fatal("malformed response accepted")
				}
			})
		}
	}
}

func TestPreviewMCPReservedControlAndRPCCancelDoNotRollback(t *testing.T) {
	accepted, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var deletes atomic.Int32
	s := previewTestServer(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			close(accepted) // The API created a session-owned grant before losing its ACK.
			<-r.Context().Done()
			<-release
			return nil, r.Context().Err()
		}
		i := previewTestInfo(false)
		if r.Method == "DELETE" {
			deletes.Add(1)
			i.Status = "revoked"
		}
		return reply(i), nil
	})
	h := harness(t, s)
	h.send(modern(1, "tools/call", map[string]any{"name": "sandbox.preview.create", "arguments": previewTestArgs()}))
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("create not accepted")
	}
	for index, op := range []string{"info", "revoke"} {
		h.send(modern(index+2, "tools/call", map[string]any{"name": "sandbox.preview." + op, "arguments": previewTestArgs()}))
		response := h.receive()
		if response["id"] != float64(index+2) || response["result"].(map[string]any)["isError"] != false {
			t.Fatal("blocked control lane", response)
		}
	}
	h.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	unblock()
	// A cancelled RPC emits no response. Discovery proves the reader is live.
	h.send(modern(4, "server/discover", nil))
	if response := h.receive(); response["id"] != float64(4) {
		t.Fatal("cancelled create emitted a response", response)
	}
	if err := h.close(); err != nil || deletes.Load() != 1 {
		t.Fatal("cancel/EOF rolled back a session-owned grant", err, deletes.Load())
	}
}
