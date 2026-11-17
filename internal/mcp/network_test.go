package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func TestNetworkToolUsesOnlyAuthenticatedAPI(t *testing.T) {
	cap := testCapabilities()
	cap.Features.NetworkFetch = true
	cap.NetworkFetchPolicy = &sandbox.EgressPolicy{AllowedOrigins: []string{"https://allowed.test:443"}, MaxRequestBytes: 262144, MaxResponseBytes: 524288, TimeoutMS: 10000}
	tools := toolsFor(cap)
	if !supported(tools, "sandbox.net.fetch") {
		t.Fatal("enabled network tool not published")
	}
	for _, tool := range tools {
		if tool.Name == "sandbox.net.fetch" && !tool.Annotations["openWorldHint"] {
			t.Fatal("external network tool misclassified")
		}
	}
	called := 0
	s := mockServer(1, func(r *http.Request) (*http.Response, error) {
		called++
		if r.Method != "POST" || r.URL.Path != "/v2/net/fetch" {
			t.Fatal("network tool bypassed API", r.Method, r.URL.Path)
		}
		var req sandbox.NetworkFetchRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.URL != "https://allowed.test/data" || req.BodyBase64 != "AP8=" || req.Method != "POST" {
			t.Fatal("network input changed", req)
		}
		return reply(sandbox.NetworkFetchResult{Protocol: "osv-sandbox-network-fetch/v1", Status: 404, BodyBase64: "bm90IGZvdW5k", RequestID: "111111111111111111111111"}), nil
	})
	result := s.callTool(context.Background(), "sandbox.net.fetch", json.RawMessage(`{"url":"https://allowed.test/data","method":"POST","body_base64":"AP8="}`), cap)
	if !result.IsError || called != 1 {
		t.Fatal("upstream HTTP failure was hidden", string(result.Data))
	}
	cap.Features.NetworkFetch = false
	if supported(toolsFor(cap), "sandbox.net.fetch") {
		t.Fatal("disabled network tool published")
	}
	cap.Features.NetworkFetch = true
	cap.NetworkFetchPolicy = nil
	if supported(toolsFor(cap), "sandbox.net.fetch") {
		t.Fatal("missing network policy published")
	}
}

func TestGuestProxyToolsForwardAuthorizedRequestsWithoutHostConfiguration(t *testing.T) {
	cap := testCapabilities()
	cap.Features.NetworkEgress = true
	for _, tc := range []struct{ name, args, path string }{
		{"sandbox.exec", `{"entrypoint":"/bin/sh","network":"proxy"}`, "/v2/jobs"},
		{"sandbox.session.create", `{"network":"proxy"}`, "/v2/sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := 0
			s := mockServer(1, func(r *http.Request) (*http.Response, error) {
				called++
				if r.Method != "POST" || r.URL.Path != tc.path || r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Fatal("proxy request bypassed authenticated API", r.Method, r.URL.Path)
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["network"] != "proxy" || body["backend"] != cap.Backend || body["artifact_manifest_sha256"] != cap.ArtifactManifestSHA256 {
					t.Fatal("proxy request or template changed", body)
				}
				if tc.path == "/v2/jobs" {
					return reply(map[string]any{"state": "succeeded", "protocol_ok": true}), nil
				}
				return reply(sandbox.SessionInfo{ID: "0123456789abcdef01234567", Network: "proxy"}), nil
			})
			result := s.callTool(context.Background(), tc.name, json.RawMessage(tc.args), cap)
			if result.IsError || called != 1 {
				t.Fatal("authorized proxy blocked by gateway configuration", string(result.Data), called)
			}
			cap.Features.NetworkEgress = false
			denied := s.callTool(context.Background(), tc.name, json.RawMessage(tc.args), cap)
			if !denied.IsError || called != 1 {
				t.Fatal("disabled proxy reached API", string(denied.Data), called)
			}
			cap.Features.NetworkEgress = true
		})
	}
}

func TestSessionExecCannotChangeNetworkMode(t *testing.T) {
	cap := testCapabilities()
	cap.Features.NetworkEgress = true
	s := mockServer(1, func(r *http.Request) (*http.Response, error) {
		t.Fatal("network mutation reached API", r.URL.Path)
		return nil, nil
	})
	result := s.callTool(context.Background(), "sandbox.exec", json.RawMessage(`{"session_id":"0123456789abcdef01234567","entrypoint":"/bin/sh","network":"proxy"}`), cap)
	if !result.IsError {
		t.Fatal("session exec silently ignored network mutation")
	}
}
