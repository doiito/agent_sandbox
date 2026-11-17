package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func catalogCapabilitiesForTest() (sandbox.CapabilityReport, sandbox.CapabilityReport, *sandbox.TemplateCatalogReport) {
	first, second := testCapabilities(), testCapabilities()
	first.Backend = "firecracker-osv"
	first.AllowedEntrypoints = []string{"/python.so"}
	first.Features = sandbox.CapabilityFeatures{OneShotJob: true, Argv: true, Environment: true, Stdin: true}
	first.Methods = []string{"GET /v2/templates"}
	second.ArtifactManifestSHA256 = strings.Repeat("b", 64)
	second.Methods = []string{"GET /v2/templates"}
	second.Features.NetworkEgress = true
	catalog := &sandbox.TemplateCatalogReport{Protocol: "osv-sandbox-template-catalog/v1", DefaultTemplateID: "python", Templates: []sandbox.TemplateReport{{ID: "python", Available: true, Capabilities: first}, {ID: "linux", Available: true, Capabilities: second}}}
	return first, second, catalog
}

func TestCatalogToolsExposeUnionButValidateSelectedTemplate(t *testing.T) {
	first, second, catalog := catalogCapabilitiesForTest()
	tools := toolsFor(first, catalog)
	if !supported(tools, "sandbox.session.create") || !supported(tools, "sandbox.exec") {
		t.Fatal("nondefault session tools absent")
	}
	for _, definition := range tools {
		if definition.Name == "sandbox.exec" {
			props := definition.InputSchema["properties"].(map[string]any)
			entries := props["entrypoint"].(map[string]any)["enum"].([]string)
			if !contains(entries, "/python.so") || !contains(entries, "/bin/sh") {
				t.Fatal("catalog entrypoints not visible", entries)
			}
		}
	}
	var posts atomic.Int32
	s := newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Fatal("selector query bypassed authentication")
		}
		if r.URL.Path == "/v1/capabilities" {
			if r.URL.Query().Get("backend") == second.Backend && r.URL.Query().Get("artifact_manifest_sha256") == second.ArtifactManifestSHA256 {
				return reply(second), nil
			}
			if r.URL.Query().Get("backend") == first.Backend {
				return reply(first), nil
			}
			t.Fatal("wrong selected capability query", r.URL.RequestURI())
		}
		posts.Add(1)
		var body sandbox.RunRequest
		if r.URL.Path != "/v2/jobs" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Backend != second.Backend || body.ArtifactManifestSHA256 != second.ArtifactManifestSHA256 || body.Network != "proxy" {
			t.Fatal("nondefault exec changed template", r.URL.Path, body)
		}
		return reply(map[string]any{"state": "succeeded", "protocol_ok": true}), nil
	})}}, 2)
	args := rawObject(map[string]any{"entrypoint": "/bin/sh", "backend": second.Backend, "artifact_manifest_sha256": second.ArtifactManifestSHA256, "network": "proxy"})
	if got := s.callTool(context.Background(), "sandbox.exec", args, first, catalog); got.IsError || posts.Load() != 1 {
		t.Fatal("authorized nondefault proxy rejected", string(got.Data))
	}
	bad := rawObject(map[string]any{"entrypoint": "/python.so", "backend": first.Backend, "artifact_manifest_sha256": first.ArtifactManifestSHA256, "network": "proxy"})
	if got := s.callTool(context.Background(), "sandbox.exec", bad, first, catalog); !got.IsError || posts.Load() != 1 {
		t.Fatal("OSv borrowed Linux proxy capability", string(got.Data))
	}
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func TestCatalogSessionExecutionUsesBoundTemplateAndRejectsMismatch(t *testing.T) {
	first, second, catalog := catalogCapabilitiesForTest()
	sid := strings.Repeat("1", 24)
	posts := 0
	s := newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && r.URL.Path == "/v2/sessions/"+sid {
			return reply(sandbox.SessionInfo{ID: sid, Backend: second.Backend, ArtifactManifestSHA256: second.ArtifactManifestSHA256}), nil
		}
		if r.URL.Path == "/v1/capabilities" {
			if r.URL.Query().Get("artifact_manifest_sha256") != second.ArtifactManifestSHA256 {
				t.Fatal("session capability not bound")
			}
			return reply(second), nil
		}
		posts++
		if r.URL.Path != "/v2/sessions/"+sid+"/commands" {
			t.Fatal(r.URL.Path)
		}
		return reply(map[string]any{"result": map[string]any{"state": "succeeded", "protocol_ok": true}}), nil
	})}}, 2)
	args := rawObject(map[string]any{"session_id": sid, "entrypoint": "/bin/sh"})
	if got := s.callTool(context.Background(), "sandbox.exec", args, first, catalog); got.IsError || posts != 1 {
		t.Fatal("session inherited default OSv template", string(got.Data))
	}
	args = rawObject(map[string]any{"session_id": sid, "entrypoint": "/python.so", "backend": first.Backend, "artifact_manifest_sha256": first.ArtifactManifestSHA256})
	if got := s.callTool(context.Background(), "sandbox.exec", args, first, catalog); !got.IsError || posts != 1 {
		t.Fatal("session ignored contradictory explicit selector", string(got.Data))
	}
}

func TestCatalogDiscoveryWorksWhenDefaultIsDeniedOrUnavailable(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "expired"}[unavailable], func(t *testing.T) {
			_, second, catalog := catalogCapabilitiesForTest()
			catalog.DefaultTemplateID = ""
			catalog.Templates = catalog.Templates[1:]
			var posts atomic.Int32
			s := newServer(&apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v1/capabilities":
					if r.URL.Query().Get("backend") != "" {
						return reply(second), nil
					}
					if unavailable {
						return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"code":"unavailable"}`)), Header: make(http.Header)}, nil
					}
					return reply(sandbox.CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", AllowedEntrypoints: []string{}, Methods: []string{"GET /v2/templates"}}), nil
				case "/v2/templates":
					return reply(catalog), nil
				case "/v2/jobs":
					posts.Add(1)
					return reply(map[string]any{"state": "succeeded", "protocol_ok": true}), nil
				default:
					t.Fatal("unexpected discovery request", r.URL.Path)
					return nil, nil
				}
			})}}, 2)
			h := harness(t, s)
			h.send(modern(1, "tools/list", nil))
			response := h.receive()
			if response["error"] != nil {
				t.Fatal("default blocked authorized catalog", response)
			}
			found := false
			for _, raw := range response["result"].(map[string]any)["tools"].([]any) {
				row := raw.(map[string]any)
				if row["name"] == "sandbox.exec" {
					found = true
					if row["inputSchema"].(map[string]any)["anyOf"] == nil {
						t.Fatal("implicit fallback advertised")
					}
				}
			}
			if !found {
				t.Fatal("authorized nondefault exec not advertised")
			}
			h.send(modern(2, "tools/call", map[string]any{"name": "sandbox.exec", "arguments": map[string]any{"entrypoint": "/bin/sh"}}))
			if h.receive()["result"].(map[string]any)["isError"] != true || posts.Load() != 0 {
				t.Fatal("implicit execution fell back to first catalog entry")
			}
			h.send(modern(3, "tools/call", map[string]any{"name": "sandbox.exec", "arguments": map[string]any{"entrypoint": "/bin/sh", "backend": second.Backend, "artifact_manifest_sha256": second.ArtifactManifestSHA256}}))
			if h.receive()["result"].(map[string]any)["isError"] == true || posts.Load() != 1 {
				t.Fatal("explicit authorized template did not execute")
			}
		})
	}
}
