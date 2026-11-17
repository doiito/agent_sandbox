package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDirectoryWatchToolsSelectSessionTemplateAndUseExistingAPI(t *testing.T) {
	first, second, catalog := catalogCapabilitiesForTest()
	second.Features.FileWatch, second.Features.RecursiveFileWatch, second.Features.FileWatchEntry = true, true, true
	catalog.Templates[1].Capabilities = second
	if supported(toolsFor(first), "sandbox.watch.start") || !supported(toolsFor(first, catalog), "sandbox.watch.start") {
		t.Fatal("watch discovery ignores selected signed capability")
	}
	sid, wid := strings.Repeat("1", 24), strings.Repeat("2", 24)
	var calls []string
	s := mockServer(4, nil)
	s.api.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/v2/sessions/"+sid {
			return reply(map[string]any{"id": sid, "backend": second.Backend, "artifact_manifest_sha256": second.ArtifactManifestSHA256}), nil
		}
		if r.URL.Path == "/v1/capabilities" {
			return reply(second), nil
		}
		if r.Method == "POST" {
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["session_id"] != nil || body["path"] != "/workspace" || body["recursive"] != true || body["include_entry"] != true {
				t.Error("watch API body changed", body)
			}
			return reply(map[string]any{"id": wid, "session_id": sid, "path": "/workspace"}), nil
		}
		return reply(map[string]any{"stopped": true}), nil
	})
	created := s.callTool(context.Background(), "sandbox.watch.start", rawObject(map[string]any{"session_id": sid, "path": "/workspace", "recursive": true, "include_entry": true}), first, catalog)
	if created.IsError || created.Rollback == nil || len(calls) != 3 || calls[0] != "GET /v2/sessions/"+sid || calls[2] != "POST /v2/sessions/"+sid+"/watches" {
		t.Fatal(calls, string(created.Data))
	}
	created.Rollback()
	if calls[3] != "DELETE /v2/sessions/"+sid+"/watches/"+wid {
		t.Fatal("watch rollback changed", calls)
	}
	polled := s.callTool(context.Background(), "sandbox.watch.poll", rawObject(map[string]any{"session_id": sid, "watch_id": wid, "after": 64}), second)
	if polled.IsError || calls[4] != "GET /v2/sessions/"+sid+"/watches/"+wid+"?after=64" {
		t.Fatal(calls, string(polled.Data))
	}
	for _, tool := range toolsFor(second) {
		if tool.Name == "sandbox.watch.poll" && tool.Annotations["readOnlyHint"] {
			t.Fatal("acknowledging poll advertised as read only")
		}
	}
}

func TestDirectoryWatchToolsRejectUnavailableAndInvalidOptionsBeforeAPI(t *testing.T) {
	s := mockServer(4, func(*http.Request) (*http.Response, error) { t.Fatal("invalid watcher invoked API"); return nil, nil })
	cap := testCapabilities()
	request := rawObject(map[string]any{"session_id": strings.Repeat("1", 24), "path": "/workspace"})
	if value := s.callTool(context.Background(), "sandbox.watch.start", request, cap); !value.IsError {
		t.Fatal("unsupported template admitted watcher")
	}
	cap.Features.FileWatch = true
	for _, raw := range []string{`{"session_id":"111111111111111111111111","path":"/tmp"}`, `{"session_id":"111111111111111111111111","path":"/workspace","recursive":true}`, `{"session_id":"111111111111111111111111","watch_id":"../../host"}`} {
		if value := s.callTool(context.Background(), "sandbox.watch.start", json.RawMessage(raw), cap); !value.IsError {
			t.Fatal("invalid watch accepted", raw)
		}
	}
}
