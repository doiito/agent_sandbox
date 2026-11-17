package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestToolsUseExistingAPISelectorsBytesAndDefaults(t *testing.T) {
	var requests []string
	var bodies []map[string]any
	s := mockServer(4, func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		body := map[string]any{}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		bodies = append(bodies, body)
		if r.URL.Path == "/v2/jobs" || strings.HasSuffix(r.URL.Path, "/commands") {
			return reply(map[string]any{"state": "succeeded", "protocol_ok": true}), nil
		}
		if r.Method == "GET" && r.URL.Path == "/v2/sessions/"+strings.Repeat("1", 24) {
			return reply(map[string]any{"id": strings.Repeat("1", 24), "state": "running", "memory_mib": 128, "vcpus": 1}), nil
		}
		return reply(map[string]any{"id": strings.Repeat("2", 24)}), nil
	})
	call := func(name string, args any) outcome {
		t.Helper()
		value := s.callTool(context.Background(), name, rawObject(args), testCapabilities())
		if value.IsError {
			t.Fatalf("%s: %s", name, value.Data)
		}
		return value
	}
	stdin := base64.StdEncoding.EncodeToString([]byte{0, 255, 10})
	call("sandbox.exec", map[string]any{"entrypoint": "/bin/sh", "args": []string{"-c", "cat"}, "stdin": stdin, "environment": map[string]string{"TEST": "value"}, "cwd": "/workspace"})
	if requests[0] != "POST /v2/jobs" || bodies[0]["backend"] != "firecracker-linux" || bodies[0]["artifact_manifest_sha256"] != strings.Repeat("a", 64) || bodies[0]["stdin"] != stdin || bodies[0]["memory_mib"] != nil || bodies[0]["timeout_ms"] != nil {
		t.Fatal("API defaults/selectors/bytes changed", requests, bodies)
	}
	session := strings.Repeat("1", 24)
	call("sandbox.exec", map[string]any{"entrypoint": "/bin/sh", "session_id": session})
	if requests[1] != "POST /v2/sessions/"+session+"/commands" || bodies[1]["session_id"] != nil || bodies[1]["backend"] != nil {
		t.Fatal("synchronous session mapping", requests, bodies)
	}
	call("sandbox.fs.write", map[string]any{"session_id": session, "path": "/workspace/a", "data_base64": stdin})
	if requests[2] != "POST /v2/sessions/"+session+"/files" || bodies[2]["action"] != "write" || bodies[2]["data_base64"] != stdin {
		t.Fatal("file mapping", requests, bodies)
	}
	call("sandbox.session.list", map[string]any{"limit": 2, "cursor": "a+b/c?", "order": "desc"})
	if requests[3] != "GET /v2/sessions?cursor=a%2Bb%2Fc%3F&limit=2&order=desc" {
		t.Fatal("query escaping", requests)
	}
	created := call("sandbox.commands.start", map[string]any{"session_id": session, "entrypoint": "/bin/sh", "interactive_stdin": true})
	if requests[4] != "GET /v2/sessions/"+session || requests[5] != "POST /v2/sessions/"+session+"/commands/start" || bodies[5]["interactive_stdin"] != true || created.Rollback == nil {
		t.Fatal("command creation mapping", requests, bodies)
	}
	created.Rollback()
	if requests[6] != "DELETE /v2/sessions/"+session+"/commands/"+strings.Repeat("2", 24) {
		t.Fatal("command rollback mapping", requests)
	}
	call("sandbox.commands.stdin", map[string]any{"session_id": session, "command_id": strings.Repeat("2", 24), "data_base64": "", "close": true})
	if bodies[7]["data_base64"] != "" || bodies[7]["close"] != true {
		t.Fatal("explicit EOF was lost", bodies)
	}
}

func TestToolValidationDoesNotInvokeAPI(t *testing.T) {
	s := mockServer(4, func(*http.Request) (*http.Response, error) { t.Fatal("invalid arguments invoked API"); return nil, nil })
	for _, test := range []struct {
		name string
		args string
	}{
		{"sandbox.exec", `{"entrypoint":"/bin/host"}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","backend":"firecracker-osv"}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","stdin":"%%%"}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","network":"host"}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","cwd":"relative"}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","session_id":"111111111111111111111111","stdin":""}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","memory_mib":9999}`},
		{"sandbox.exec", `{"entrypoint":"/bin/sh","unrecognized":true}`},
		{"sandbox.fs.read", `{"session_id":"111111111111111111111111","path":"/etc/passwd"}`},
		{"sandbox.fs.read", `{"session_id":"111111111111111111111111","path":"/workspace/../a"}`},
		{"sandbox.fs.rename", `{"session_id":"111111111111111111111111","path":"/workspace/a"}`},
		{"sandbox.session.get", `{"session_id":"../../etc/passwd"}`},
		{"sandbox.session.set_timeout", `{"session_id":"111111111111111111111111","ttl_ms":1}`},
		{"sandbox.session.list", `{"limit":101}`},
		{"sandbox.commands.stdin", `{"session_id":"111111111111111111111111","command_id":"222222222222222222222222"}`},
		{"sandbox.commands.stdin_status", `{"session_id":"111111111111111111111111","command_id":"222222222222222222222222","sequence":0}`},
	} {
		if got := s.callTool(context.Background(), test.name, json.RawMessage(test.args), testCapabilities()); !got.IsError {
			t.Fatalf("invalid %s accepted: %s", test.name, test.args)
		}
	}
}

func TestCapabilitiesGateToolsAndTemplates(t *testing.T) {
	cap := testCapabilities()
	cap.Features.Sessions, cap.Features.Environment, cap.Features.WorkingDirectory, cap.Features.Stdin, cap.Features.InputFiles = false, false, false, false, false
	tools := toolsFor(cap)
	if len(tools) != 3 || supported(tools, "sandbox.fs.read") {
		t.Fatal("unavailable tool published", tools)
	}
	for _, tool := range tools {
		if tool.Name == "sandbox.exec" {
			props := tool.InputSchema["properties"].(map[string]any)
			for _, field := range []string{"environment", "cwd", "stdin", "input_files", "session_id"} {
				if props[field] != nil {
					t.Fatal("unavailable argument published", field)
				}
			}
		}
	}
	cap.ArtifactAuthenticated = false
	if supported(toolsFor(cap), "sandbox.exec") {
		t.Fatal("unauthenticated exec published")
	}
	s := mockServer(1, nil)
	result := s.callTool(context.Background(), "sandbox.templates", json.RawMessage(`{}`), cap)
	if string(result.Data) != `{"templates":[]}` {
		t.Fatal("invented unauthenticated template", string(result.Data))
	}
}

func TestAPIErrorAndGuestErrorAreToolResults(t *testing.T) {
	h := harness(t, mockServer(1, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"code":"forbidden","message":"test-secret internal diagnostic"}`))}, nil
	}))
	h.send(modern(1, "tools/call", map[string]any{"name": "sandbox.session.get", "arguments": map[string]any{"session_id": strings.Repeat("1", 24)}}))
	response := h.receive()
	result, ok := response["result"].(map[string]any)
	if !ok || result["isError"] != true || result["resultType"] != "complete" {
		t.Fatal(response)
	}
	if data, _ := json.Marshal(result); strings.Contains(string(data), "test-secret") {
		t.Fatal("API diagnostic leaked into protocol")
	}
	if err := h.close(); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"succeeded", "timed_out", "guest_error", "cancelled"} {
		s := mockServer(1, func(*http.Request) (*http.Response, error) {
			return reply(map[string]any{"info": map[string]any{"state": state}}), nil
		})
		got := s.callTool(context.Background(), "sandbox.commands.wait", json.RawMessage(`{"session_id":"111111111111111111111111","command_id":"222222222222222222222222"}`), testCapabilities())
		if got.IsError != (state != "succeeded") {
			t.Fatal("terminal command error was hidden", state, string(got.Data))
		}
	}
}
