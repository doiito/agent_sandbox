package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type codeHTTPFixture struct{ watchHTTPFixture }

func (f *codeHTTPFixture) Capabilities() (CapabilityReport, error) {
	return f.session.manager.Capabilities()
}

func codeLauncherSocket(t *testing.T, s *Session, options LauncherOptions) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "cl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "rpc")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
				frame, err := bufio.NewReader(connection).ReadBytes('\n')
				if err == nil {
					var header struct {
						Protocol string `json:"protocol"`
					}
					if json.Unmarshal(frame, &header) == nil && header.Protocol == launcherWatchProtocol {
						handleLauncherWatchConnection(context.Background(), connection, frame, s.manager, options, syscall.Ucred{})
					} else {
						handleLauncherCodeConnection(context.Background(), connection, frame, s.manager, options, syscall.Ucred{})
					}
				}
			}()
		}
	}()
	return socket
}

func TestCodeHTTPAllRoutesOwnerPolicyAndIndependentControl(t *testing.T) {
	var mu sync.Mutex
	ctxInfo := testCodeContext()
	var calls atomic.Int32
	s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
		mu.Lock()
		defer mu.Unlock()
		calls.Add(1)
		response := CodeResponse{}
		switch r.Request.Operation {
		case "default", "info":
			copy := ctxInfo
			response = CodeResponse{Kind: "context", Context: &copy}
		case "create":
			copy := ctxInfo
			copy.ID, copy.Language, copy.Cwd = r.Request.ContextID, r.Request.Language, r.Request.Cwd
			response = CodeResponse{Kind: "context", Context: &copy}
		case "list":
			response = CodeResponse{Kind: "contexts", Contexts: []CodeContext{ctxInfo}}
		case "restart":
			ctxInfo.Generation++
			ctxInfo.State, ctxInfo.PID = "starting", nil
			copy := ctxInfo
			response = CodeResponse{Kind: "context", Context: &copy}
		case "remove":
			response.Kind = "removed"
		case "execute", "cancel":
			response.Kind = "accepted"
		case "execution":
			response = CodeResponse{Kind: "execution", Execution: &CodeExecutionPage{ID: r.Request.ExecutionID, ContextID: testCodeContext().ID, Generation: 1, Status: "completed", Events: []CodeSequencedEvent{{Sequence: 1, Event: CodeEvent{Type: "started"}}, {Sequence: 2, Event: CodeEvent{Type: "finished", Status: "completed", ContextUsable: codeBool(true)}}}, LastSequence: 2, NextSequence: 2}}
		}
		sendCodeReply(c, r, &response, nil)
	})
	fixture := &codeHTTPFixture{watchHTTPFixture{socket: codeLauncherSocket(t, s, LauncherOptions{}), session: s}}
	fixture.handles = make(chan *LauncherSessionClient, 1)
	auth := sessionAuthForTest()
	tenant, _ := auth.Authenticate("Bearer token-a")
	tenant.policy.AllowedEntrypoints = []string{"/bin/sh", codeEntrypoint("python")}
	handler := NewAPIWithAuthenticator(fixture, auth, slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	handle := <-fixture.handles
	defer handle.Close()
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+s.info.ID, "")
	handle.mu.Lock() // The persistent command RPC is occupied for every code call.
	defer handle.mu.Unlock()
	base := "/v2/sessions/" + s.info.ID
	cid, eid := testCodeContext().ID, strings.Repeat("e", 24)
	type call struct {
		method, path, body string
		status             int
	}
	routes := []call{
		{"POST", "/contexts", `{"context_id":"` + strings.Repeat("d", 24) + `","language":"python"}`, 201},
		{"POST", "/contexts/default", `{}`, 200},
		{"GET", "/contexts", "", 200},
		{"GET", "/contexts/" + cid, "", 200},
		{"POST", "/code-executions", `{"context_id":"` + cid + `","generation":1,"execution_id":"` + eid + `","code":"","timeout_ms":0}`, 202},
		{"GET", "/code-executions/" + eid, "", 200},
		{"DELETE", "/code-executions/" + eid + "?context_id=" + cid + "&generation=1", "", 202},
		{"POST", "/contexts/" + cid + "/restart", `{"generation":1}`, 202},
		{"DELETE", "/contexts/" + cid + "?generation=2", "", 202},
	}
	for _, route := range routes {
		before := calls.Load()
		if response := sessionHTTPCall(handler, "token-b", route.method, base+route.path, route.body); response.Code != 404 || calls.Load() != before {
			t.Fatal("cross-owner route reached guest", route.path, response.Code, response.Body.String())
		}
		response := sessionHTTPCall(handler, "token-a", route.method, base+route.path, route.body)
		if response.Code != route.status || !strings.Contains(response.Body.String(), s.info.ID) {
			t.Fatal(route.method, route.path, response.Code, response.Body.String())
		}
	}
	before := calls.Load()
	denied := sessionHTTPCall(handler, "token-a", "POST", base+"/contexts/default", `{"language":"javascript"}`)
	if denied.Code != 403 || calls.Load() != before {
		t.Fatal("tenant interpreter policy bypassed", denied.Code)
	}
	for _, path := range []string{"?after=-1", "?after=257", "?after=invalid"} {
		if response := sessionHTTPCall(handler, "token-a", "GET", base+"/code-executions/"+eid+path, ""); response.Code != 400 {
			t.Fatal("invalid cursor accepted", response.Code)
		}
	}
	if response := sessionHTTPCall(handler, "token-a", "DELETE", base+"/contexts/"+cid, ""); response.Code != 400 {
		t.Fatal("missing generation accepted", response.Code)
	}
	other := &LauncherSessionClient{socketPath: fixture.socket, tenant: "tenant-b", id: s.info.ID}
	_, err := other.Code(context.Background(), CodeCommand{Operation: "list"})
	codeErrorIs(t, err, "closed")
	if s.closed.Load() {
		t.Fatal("denied owner lookup destroyed legitimate session")
	}
	capability := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v1/capabilities", "")
	var report CapabilityReport
	if json.Unmarshal(capability.Body.Bytes(), &report) != nil || len(report.CodeLanguages) != 1 || report.CodeLanguages[0] != "python" {
		t.Fatal("discovery ignores tenant interpreter policy", capability.Body.String())
	}
}

func TestCodeHTTPExistingTemplateReturnsUnsupported(t *testing.T) {
	fixture := &fakeSessionRunner{handles: make(chan *LauncherSessionClient, 1)}
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	handle := <-fixture.handles
	defer handle.Close()
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+handle.id, "")
	response := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions/"+handle.id+"/contexts/default", `{}`)
	if response.Code != 501 {
		t.Fatal("old template advertised code", response.Code, response.Body.String())
	}
}

func TestCodeHTTPMissingChildIsDistinctFromMissingOwner(t *testing.T) {
	s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
		sendCodeReply(c, r, nil, &CodeRequestError{Code: "not_found", Message: "context not found"})
	})
	fixture := &codeHTTPFixture{watchHTTPFixture{socket: codeLauncherSocket(t, s, LauncherOptions{}), session: s}}
	fixture.handles = make(chan *LauncherSessionClient, 1)
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	handle := <-fixture.handles
	defer handle.Close()
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+s.info.ID, "")
	path := "/v2/sessions/" + s.info.ID + "/contexts/" + testCodeContext().ID
	for _, expected := range []struct{ token, code string }{{"token-a", "code_not_found"}, {"token-b", "not_found"}} {
		response := sessionHTTPCall(handler, expected.token, "GET", path, "")
		var body struct {
			Code string `json:"code"`
		}
		if response.Code != 404 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Code != expected.code {
			t.Fatal("missing child confused with absent owner", response.Code, response.Body.String())
		}
	}
}

type codeFailAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	failAt int
}

func (a *codeFailAudit) Err() error { return nil }
func (a *codeFailAudit) Append(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	if len(a.events) == a.failAt {
		return errors.New("fixture audit unavailable")
	}
	return nil
}

func TestCodeLauncherAuditFailureStopsOwnerBeforeOrAfterMutation(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			var calls atomic.Int32
			s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
				calls.Add(1)
				info := testCodeContext()
				sendCodeReply(c, r, &CodeResponse{Kind: "context", Context: &info}, nil)
			})
			if err := s.manager.registerOwnedSession(s, "tenant-a"); err != nil {
				t.Fatal(err)
			}
			audit := &codeFailAudit{failAt: failAt}
			h := &LauncherSessionClient{socketPath: codeLauncherSocket(t, s, LauncherOptions{Audit: audit}), tenant: "tenant-a", id: s.info.ID}
			_, err := h.Code(context.Background(), CodeCommand{Operation: "default", Language: "python"})
			codeErrorIs(t, err, "unavailable")
			if !s.closed.Load() || calls.Load() != int32(failAt-1) {
				t.Fatal("audit failure retained work", calls.Load())
			}
			if value := s.manager.Capacity(); value.Active != 0 || value.Instances != 0 {
				t.Fatal("audit failure leaked resources", value)
			}
		})
	}
}
