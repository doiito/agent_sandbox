package sandbox

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSessionRunner struct {
	infoTransform       func(SessionInfo) SessionInfo
	created             atomic.Int32
	closeDelay          time.Duration
	handles             chan *LauncherSessionClient
	closeStarted        chan struct{}
	closeProceed        chan struct{}
	commandPollStarted  chan struct{}
	commandPollProceed  chan struct{}
	commandStaysRunning bool
}

func (*fakeSessionRunner) Run(context.Context, RunRequest) (RunResult, error) {
	return RunResult{}, nil
}

func (*fakeSessionRunner) Doctor() DoctorReport {
	return DoctorReport{Ready: true}
}

func (*fakeSessionRunner) Capabilities() (CapabilityReport, error) {
	return CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: "firecracker-linux", ArtifactAuthenticated: true, ArtifactManifestSHA256: strings.Repeat("a", 64), AllowedEntrypoints: []string{"/bin/sh"}}, nil
}

func TestSessionCreateRequiresTenantEntrypoint(t *testing.T) {
	auth := sessionAuthForTest()
	tenant, ok := auth.Authenticate("Bearer token-b")
	if !ok {
		t.Fatal("test tenant missing")
	}
	tenant.policy.AllowedEntrypoints = []string{"/bin/false"}
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, auth, slog.Default())
	created := sessionHTTPCall(handler, "token-b", http.MethodPost, "/v2/sessions",
		`{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != http.StatusForbidden {
		t.Fatalf("tenant without a permitted command created a session: %d", created.Code)
	}
}

func TestSessionQueryRejectsDeadLauncherWithoutWaitingForHeartbeat(t *testing.T) {
	fixture := &fakeSessionRunner{handles: make(chan *LauncherSessionClient, 1)}
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions",
		`{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	handle := <-fixture.handles
	if err := handle.conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("dead launcher retained cached running state: %d %s", response.Code, response.Body.String())
		}
	}
}

func TestSessionQueryWhileControlBusyDoesNotClaimConfirmedLiveness(t *testing.T) {
	fixture := &fakeSessionRunner{handles: make(chan *LauncherSessionClient, 1)}
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions",
		`{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatal(created.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	handle := <-fixture.handles
	handle.mu.Lock()
	response := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "")
	handle.mu.Unlock()
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("busy control returned cached liveness: %d", response.Code)
	}
	if response := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, ""); response.Code != http.StatusOK {
		t.Fatalf("busy probe destroyed a live session: %d", response.Code)
	}
	if response := sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("cannot close live session after busy probe: %d", response.Code)
	}
}

func (f *fakeSessionRunner) CreateSession(_ context.Context, request SessionCreateRequest, tenant string) (*LauncherSessionClient, SessionInfo, error) {
	sequence := f.created.Add(1)
	id := fmt.Sprintf("%024x", sequence)
	ttl := time.Minute
	if request.TTLMS > 0 {
		ttl = time.Duration(request.TTLMS) * time.Millisecond
	}
	now := time.Now()
	info := SessionInfo{ID: id, State: "running", Backend: "firecracker-linux", ArtifactManifestSHA256: request.ArtifactManifestSHA256, CreatedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), MaxExpiresAt: now.Add(600 * time.Second).UTC(), RemainingTTLMS: ttl.Milliseconds(), MemoryMiB: 128, VCPUs: 1, GuestProtocol: linuxSessionProtocol, LeaseRevision: 1}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		reader := bufio.NewReader(server)
		inputs := []SessionCommandInputReceipt{}
		for {
			frame, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var request launcherSessionRequest
			if json.Unmarshal(frame, &request) != nil {
				return
			}
			response := launcherSessionResponse{Protocol: launcherSessionProtocol}
			switch request.Operation {
			case "command-stdin-submit":
				data, _ := request.Input.data()
				receipt := SessionCommandInputReceipt{SessionID: id, CommandID: request.CommandID, Sequence: len(inputs) + 1, State: "delivered", WrittenBytes: len(data), Closed: request.Input.Close}
				if receipt.Closed {
					receipt.State = "closed"
				}
				inputs = append(inputs, receipt)
				response.InputReceipt = &receipt
			case "command-stdin-poll":
				if request.InputSequence < 1 || request.InputSequence > len(inputs) {
					response.Code = "command-not-found"
					response.Error = "input not found"
				} else {
					receipt := inputs[request.InputSequence-1]
					response.InputReceipt = &receipt
				}

			case "timeout":
				if time.Now().Add(time.Duration(request.TTLMS) * time.Millisecond).After(info.MaxExpiresAt) {
					response.Code = "timeout-lifetime"
					response.Error = ErrTimeoutBeyondLifetime.Error()
				} else {
					info.ExpiresAt = time.Now().Add(time.Duration(request.TTLMS) * time.Millisecond).UTC()
					info.RemainingTTLMS = int64(request.TTLMS)
					info.LeaseRevision++
					response.Info = &info
				}
			case "ping":
				info.RemainingTTLMS = max(0, time.Until(info.ExpiresAt).Milliseconds())
				if !info.ExpiresAt.After(time.Now()) {
					info.State = "closed"
				}
				response.Info = &info
				if f.infoTransform != nil {
					transformed := f.infoTransform(info)
					response.Info = &transformed
				}
			case "command-start":
				response.CommandInfo = &SessionCommandInfo{ID: strings.Repeat("c", 24), SessionID: id, State: "running"}
			case "command-list":
				list := []SessionCommandInfo{{ID: strings.Repeat("c", 24), SessionID: id, State: "running"}}
				response.Commands = &list
			case "command-poll":
				if f.commandPollStarted != nil {
					f.commandPollStarted <- struct{}{}
					<-f.commandPollProceed
				}
				events := []SessionOutputEvent{}
				if request.After == 0 {
					events = append(events, SessionOutputEvent{Sequence: 1, Stream: "stdout", DataBase64: "eA=="})
				}
				response.CommandPage = &SessionCommandPage{Info: SessionCommandInfo{ID: request.CommandID, SessionID: id, State: "succeeded"},
					Events: events, NextSequence: 1, Complete: true, Result: &SessionCommandResult{SessionID: id, RunResult: RunResult{ID: request.CommandID, State: "succeeded", ProtocolOK: true}}}
				if f.commandStaysRunning {
					response.CommandPage.Complete = false
					response.CommandPage.Result = nil
					response.CommandPage.Info.State = "running"
				}

			case "command-kill":
				killed := true
				response.Killed = &killed
			case "run":
				if len(request.Command.Args) > 0 && request.Command.Args[0] == "block" {
					time.Sleep(100 * time.Millisecond)
				}
				response.Result = &SessionCommandResult{SessionID: id, RunResult: RunResult{
					ID: "0123456789abcdef01234567", State: "succeeded", ProtocolOK: true,
				}}
			case "file":
				result := SessionFileResult{SessionID: id, Action: request.File.Action, Path: request.File.Path}
				switch request.File.Action {
				case "read":
					encoded := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255})
					result.DataBase64, result.Size = &encoded, 4
				case "write":
					data, _ := base64.StdEncoding.DecodeString(*request.File.DataBase64)
					result.Size = len(data)
				case "list":
					entries := []string{"item", "sub"}
					result.Size, result.Entries = len(entries), &entries
				case "stat":
					result.Size, result.Kind = 4, "file"
				case "delete", "remove":
					result.Size = 0
				case "rename":
					result.Destination = request.File.Destination
					result.Kind, result.Size = "file", 4
					result.Info = &SessionFileInfo{Path: *request.File.Destination, Name: filepath.Base(*request.File.Destination),
						Type: "file", Size: 4, Mode: 0o100600, Permissions: "rw-------", Owner: "agent", Group: "agent", ModifiedTimeMS: 1}
				case "mkdir":
					created := true
					result.Created = &created
				}
				response.File = &result
			case "close":
				if f.closeStarted != nil {
					select {
					case f.closeStarted <- struct{}{}:
					default:
					}
				}
				if f.closeProceed != nil {
					<-f.closeProceed
				}
				if f.closeDelay > 0 {
					time.Sleep(f.closeDelay)
				}
				_ = json.NewEncoder(server).Encode(response)
				return
			default:
				return
			}
			if json.NewEncoder(server).Encode(response) != nil {
				return
			}
		}
	}()
	handle := &LauncherSessionClient{conn: client, reader: bufio.NewReader(client), id: id, tenant: tenant}
	if f.handles != nil {
		f.handles <- handle
	}
	return handle, info, nil
}

func TestSessionFileAPIConfinesTenantPathAndBytes(t *testing.T) {
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions",
		`{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d", created.Code)
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	path := "/v2/sessions/" + info.ID + "/files"
	read := `{"action":"read","path":"/workspace/item"}`
	if got := sessionHTTPCall(handler, "token-b", http.MethodPost, path, read).Code; got != http.StatusNotFound {
		t.Fatalf("cross-tenant file status=%d", got)
	}
	for _, invalid := range []string{
		`{"action":"read","path":"/workspace/../secret"}`,
		`{"action":"write","path":"/workspace/item","data_base64":"@@"}`,
	} {
		if got := sessionHTTPCall(handler, "token-a", http.MethodPost, path, invalid).Code; got != http.StatusBadRequest {
			t.Fatalf("invalid file request status=%d", got)
		}
	}
	write := `{"action":"write","path":"/workspace/item","data_base64":"AAEC/w=="}`
	if got := sessionHTTPCall(handler, "token-a", http.MethodPost, path, write).Code; got != http.StatusOK {
		t.Fatalf("write file status=%d", got)
	}
	response := sessionHTTPCall(handler, "token-a", http.MethodPost, path, read)
	if response.Code != http.StatusOK {
		t.Fatalf("read file status=%d", response.Code)
	}
	var result SessionFileResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SessionID != info.ID || result.DataBase64 == nil || *result.DataBase64 != "AAEC/w==" || result.Size != 4 {
		t.Fatalf("incorrect file response: %+v", result)
	}
	for _, action := range []string{"list", "stat", "delete", "mkdir", "remove"} {
		filePath := "/workspace/item"
		if action == "list" {
			filePath = "/workspace"
		}
		body := `{"action":"` + action + `","path":"` + filePath + `"}`
		response := sessionHTTPCall(handler, "token-a", http.MethodPost, path, body)
		if response.Code != http.StatusOK {
			t.Fatalf("%s file status=%d", action, response.Code)
		}
		var got SessionFileResult
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Action != action || got.Path != filePath || got.SessionID != info.ID {
			t.Fatalf("%s file result binding=%+v", action, got)
		}
		if action == "mkdir" && (got.Created == nil || !*got.Created) {
			t.Fatalf("mkdir created result missing: %+v", got)
		}
	}
	rename := sessionHTTPCall(handler, "token-a", http.MethodPost, path,
		`{"action":"rename","path":"/workspace/item","destination":"/workspace/renamed"}`)
	if rename.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rename.Code, rename.Body.String())
	}
	var moved SessionFileResult
	if err := json.Unmarshal(rename.Body.Bytes(), &moved); err != nil || moved.Destination == nil || *moved.Destination != "/workspace/renamed" || moved.Info == nil || moved.Info.Path != "/workspace/renamed" {
		t.Fatalf("rename binding: %+v %v", moved, err)
	}
	for _, body := range []string{
		`{"action":"rename","path":"/workspace/item","destination":"/etc/out"}`,
		`{"action":"remove","path":"/workspace"}`,
		`{"action":"read","path":"/workspace/item","destination":"/workspace/other"}`,
	} {
		if got := sessionHTTPCall(handler, "token-a", http.MethodPost, path, body).Code; got != http.StatusBadRequest {
			t.Fatalf("invalid mutation status %d", got)
		}
	}
	if got := sessionHTTPCall(handler, "token-b", http.MethodPost, path,
		`{"action":"delete","path":"/workspace/item"}`).Code; got != http.StatusNotFound {
		t.Fatalf("cross-tenant delete status=%d", got)
	}
	sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, "")
}

func sessionAuthForTest() *Authenticator {
	a := sha256.Sum256([]byte("token-a"))
	b := sha256.Sum256([]byte("token-b"))
	makeTenant := func(id string) *tenantRuntime {
		policy := TenantPolicy{ID: id, AllowedEntrypoints: []string{"/bin/sh"}, RequestsPerSecond: 100, Burst: 100, MaxConcurrent: 1}
		return &tenantRuntime{policy: policy, sem: make(chan struct{}, 1), tokens: 100, last: time.Now()}
	}
	return &Authenticator{tenants: map[[sha256.Size]byte]*tenantRuntime{a: makeTenant("tenant-a"), b: makeTenant("tenant-b")}}
}

func sessionHTTPCall(handler http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSessionAPIKeepsTenantSlotAndRejectsCrossTenantAccess(t *testing.T) {
	runner := &fakeSessionRunner{}
	handler := NewAPIWithAuthenticator(runner, sessionAuthForTest(), slog.Default())
	createBody := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `"}`
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	path := "/v2/sessions/" + info.ID
	if got := sessionHTTPCall(handler, "token-b", http.MethodGet, path, "").Code; got != http.StatusNotFound {
		t.Fatalf("other tenant discovered session: %d", got)
	}
	commandBody := `{"entrypoint":"/bin/sh","args":["-c","true"]}`
	if got := sessionHTTPCall(handler, "token-b", http.MethodPost, path+"/commands", commandBody).Code; got != http.StatusNotFound {
		t.Fatalf("other tenant executed session: %d", got)
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodPost, path+"/commands", commandBody).Code; got != http.StatusOK {
		t.Fatalf("owner command status=%d", got)
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody).Code; got != http.StatusTooManyRequests {
		t.Fatalf("held session slot was ignored: %d", got)
	}
	if got := sessionHTTPCall(handler, "token-b", http.MethodDelete, path, "").Code; got != http.StatusNotFound {
		t.Fatalf("other tenant deleted session: %d", got)
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodDelete, path, "").Code; got != http.StatusNoContent {
		t.Fatalf("owner delete status=%d", got)
	}
	recreated := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	if recreated.Code != http.StatusCreated {
		t.Fatalf("session slot was not released: %d", recreated.Code)
	}
	var newInfo SessionInfo
	if err := json.Unmarshal(recreated.Body.Bytes(), &newInfo); err != nil {
		t.Fatal(err)
	}
	sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+newInfo.ID, "")
}

func TestSessionCommandCancellationQuarantinesTenantSlot(t *testing.T) {
	runner := &fakeSessionRunner{}
	handler := NewAPIWithAuthenticator(runner, sessionAuthForTest(), slog.Default())
	createBody := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `"}`
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v2/sessions/"+info.ID+"/commands", strings.NewReader(`{"entrypoint":"/bin/sh","args":["block"]}`)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer token-a")
	finished := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(finished)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("canceled session command did not return")
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "").Code; got != http.StatusNotFound {
		t.Fatalf("canceled session remained visible: %d", got)
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody).Code; got != http.StatusTooManyRequests {
		t.Fatalf("tenant slot released before uncertain cleanup: %d", got)
	}
}

func TestUncertainSessionCloseHoldsSlotThroughCleanupWindow(t *testing.T) {
	api := &API{log: slog.Default(), sessionCleanupHold: 25 * time.Millisecond}
	released := make(chan struct{})
	api.releaseSessionAfterClose(func() { close(released) }, ErrSessionClosed)
	select {
	case <-released:
		t.Fatal("uncertain cleanup released quota immediately")
	default:
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("uncertain cleanup never released quota")
	}
}

func TestSessionTTLReleasesTenantSlot(t *testing.T) {
	proceed := make(chan struct{})
	started := make(chan struct{}, 1)
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{closeStarted: started, closeProceed: proceed}, sessionAuthForTest(), slog.Default())
	createBody := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `","ttl_ms":50}`
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TTL did not start cleanup")
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "").Code; got != http.StatusNotFound {
		t.Fatalf("expired session visible during cleanup: %d", got)
	}
	if got := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody).Code; got != http.StatusTooManyRequests {
		t.Fatalf("quota released before cleanup acknowledgment: %d", got)
	}
	close(proceed)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recreated := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
		if recreated.Code == http.StatusTooManyRequests {
			time.Sleep(time.Millisecond)
			continue
		}
		if recreated.Code != http.StatusCreated {
			t.Fatalf("recreate failed: %d %s", recreated.Code, recreated.Body.String())
		}
		var next SessionInfo
		if err := json.Unmarshal(recreated.Body.Bytes(), &next); err != nil {
			t.Fatal(err)
		}
		sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+next.ID, "")
		return
	}
	t.Fatal("quota did not return after cleanup acknowledgment")
}

func TestSessionDeleteWaitsForLauncherCleanupAck(t *testing.T) {
	runner := &fakeSessionRunner{closeDelay: 50 * time.Millisecond}
	handler := NewAPIWithAuthenticator(runner, sessionAuthForTest(), slog.Default())
	createBody := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `"}`
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d", created.Code)
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if got := sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, "").Code; got != http.StatusNoContent {
		t.Fatalf("delete status=%d", got)
	}
	if time.Since(started) < runner.closeDelay {
		t.Fatal("delete returned before launcher acknowledged cleanup")
	}
	recreated := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", createBody)
	if recreated.Code != http.StatusCreated {
		t.Fatalf("tenant slot remained held after cleanup acknowledgment: %d", recreated.Code)
	}
	var next SessionInfo
	if err := json.Unmarshal(recreated.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+next.ID, "")
}
