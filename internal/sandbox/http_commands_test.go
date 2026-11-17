package sandbox

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBackgroundCommandHTTPAndSSEKeepTenantBinding(t *testing.T) {
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	var info SessionInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	defer sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, "")
	path := "/v2/sessions/" + info.ID + "/commands"
	started := sessionHTTPCall(handler, "token-a", http.MethodPost, path+"/start", `{"entrypoint":"/bin/sh","args":["-c","printf x"]}`)
	if started.Code != 202 {
		t.Fatalf("start: %d %s", started.Code, started.Body.String())
	}
	var command SessionCommandInfo
	if err := json.Unmarshal(started.Body.Bytes(), &command); err != nil {
		t.Fatal(err)
	}
	if command.SessionID != info.ID {
		t.Fatal("wrong session owner")
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for _, suffix := range []string{"/" + command.ID, "/" + command.ID + "/events"} {
			if method == http.MethodDelete && strings.HasSuffix(suffix, "/events") {
				continue
			}
			denied := sessionHTTPCall(handler, "token-b", method, path+suffix, "")
			if denied.Code != 404 {
				t.Fatalf("cross tenant command exposed: %d %s", denied.Code, denied.Body.String())
			}
		}
	}
	listed := sessionHTTPCall(handler, "token-a", http.MethodGet, path, "")
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), command.ID) {
		t.Fatal("command list lost handle")
	}
	events := sessionHTTPCall(handler, "token-a", http.MethodGet, path+"/"+command.ID+"/events", "")
	if events.Code != 200 || events.Header().Get("Content-Type") != "text/event-stream" || strings.Count(events.Body.String(), "event: output") != 1 || strings.Count(events.Body.String(), "event: result") != 1 {
		t.Fatalf("invalid stream: %d %s", events.Code, events.Body.String())
	}
	resumed := sessionHTTPCall(handler, "token-a", http.MethodGet, path+"/"+command.ID+"/events?after=1", "")
	if resumed.Code != 200 || strings.Contains(resumed.Body.String(), "event: output") || !strings.Contains(resumed.Body.String(), "event: result") {
		t.Fatal("cursor resume repeated output")
	}
	invalid := sessionHTTPCall(handler, "token-a", http.MethodGet, path+"/"+command.ID+"?after=-1", "")
	if invalid.Code != 400 {
		t.Fatal("negative output cursor accepted")
	}
	denied := sessionHTTPCall(handler, "token-a", http.MethodPost, path+"/start", `{"entrypoint":"/bin/denied"}`)
	if denied.Code != 403 {
		t.Fatal("background start bypassed entrypoint policy")
	}
}

func TestCommandObserverDisconnectDoesNotCloseSessionController(t *testing.T) {
	fixture := &fakeSessionRunner{commandPollStarted: make(chan struct{}, 1), commandPollProceed: make(chan struct{})}
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	var info SessionInfo
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &info) != nil {
		t.Fatal(created.Body.String())
	}
	defer sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v2/sessions/"+info.ID+"/commands/"+strings.Repeat("c", 24), nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer token-a")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(httptest.NewRecorder(), req); close(done) }()
	select {
	case <-fixture.commandPollStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("observer never reached launcher")
	}
	cancel()
	close(fixture.commandPollProceed)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("observer failed to release RPC")
	}
	live := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "")
	if live.Code != 200 {
		t.Fatalf("observer disconnect destroyed session: %d %s", live.Code, live.Body.String())
	}
}

func TestCommandObservationTimeoutDoesNotCancelSession(t *testing.T) {
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{commandStaysRunning: true}, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	var info SessionInfo
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &info) != nil {
		t.Fatal(created.Body.String())
	}
	defer sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+info.ID, "")
	path := "/v2/sessions/" + info.ID + "/commands/" + strings.Repeat("c", 24) + "/events?timeout_ms=10"
	response := sessionHTTPCall(handler, "token-a", http.MethodGet, path, "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), "event: timeout") {
		t.Fatalf("observation did not time out: %d %s", response.Code, response.Body.String())
	}
	query := sessionHTTPCall(handler, "token-a", http.MethodGet, "/v2/sessions/"+info.ID, "")
	if query.Code != 200 {
		t.Fatal("observation deadline destroyed session")
	}
}

func TestCommandControlWaitsForObserverRPC(t *testing.T) {
	fixture := &fakeSessionRunner{commandPollStarted: make(chan struct{}, 1), commandPollProceed: make(chan struct{})}
	handle, _, err := fixture.CreateSession(context.Background(), SessionCreateRequest{}, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	polled := make(chan error, 1)
	go func() { _, err := handle.PollCommand(ctx, strings.Repeat("c", 24), 0); polled <- err }()
	select {
	case <-fixture.commandPollStarted:
	case <-ctx.Done():
		t.Fatal("observer did not reach launcher")
	}
	listed := make(chan error, 1)
	go func() { _, err := handle.ListCommands(ctx); listed <- err }()
	select {
	case err := <-listed:
		t.Fatalf("control did not wait for observer RPC: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(fixture.commandPollProceed)
	for _, done := range []chan error{polled, listed} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("command RPC failed to resume")
		}
	}
	if err := handle.Ping(ctx); err != nil {
		t.Fatal("observer/control concurrency destroyed controller", err)
	}
}

func TestCommandInputHTTPKeepsOwnerAndValidatesBeforeSubmit(t *testing.T) {
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", http.MethodPost, "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	var session SessionInfo
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil {
		t.Fatal(created.Body.String())
	}
	defer sessionHTTPCall(handler, "token-a", http.MethodDelete, "/v2/sessions/"+session.ID, "")
	path := "/v2/sessions/" + session.ID + "/commands/" + strings.Repeat("c", 24) + "/stdin"
	posted := sessionHTTPCall(handler, "token-a", http.MethodPost, path, `{"data_base64":"AP8=","close":false}`)
	if posted.Code != 202 {
		t.Fatal(posted.Code, posted.Body.String())
	}
	var receipt SessionCommandInputReceipt
	if json.Unmarshal(posted.Body.Bytes(), &receipt) != nil || receipt.Sequence != 1 || receipt.WrittenBytes != 2 {
		t.Fatal("wrong receipt", posted.Body.String())
	}
	polled := sessionHTTPCall(handler, "token-a", http.MethodGet, path+"/1", "")
	if polled.Code != 200 || polled.Body.String() != posted.Body.String() {
		t.Fatal("lost confirmation", polled.Body.String())
	}
	for _, body := range []string{`{"data_base64":"%%"}`, `{"data_base64":"Zg==","close":true}`, `{"data_base64":"","close":true,"unknown":1}`} {
		invalid := sessionHTTPCall(handler, "token-a", http.MethodPost, path, body)
		if invalid.Code != 400 {
			t.Fatal("invalid stdin accepted", invalid.Code)
		}
	}
	huge := sessionHTTPCall(handler, "token-a", http.MethodPost, path, `{"data_base64":"`+strings.Repeat("A", 23000)+`"}`)
	if huge.Code != 413 {
		t.Fatal("input size bound missing", huge.Code)
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		target := path
		body := `{"data_base64":"eA=="}`
		if method == http.MethodGet {
			target += "/1"
			body = ""
		}
		denied := sessionHTTPCall(handler, "token-b", method, target, body)
		if denied.Code != 404 {
			t.Fatal("foreign stdin accessible", denied.Code)
		}
	}
	invalid := sessionHTTPCall(handler, "token-a", http.MethodGet, path+"/257", "")
	if invalid.Code != 400 {
		t.Fatal("invalid input sequence accepted", invalid.Code)
	}
}
