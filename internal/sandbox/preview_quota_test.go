package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPreviewRealRequestQuotaAndQueuedCancellation(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	info := f.create(t, strings.Repeat("f", 24), 10000)
	cookie := f.bootstrap(t, info)
	done := make(chan error, previewRequestLimit)
	for i := 0; i < previewRequestLimit; i++ {
		go func() {
			request, _ := http.NewRequest("GET", info.Origin+"/blocked", nil)
			request.AddCookie(cookie)
			response, err := f.browser.Do(request)
			if response != nil {
				_ = response.Body.Close()
				if response.StatusCode == 200 {
					err = fmt.Errorf("blocked application unexpectedly succeeded")
				}
			}
			done <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.service.mu.Lock()
		active := f.service.inflight
		f.service.mu.Unlock()
		if active == previewRequestLimit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real requests did not reach the bounded admission limit", active)
		}
		time.Sleep(time.Millisecond)
	}
	response := f.request(t, "GET", info.Origin+"/overflow", cookie, nil, nil)
	if response.StatusCode != 429 {
		t.Fatal("request quota bypassed", response.StatusCode)
	}
	previewRead(t, response)
	status, _ := f.control(t, "DELETE", "/v2/sessions/"+info.SessionID+"/previews/"+info.ID, "token-a", nil)
	if status != 200 {
		t.Fatal(status)
	}
	for i := 0; i < previewRequestLimit; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("queued or active request not reaped")
		}
	}
	if f.guest.opens.Load() > 8 {
		t.Fatal("HTTP pool exceeded native connection bound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.api.handler.Shutdown(ctx); err != nil {
		t.Fatal("shutdown after quota", err)
	}
	f.service.mu.Lock()
	inflight := f.service.inflight
	f.service.mu.Unlock()
	if inflight != 0 {
		t.Fatal("request slots leaked")
	}
}

func TestLauncherPreviewAuditBindsGrantAndKeepsPayloadPrivate(t *testing.T) {
	s, owner := portTestSession(t, 1, func(c net.Conn, r *bufio.Reader, request linuxPortRequest) { portEchoGuest(t, c, r, request) })
	owner.policy.Ports.Preview = true
	audit := &portMemoryAudit{}
	handle := portLauncherFixture(t, s, owner, audit, os.Geteuid())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	previewID := strings.Repeat("7", 24)
	stream, err := handle.OpenPreviewPort(ctx, ctx, portOpenRequest(19), previewID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := []byte("private-preview-payload")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		if frame.Info != nil {
			break
		}
	}
	audit.mu.Lock()
	events := append([]AuditEvent{}, audit.events...)
	audit.mu.Unlock()
	if len(events) < 3 {
		t.Fatal("preview audit incomplete")
	}
	for _, event := range events {
		if event.PreviewID != previewID {
			t.Fatal("grant audit binding missing")
		}
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), string(payload)) || strings.Contains(string(encoded), "nonce") {
		t.Fatal("private protocol data reached audit")
	}
}
