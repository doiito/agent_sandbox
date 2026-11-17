package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPreviewGrantActiveHistoryQuotaAndPolicyIndependentCleanup(t *testing.T) {
	t.Run("active-and-policy", func(t *testing.T) {
		f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
		var first PreviewGrantInfo
		for i := 1; i <= previewSessionLimit; i++ {
			info := f.create(t, fmt.Sprintf("%024x", i), 10000)
			if i == 1 {
				first = info
			}
		}
		path := fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%024x", first.SessionID, f.port, 9)
		status, _ := f.control(t, "POST", path, "token-a", map[string]int{"ttl_ms": 10000})
		if status != 429 {
			t.Fatal("active quota bypassed", status)
		}
		f.api.apiTenant.policy.Ports.Preview = false
		status, _ = f.control(t, "POST", path, "token-a", map[string]int{"ttl_ms": 10000})
		if status != 403 {
			t.Fatal("policy bypassed", status)
		}
		control := "/v2/sessions/" + first.SessionID + "/previews/" + first.ID
		status, _ = f.control(t, "GET", control, "token-a", nil)
		if status != 200 {
			t.Fatal("policy change blocked observation")
		}
		status, _ = f.control(t, "DELETE", control, "token-a", nil)
		if status != 200 {
			t.Fatal("policy change blocked cleanup")
		}
		f.api.apiTenant.policy.Ports.Preview = true
		status, _ = f.control(t, "POST", path, "token-a", map[string]int{"ttl_ms": 10000})
		if status != 201 {
			t.Fatal("revocation did not release active quota", status)
		}
		if f.guest.opens.Load() != 0 {
			t.Fatal("grant metadata opened TCP")
		}
	})
	t.Run("non-evicting-history", func(t *testing.T) {
		f := newPreviewFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		for i := 1; i <= previewHistoryLimit; i++ {
			info := f.create(t, fmt.Sprintf("%024x", i), 10000)
			status, _ := f.control(t, "DELETE", "/v2/sessions/"+info.SessionID+"/previews/"+info.ID, "token-a", nil)
			if status != 200 {
				t.Fatal(status)
			}
		}
		path := fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%024x", f.api.session.info.ID, f.port, 33)
		status, _ := f.control(t, "POST", path, "token-a", map[string]int{"ttl_ms": 10000})
		if status != 429 {
			t.Fatal("grant history bound bypassed", status)
		}
	})
}

func TestPreviewRootPolicyIsIndependentAndNativePortRemainsAvailable(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	info := f.create(t, strings.Repeat("b", 24), 5000)
	cookie := f.bootstrap(t, info)
	f.api.owner.policy.Ports.Preview = false
	response := f.request(t, "GET", info.Origin, cookie, nil, nil)
	if response.StatusCode != 403 {
		t.Fatal("root preview denial bypassed", response.StatusCode)
	}
	previewRead(t, response)
	if f.guest.opens.Load() != 0 {
		t.Fatal("root denied preview reached guest")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := portOpenRequest(31)
	request.Port = f.port
	stream, err := f.api.session.handle.OpenPort(ctx, ctx, request)
	if err != nil {
		t.Fatal("native ports incorrectly require preview permission", err)
	}
	defer stream.Close()
	_, err = stream.Write([]byte("GET / HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var data []byte
	for {
		frame, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, frame.Data...)
		if frame.Info != nil {
			if frame.Info.Status != "completed" {
				t.Fatal("native port failed")
			}
			break
		}
	}
	if !bytes.Contains(data, []byte("ok")) {
		t.Fatal("native application response missing")
	}
}

func TestPreviewCapabilityNeedsEnabledListenerPolicyAndV6(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	f.api.session.capability.AllowedEntrypoints = []string{"/bin/bash"}
	f.api.session.capability.Methods = []string{}
	path := "/v2/sessions/" + f.api.session.info.ID + "/capabilities"
	read := func() CapabilityReport {
		status, data := f.control(t, "GET", path, "token-a", nil)
		if status != 200 {
			t.Fatal(status)
		}
		var result SessionCapabilityReport
		if json.Unmarshal(data, &result) != nil {
			t.Fatal("bad capabilities")
		}
		return result.CapabilityReport
	}
	for _, protocol := range []string{"osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8"} {
		f.api.session.capability.ArtifactManifestProtocol = protocol
		cap := read()
		if !cap.Features.PortPreview || cap.PortForwardPolicy == nil || !cap.PortForwardPolicy.Preview {
			t.Fatal("signed profile lost preview", protocol, cap)
		}
	}
	cap := read()
	if !cap.Features.PortPreview || cap.PortForwardPolicy == nil || !cap.PortForwardPolicy.Preview || cap.Limits.PreviewGrantIDs != 32 || cap.Limits.PreviewGrants != 8 {
		t.Fatal("preview capability missing")
	}
	if f.api.session.capability.Features.PortPreview {
		t.Fatal("filter changed immutable session contract")
	}
	f.api.apiTenant.policy.Ports.Preview = false
	cap = read()
	if cap.Features.PortPreview || cap.PortForwardPolicy.Preview || cap.Limits.PreviewGrants != 0 {
		t.Fatal("policy not reflected")
	}
	f.api.apiTenant.policy.Ports.Preview = true
	f.api.session.capability.ArtifactManifestProtocol = "osv-sandbox-artifacts/v5"
	cap = read()
	if cap.Features.PortPreview || cap.Limits.PreviewGrants != 0 {
		t.Fatal("old profile acquired preview")
	}
	status, _ := f.control(t, "POST", fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%s", f.api.session.info.ID, f.port, strings.Repeat("a", 24)), "token-a", map[string]int{"ttl_ms": 5000})
	if status != 501 {
		t.Fatal("old profile preview admission bypassed", status)
	}
	f.api.session.capability.ArtifactManifestProtocol = "osv-sandbox-artifacts/v6"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if f.api.handler.Shutdown(ctx) != nil {
		t.Fatal("shutdown failed")
	}
	cap = read()
	if cap.Features.PortPreview || cap.Limits.PreviewGrants != 0 {
		t.Fatal("closed listener advertised preview")
	}
}

func TestPreviewPendingOpenIsCancelledAndShutdownJoinsDial(t *testing.T) {
	entered, closed := make(chan struct{}), make(chan struct{})
	f := newPortHTTPFixture(t, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
		if r.Operation != "open" {
			sendPortControlInfo(c, r, "cancelled")
			return
		}
		close(entered)
		_, _ = io.Copy(io.Discard, reader)
		close(closed)
	})
	f.owner.policy.Ports.Preview = true
	f.apiTenant.policy.Ports.Preview = true
	p, err := newPreviewService(f.handler.api, previewConfigForTest())
	if err != nil {
		t.Fatal(err)
	}
	f.handler.api.preview = p
	info, err := p.create(f.session, strings.Repeat("c", 24), 8080, 5000)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	grant := f.session.previews[info.ID]
	p.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		conn, err := p.dial(context.Background(), grant)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.handler.Shutdown(ctx); err != nil {
		t.Fatal("pending shutdown did not finish", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending open succeeded after shutdown")
		}
	case <-ctx.Done():
		t.Fatal("dial not joined")
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("guest handshake was not closed")
	}
}

func TestPreviewSessionCloseRevokesGrantWithoutExtendingLease(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	f.api.session.mu.Lock()
	f.api.session.deadline = time.Now().Add(2 * time.Second)
	deadline := f.api.session.deadline
	f.api.session.mu.Unlock()
	info := f.create(t, strings.Repeat("d", 24), 300000)
	if info.ExpiresAt.After(deadline) {
		t.Fatal("grant extended session")
	}
	cookie := f.bootstrap(t, info)
	f.api.session.close(f.api.handler.api)
	response := f.request(t, "GET", info.Origin, cookie, nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("closed session still served preview")
	}
	previewRead(t, response)
}

func TestPreviewRejectsWrongHostReservedPathsOriginsAndOversizedBody(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid request reached app") }))
	info := f.create(t, strings.Repeat("e", 24), 5000)
	cookie := f.bootstrap(t, info)
	for _, row := range []struct {
		method, path string
		headers      http.Header
		body         io.Reader
		status       int
	}{
		{"GET", "/.osv/hidden", nil, nil, 404},
		{"GET", "/", http.Header{"Origin": {"https://other.test"}}, nil, 403},
		{"POST", "/", http.Header{"Sec-Fetch-Site": {"cross-site"}}, bytes.NewReader([]byte("x")), 403},
		{"CONNECT", "/", nil, nil, 405},
		{"POST", "/", nil, bytes.NewReader(make([]byte, previewRequestBytes+1)), 413},
	} {
		response := f.request(t, row.method, info.Origin+row.path, cookie, row.headers, row.body)
		if response.StatusCode != row.status {
			t.Errorf("%s %s = %d", row.method, row.path, response.StatusCode)
		}
		previewRead(t, response)
	}
	response := f.request(t, "GET", "https://unknown.preview.test:9444/", cookie, nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("wrong host accepted")
	}
	previewRead(t, response)
	if f.guest.opens.Load() != 0 {
		t.Fatal("rejected requests opened TCP")
	}
}
