package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type artifactHTTPFixture struct{ watchHTTPFixture }

func (f *artifactHTTPFixture) Capabilities() (CapabilityReport, error) {
	return f.session.manager.Capabilities()
}

func artifactHTTPSetup(t *testing.T) (*Session, *LauncherSessionClient, http.Handler, string, *portMemoryAudit, []byte) {
	t.Helper()
	data := bytes.Repeat([]byte{0, 255, 42, 10, 128}, 150001)
	s := artifactTestSession(t, func(c net.Conn, r linuxArtifactRequest) {
		entries := []linuxArtifactEntry{{Path: "empty", Type: "directory", Mode: 0o40700}, {Path: "报告.bin", Type: "file", Mode: 0o100644, Size: int64(len(data))}}
		_, _ = c.Write(artifactTestWire(r, artifactTestFrames(r, "directory", entries, map[string][]byte{"报告.bin": data})))
	})
	audit := &portMemoryAudit{}
	owner := &tenantRuntime{policy: TenantPolicy{ID: "tenant-a"}}
	h := portLauncherFixture(t, s, owner, audit, os.Geteuid())
	fixture := &artifactHTTPFixture{watchHTTPFixture{fakeSessionRunner: fakeSessionRunner{handles: make(chan *LauncherSessionClient, 1)}, socket: h.socketPath, session: s}}
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	var info SessionInfo
	if json.Unmarshal(created.Body.Bytes(), &info) != nil {
		t.Fatal("bad session create")
	}
	actual := <-fixture.handles
	t.Cleanup(func() { _ = sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+info.ID, "") })
	return s, actual, handler, "/v2/sessions/" + info.ID, audit, data
}

func createHTTPArtifact(t *testing.T, handler http.Handler, path string) SessionArtifactInfo {
	t.Helper()
	response := sessionHTTPCall(handler, "token-a", "POST", path+"/artifacts", `{"path":"/workspace"}`)
	var info SessionArtifactInfo
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &info) != nil || !info.valid() {
		t.Fatal(response.Code, response.Body.String())
	}
	return info
}

func TestSessionArtifactHTTPDownloadQuotaOwnershipAndDelete(t *testing.T) {
	s, h, handler, path, audit, payload := artifactHTTPSetup(t)
	h.mu.Lock() // All artifact RPCs must be independent of foreground Run.
	first := createHTTPArtifact(t, handler, path)
	second := createHTTPArtifact(t, handler, path)
	h.mu.Unlock()
	response := sessionHTTPCall(handler, "token-a", "POST", path+"/artifacts", `{"path":"/workspace"}`)
	if response.Code != 429 || !strings.Contains(response.Body.String(), `"code":"artifact_limit"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	var archive []byte
	for offset := int64(0); offset < first.Size; {
		body, _ := json.Marshal(SessionArtifactReadRequest{Offset: offset, Length: sessionArtifactReadBytes})
		response := sessionHTTPCall(handler, "token-a", "POST", path+"/artifacts/"+first.ID+"/read", string(body))
		var chunk SessionArtifactChunk
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &chunk) != nil || !chunk.valid(s.info.ID, first.ID, SessionArtifactReadRequest{Offset: offset, Length: sessionArtifactReadBytes}) || chunk.ArchiveSHA256 != first.SHA256 {
			t.Fatal(response.Code, response.Body.String())
		}
		data, _ := base64.StdEncoding.DecodeString(chunk.DataBase64)
		archive = append(archive, data...)
		offset += int64(len(data))
	}
	if artifactTestSHA(archive) != first.SHA256 {
		t.Fatal("download digest mismatch")
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if header.Name == "报告.bin" {
			data, _ := io.ReadAll(reader)
			if !bytes.Equal(data, payload) {
				t.Fatal("binary contents changed")
			}
		}
	}
	if strings.Join(names, ",") != artifactManifestName+",empty/,报告.bin" {
		t.Fatal(names)
	}
	for _, call := range []struct {
		method, url, body string
		status            int
	}{
		{"POST", path + "/artifacts/" + first.ID + "/read", `{"offset":-1,"length":1}`, 416},
		{"POST", path + "/artifacts/" + first.ID + "/read", `{"offset":0,"length":524289}`, 416},
		{"POST", path + "/artifacts", `{"path":"/workspace/../etc"}`, 400},
		{"POST", path + "/artifacts", `{"path":"/workspace","unknown":true}`, 400},
		{"POST", path + "/artifacts/" + strings.Repeat("f", 24) + "/read", `{"offset":0,"length":1}`, 404},
	} {
		r := sessionHTTPCall(handler, "token-a", call.method, call.url, call.body)
		if r.Code != call.status {
			t.Fatal(call, r.Code, r.Body.String())
		}
	}
	for _, method := range []string{"POST", "DELETE"} {
		url := path + "/artifacts/" + first.ID
		body := ""
		if method == "POST" {
			url += "/read"
			body = `{"offset":0,"length":1}`
		}
		r := sessionHTTPCall(handler, "token-b", method, url, body)
		if r.Code != 404 {
			t.Fatal("wrong tenant reached archive", r.Code)
		}
	}
	if r := sessionHTTPCall(handler, "token-a", "DELETE", path+"/artifacts/"+first.ID, ""); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := sessionHTTPCall(handler, "token-a", "DELETE", path+"/artifacts/"+first.ID, ""); r.Code != 404 {
		t.Fatal(r.Code)
	}
	third := createHTTPArtifact(t, handler, path)
	if third.ID == first.ID || third.ID == second.ID {
		t.Fatal("artifact identity reused")
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, event := range audit.events {
		encoded, _ := json.Marshal(event)
		if bytes.Contains(encoded, []byte("报告")) || bytes.Contains(encoded, []byte("/workspace")) {
			t.Fatal("filenames entered audit")
		}
	}
}

func TestSessionArtifactCapabilitiesBoundToSignedTemplateAndBackend(t *testing.T) {
	s := artifactTestSession(t, func(net.Conn, linuxArtifactRequest) { t.Error("capability discovery reached guest") })
	for _, enabled := range []bool{true, false} {
		b := s.backend
		b.WorkspaceArtifacts = enabled
		s.manager.backend = b
		report, err := s.manager.Capabilities()
		if err != nil {
			t.Fatal(err)
		}
		if report.Features.SessionArtifacts != enabled || (report.Limits.SessionArtifactCount == 2) != enabled || (report.Limits.SessionArtifactReadBytes == 524288) != enabled {
			t.Fatal("artifact capability mismatch", report)
		}
	}
	s.manager.manifest.Protocol = "osv-sandbox-artifacts/v6"
	s.manager.backend = s.backend
	report, _ := s.manager.Capabilities()
	if report.Features.SessionArtifacts {
		t.Fatal("old template advertised artifacts")
	}
}

func TestSessionArtifactLauncherRejectsWrongTenantAndPeerUID(t *testing.T) {
	s := artifactTestSession(t, func(c net.Conn, r linuxArtifactRequest) {
		_, _ = c.Write(artifactTestWire(r, artifactTestFrames(r, "directory", nil, nil)))
	})
	if err := s.manager.registerOwnedSession(s, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	owner := &tenantRuntime{policy: TenantPolicy{ID: "tenant-a"}}
	h := portLauncherFixture(t, s, owner, &portMemoryAudit{}, os.Geteuid())
	h.tenant = "tenant-b"
	if _, err := h.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"}); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("wrong owner accepted", err)
	}
	h = portLauncherFixture(t, s, owner, &portMemoryAudit{}, os.Geteuid()+1)
	if _, err := h.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"}); err == nil {
		t.Fatal("wrong peer UID accepted")
	}
}

func TestSessionArtifactCancelledCacheReadKeepsOwnerConnection(t *testing.T) {
	s, h, _, _, audit, _ := artifactHTTPSetup(t)
	info, err := h.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	// Holding the cache lock stalls only this read, independently of VM work.
	s.artifacts.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.ReadArtifact(ctx, info.ID, SessionArtifactReadRequest{Length: 512}); done <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		audit.mu.Lock()
		admitted := false
		for _, event := range audit.events {
			if event.Event == "session.artifact.rpc.read.admitted" {
				admitted = true
			}
		}
		audit.mu.Unlock()
		if admitted {
			break
		}
		if time.Now().After(deadline) {
			s.artifacts.mu.Unlock()
			cancel()
			t.Fatal("cache read was not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Error("cancelled client did not return")
	}
	s.artifacts.mu.Unlock()
	if h.closed.Load() || s.closed.Load() {
		t.Fatal("cache read cancellation destroyed VM owner")
	}
	if _, err := h.ReadArtifact(context.Background(), info.ID, SessionArtifactReadRequest{Length: 512}); err != nil {
		t.Fatal("owner did not survive cancelled read", err)
	}
}

type artifactFailWriter struct{ header http.Header }

func (w *artifactFailWriter) Header() http.Header     { return w.header }
func (*artifactFailWriter) WriteHeader(int)           {}
func (*artifactFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSessionArtifactFailedHTTPCreateReplyDeletesCache(t *testing.T) {
	s, _, handler, path, _, _ := artifactHTTPSetup(t)
	request := httptest.NewRequest("POST", path+"/artifacts", strings.NewReader(`{"path":"/workspace"}`))
	request.Header.Set("Authorization", "Bearer token-a")
	handler.ServeHTTP(&artifactFailWriter{header: make(http.Header)}, request)
	s.artifacts.mu.Lock()
	remaining := len(s.artifacts.items)
	s.artifacts.mu.Unlock()
	if remaining != 0 || s.closed.Load() {
		t.Fatal("failed reply leaked cache or destroyed healthy owner", remaining)
	}
}

func TestSessionArtifactRPCRejectsReboundChunks(t *testing.T) {
	request := SessionArtifactReadRequest{Length: 1}
	valid := SessionArtifactChunk{ID: strings.Repeat("a", 24), SessionID: strings.Repeat("b", 24), TotalSize: 2048, DataBase64: "AA==", DataSHA256: artifactTestSHA([]byte{0}), ArchiveSHA256: strings.Repeat("c", 64)}
	if !valid.valid(valid.SessionID, valid.ID, request) {
		t.Fatal("bad fixture")
	}
	for _, change := range []func(*SessionArtifactChunk){func(v *SessionArtifactChunk) { v.Offset = 1 }, func(v *SessionArtifactChunk) { v.DataBase64 = "AQ==" }, func(v *SessionArtifactChunk) { v.EOF = true }, func(v *SessionArtifactChunk) { v.TotalSize = 2049 }} {
		copy := valid
		change(&copy)
		if copy.valid(valid.SessionID, valid.ID, request) {
			t.Fatal("invalid chunk accepted", copy)
		}
	}
}

// Exercise strict RPC shape checks before dispatch, separately from HTTP JSON.
func TestSessionArtifactRPCShapeRejectsMixedOperations(t *testing.T) {
	base := launcherArtifactRequest{Protocol: launcherArtifactProtocol, Operation: "read", Tenant: "tenant-a", SessionID: strings.Repeat("a", 24), Nonce: strings.Repeat("b", 64), ArtifactID: strings.Repeat("c", 24), Read: &SessionArtifactReadRequest{Length: 1}}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	base.Create = &SessionArtifactCreateRequest{Path: "/workspace"}
	if base.validate() == nil {
		t.Fatal("mixed artifact operation accepted")
	}
}
