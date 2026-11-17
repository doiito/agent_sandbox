package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func directoryWatchSession(t *testing.T, serve func(net.Conn, *bufio.Reader, linuxWatchRequest)) *Session {
	t.Helper()
	backend, wire, work := watchTransportFixture(t, false, serve)
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{config: Config{Backend: "firecracker-linux"}, backend: backend, manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v4", Backend: "firecracker-linux", AgentFeatures: []string{"workspace-watch-v1"}}}
	s := &Session{manager: m, backend: backend, workdir: work, ctx: ctx, cancel: cancel, instance: &vmInstance{ctx: ctx}, info: SessionInfo{ID: wire.SessionID, State: "running", CreatedAt: time.Now().UTC()}, hardDeadline: time.Now().Add(time.Minute)}
	t.Cleanup(func() {
		cancel()
		if err := s.closeFileWatches(); err != nil {
			t.Error(err)
		}
		s.unregisterOwnedSession()
	})
	return s
}

func TestDirectoryWatchJournalAcknowledgesAndCopiesEntries(t *testing.T) {
	id := strings.Repeat("b", 24)
	r := &watchRecord{info: SessionWatchInfo{ID: id, State: "watching"}, cancel: func() {}, done: make(chan struct{})}
	for n := 1; n <= 130; n++ {
		event := SessionWatchEvent{Sequence: n, Name: "file", Type: "create", Entry: &SessionFileInfo{Metadata: map[string]string{"x": "original"}}}
		data, _ := json.Marshal(event)
		r.events = append(r.events, event)
		r.bytes += len(data)
		r.last = n
	}
	s := &Session{watches: map[string]*watchRecord{id: r}}
	first, err := s.PollFileWatch(id, 0)
	if err != nil || len(first.Events) != 64 || first.NextSequence != 64 {
		t.Fatal(first, err)
	}
	first.Events[0].Entry.Metadata["x"] = "changed"
	retry, _ := s.PollFileWatch(id, 0)
	if retry.Events[0].Entry.Metadata["x"] != "original" {
		t.Fatal("page aliases journal")
	}
	for _, cursor := range []int{64, 128, 130} {
		page, err := s.PollFileWatch(id, cursor)
		if err != nil || page.NextSequence != min(cursor+64, 130) {
			t.Fatal(page, err)
		}
	}
	if len(r.events) != 0 || r.bytes != 0 {
		t.Fatal("acknowledged queue retained memory", r.bytes)
	}
	for _, invalid := range []int{0, 129, 131, -1} {
		if _, err := s.PollFileWatch(id, invalid); !errors.Is(err, ErrWatchCursor) {
			t.Fatal("invalid cursor accepted", invalid, err)
		}
	}
	r.finish("closed", "")
	page, _ := s.PollFileWatch(id, 130)
	if !page.Complete {
		t.Fatal("terminal queue did not finish")
	}
}

func TestDirectoryWatchSessionOverflowQuotaAndCancellation(t *testing.T) {
	for _, mode := range []string{"overflow", "cancel", "quota", "history"} {
		t.Run(mode, func(t *testing.T) {
			peerClosed := make(chan struct{})
			s := directoryWatchSession(t, func(c net.Conn, r *bufio.Reader, request linuxWatchRequest) {
				defer close(peerClosed)
				sendWatchFrame(c, watchFrame(request, "ready", nil))
				if mode == "overflow" {
					for n := 1; n <= sessionWatchEventLimit+1; n++ {
						sendWatchFrame(c, watchFrame(request, "event", &SessionWatchEvent{Sequence: n, Name: "live", Type: "write"}))
					}
				}
				_, _ = io.Copy(io.Discard, r)
			})
			if mode == "quota" || mode == "history" {
				s.watches = map[string]*watchRecord{}
				count := sessionWatchActiveLimit
				if mode == "history" {
					count = sessionWatchHistoryLimit
				}
				for n := 0; n < count; n++ {
					id := fmt.Sprintf("%024x", n)
					r := &watchRecord{info: SessionWatchInfo{ID: id, State: "watching"}, cancel: func() {}, done: make(chan struct{})}
					if mode == "history" {
						r.finish("closed", "")
					}
					s.watches[id] = r
					s.watchOrder = append(s.watchOrder, id)
				}
			}
			info, err := s.StartFileWatch(context.Background(), SessionWatchRequest{Path: "/workspace"})
			if mode == "quota" {
				if !errors.Is(err, ErrBusy) {
					t.Fatal("watch quota bypassed", err)
				}
				for _, r := range s.watches {
					r.finish("closed", "")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "overflow" {
				record, _ := s.fileWatch(info.ID)
				select {
				case <-record.done:
				case <-time.After(2 * time.Second):
					t.Fatal("overflow failed to stop transport")
				}
				page, _ := s.PollFileWatch(info.ID, 0)
				if page.Info.State != "failed" || page.Info.ErrorCode != "overflow" || record.last != 256 {
					t.Fatal(page.Info, record.last)
				}
			} else {
				if mode == "history" && len(s.ListFileWatches()) != sessionWatchHistoryLimit {
					t.Fatal("closed watch history was not pruned")
				}
				if active, err := s.StopFileWatch(info.ID); err != nil || !active {
					t.Fatal(active, err)
				}
				if active, err := s.StopFileWatch(info.ID); err != nil || active {
					t.Fatal("stop not idempotent", active, err)
				}
			}
			select {
			case <-peerClosed:
			case <-time.After(time.Second):
				t.Fatal("watch transport leaked")
			}
		})
	}
}

type watchHTTPFixture struct {
	fakeSessionRunner
	socket  string
	session *Session
}

func (f *watchHTTPFixture) CreateSession(ctx context.Context, request SessionCreateRequest, tenant string) (*LauncherSessionClient, SessionInfo, error) {
	h, info, err := f.fakeSessionRunner.CreateSession(ctx, request, tenant)
	if err != nil {
		return h, info, err
	}
	h.socketPath = f.socket
	f.session.lifecycleMu.Lock()
	f.session.info = info
	f.session.lifecycleMu.Unlock()
	if err = f.session.manager.registerOwnedSession(f.session, tenant); err != nil {
		_ = h.Close()
		return nil, SessionInfo{}, err
	}
	return h, info, nil
}

func TestDirectoryWatchHTTPIndependentControlAndTenantOwnership(t *testing.T) {
	s := directoryWatchSession(t, func(c net.Conn, r *bufio.Reader, request linuxWatchRequest) {
		sendWatchFrame(c, watchFrame(request, "ready", nil))
		sendWatchFrame(c, watchFrame(request, "event", &SessionWatchEvent{Sequence: 1, Name: "during-run", Type: "create"}))
		_, _ = io.Copy(io.Discard, r)
	})
	dir, err := os.MkdirTemp("/tmp", "watch-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "launcher.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				frame, err := bufio.NewReader(conn).ReadBytes('\n')
				if err == nil {
					handleLauncherWatchConnection(context.Background(), conn, frame, s.manager, LauncherOptions{}, syscall.Ucred{})
				}
			}()
		}
	}()
	fixture := &watchHTTPFixture{socket: socket, session: s}
	fixture.handles = make(chan *LauncherSessionClient, 1)
	handler := NewAPIWithAuthenticator(fixture, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	handle := <-fixture.handles
	defer handle.Close()
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+s.info.ID, "")
	handle.mu.Lock()
	s.opMu.Lock() // Both synchronous command control paths are occupied.
	defer handle.mu.Unlock()
	defer s.opMu.Unlock()
	if info, err := handle.Info(context.Background()); err != nil || info.ID != s.info.ID {
		t.Fatal("independent session identity blocked", info, err)
	}
	base := "/v2/sessions/" + s.info.ID + "/watches"
	started := sessionHTTPCall(handler, "token-a", "POST", base, `{"path":"/workspace"}`)
	var info SessionWatchInfo
	if started.Code != 201 || json.Unmarshal(started.Body.Bytes(), &info) != nil {
		t.Fatal(started.Code, started.Body.String())
	}
	watchPath := base + "/" + info.ID
	for _, request := range [][2]string{{"POST", base}, {"GET", base}, {"GET", watchPath}, {"DELETE", watchPath}} {
		denied := sessionHTTPCall(handler, "token-b", request[0], request[1], `{"path":"/workspace"}`)
		if denied.Code != 404 {
			t.Fatal("cross tenant watcher exposed", denied.Code)
		}
	}
	other := &LauncherSessionClient{socketPath: socket, tenant: "tenant-b", id: s.info.ID}
	if _, err = other.ListFileWatches(context.Background()); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("launcher owner lookup bypassed", err)
	}
	waitWarm(t, func() bool { page, _ := s.PollFileWatch(info.ID, 0); return len(page.Events) == 1 })
	polled := sessionHTTPCall(handler, "token-a", http.MethodGet, watchPath, "")
	if polled.Code != 200 || !strings.Contains(polled.Body.String(), "during-run") {
		t.Fatal(polled.Code, polled.Body.String())
	}
	for _, cursor := range []string{"-1", "2147483648", "bad"} {
		if got := sessionHTTPCall(handler, "token-a", "GET", watchPath+"?after="+cursor, ""); got.Code != 400 {
			t.Fatal("bad cursor accepted", cursor, got.Code)
		}
	}
	stopped := sessionHTTPCall(handler, "token-a", "DELETE", watchPath, "")
	if stopped.Code != 200 || !strings.Contains(stopped.Body.String(), `"stopped":true`) {
		t.Fatal(stopped.Code, stopped.Body.String())
	}
	listed := sessionHTTPCall(handler, "token-a", "GET", base, "")
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), info.ID) {
		t.Fatal(listed.Code, listed.Body.String())
	}
	if _, err = s.manager.ownedSession(s.info.ID, "tenant-a"); err != nil {
		t.Fatal("watch stop destroyed session", err)
	}
	s.unregisterOwnedSession()
	if _, err = s.manager.ownedSession(s.info.ID, "tenant-a"); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("registry retained closed owner", err)
	}
}
