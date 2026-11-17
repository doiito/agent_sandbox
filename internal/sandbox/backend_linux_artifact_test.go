package sandbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func artifactTransportFixture(t *testing.T, prepared bool, serve func(net.Conn, linuxArtifactRequest)) (FirecrackerLinuxBackend, string) {
	t.Helper()
	b := FirecrackerLinuxBackend{Path: "/bin/firecracker", Pristine: prepared, WorkspaceArtifacts: true, Guest: LinuxGuestConfig{VsockPort: 5000}}
	work, err := os.MkdirTemp("/tmp", "av-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	socket, err := b.vsockPath(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				connect, err := reader.ReadString('\n')
				if err != nil || connect != "CONNECT 5005\n" {
					t.Error("unexpected artifact transport", connect, err)
					return
				}
				if _, err := io.WriteString(c, "OK 5005\n"); err != nil {
					return
				}
				line, err := reader.ReadBytes('\n')
				if err != nil {
					return
				}
				var request linuxArtifactRequest
				if decodeLauncherFrame(line, &request) != nil || request.Protocol != linuxArtifactProtocol {
					t.Error("invalid artifact request")
					return
				}
				serve(c, request)
			}()
		}
	}()
	return b, work
}

func artifactTestSession(t *testing.T, serve func(net.Conn, linuxArtifactRequest)) *Session {
	t.Helper()
	b, work := artifactTransportFixture(t, false, serve)
	config := capacityConfig()
	config.Jailer = nil
	m := &Manager{config: config, backend: b, capacity: newResourceLedger(config), manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v8", Backend: "firecracker-linux", AgentFeatures: []string{"workspace-artifacts-v1"}, digestSHA256: strings.Repeat("a", 64)}}
	physical, active, err := m.capacity.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	vm := &vmInstance{manager: m, ctx: ctx, cancel: cancel, physical: physical, state: vmActive}
	m.instances = map[*vmInstance]struct{}{vm: {}}
	s := &Session{manager: m, backend: b, workdir: work, ctx: ctx, cancel: cancel, active: active, instance: vm, info: SessionInfo{ID: artifactTestRequest().SessionID}}
	t.Cleanup(func() { cancel(); _ = s.Close() })
	return s
}

func TestSessionArtifactBackendPreparedAndLegacyTransport(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		b, work := artifactTransportFixture(t, prepared, func(c net.Conn, r linuxArtifactRequest) {
			_, _ = c.Write(artifactTestWire(r, artifactTestFrames(r, "directory", nil, nil)))
		})
		request := artifactTestRequest()
		if prepared {
			binding, err := newLinuxGuestBinding(request.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			request.Binding = &binding
		}
		blob, err := b.exportSessionArtifact(context.Background(), request, work)
		if err != nil || !blob.info.valid() {
			t.Fatal(blob, err)
		}
		_ = blob.Close()
		b.WorkspaceArtifacts = false
		if _, err := b.exportSessionArtifact(context.Background(), request, "/missing"); !errors.Is(err, ErrArtifactsUnsupported) {
			t.Fatal("old template reached guest", err)
		}
	}
}

func TestSessionArtifactSessionAuditPublicationQuotaAndClose(t *testing.T) {
	s := artifactTestSession(t, func(c net.Conn, r linuxArtifactRequest) {
		_, _ = c.Write(artifactTestWire(r, artifactTestFrames(r, "directory", nil, nil)))
	})
	var states []string
	s.artifactAudit = func(id, state string, info *SessionArtifactInfo, _ time.Duration) error {
		states = append(states, state)
		if state == "created" {
			if info == nil {
				t.Error("missing artifact audit size")
			}
			if _, err := s.ReadArtifact(context.Background(), id, SessionArtifactReadRequest{Length: 1}); !errors.Is(err, ErrArtifactNotFound) {
				t.Error("artifact visible before trusted audit", err)
			}
		}
		return nil
	}
	first, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"}); !errors.Is(err, ErrArtifactLimit) {
		t.Fatal("missing session quota", err)
	}
	if err := s.DeleteArtifact(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadArtifact(context.Background(), second.ID, SessionArtifactReadRequest{Length: 512}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(states, ",") != "admitted,created,admitted,created,deleted" {
		t.Fatal(states)
	}
	s.cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadArtifact(context.Background(), second.ID, SessionArtifactReadRequest{Length: 1}); !errors.Is(err, ErrSessionClosed) {
		t.Fatal(err)
	}
	if s.manager.capacity.snapshot().Instances != 0 {
		t.Fatal("closed artifact session kept VM capacity")
	}
}

func TestSessionArtifactFailureDoesNotPublishAndInvalidProtocolClosesOwner(t *testing.T) {
	for _, code := range []string{"conflict", "denied", "invalid_protocol"} {
		t.Run(code, func(t *testing.T) {
			s := artifactTestSession(t, func(c net.Conn, r linuxArtifactRequest) {
				if code == "invalid_protocol" {
					r.Nonce = strings.Repeat("e", 64)
				}
				_, _ = c.Write(artifactTestWire(r, []linuxArtifactFrame{{Kind: "end", Code: code}}))
			})
			_, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"})
			if err == nil || len(s.artifacts.items) != 0 || s.closed.Load() != (code == "invalid_protocol") {
				t.Fatal("incorrect failed transfer ownership", code, err)
			}
		})
	}
	for _, failAt := range []string{"admitted", "created"} {
		t.Run("audit_"+failAt, func(t *testing.T) {
			s := artifactTestSession(t, func(c net.Conn, r linuxArtifactRequest) {
				_, _ = c.Write(artifactTestWire(r, artifactTestFrames(r, "directory", nil, nil)))
			})
			s.artifactAudit = func(_, state string, _ *SessionArtifactInfo, _ time.Duration) error {
				if state == failAt {
					return errors.New("audit fixture failure")
				}
				return nil
			}
			if _, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"}); !errors.Is(err, ErrUnavailable) || !s.closed.Load() || len(s.artifacts.items) != 0 {
				t.Fatal("audit failure published artifact", err)
			}
		})
	}
}

// Keep the source-bound fixture response encodable within the existing UDS
// envelope even at its largest public read size.
func TestSessionArtifactMaximumChunkFitsLauncherFrame(t *testing.T) {
	data := base64.StdEncoding.EncodeToString(make([]byte, sessionArtifactReadBytes))
	chunk := SessionArtifactChunk{DataBase64: data}
	encoded, err := json.Marshal(chunk)
	if err != nil || len(encoded) > 1<<20 {
		t.Fatal(err, len(encoded))
	}
}

func TestSessionArtifactCloseDuringTransferCancelsUnpublishedExport(t *testing.T) {
	entered := make(chan struct{})
	s := artifactTestSession(t, func(c net.Conn, _ linuxArtifactRequest) { close(entered); _, _ = io.Copy(io.Discard, c) })
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateArtifact(context.Background(), SessionArtifactCreateRequest{Path: "/workspace"})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("transfer was not admitted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed transfer published artifact")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session close did not cancel export")
	}
	if len(s.artifacts.items) != 0 || s.manager.capacity.snapshot().Instances != 0 {
		t.Fatal("cancelled export retained cache or VM capacity")
	}
	names, err := os.ReadDir(s.workdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasPrefix(name.Name(), ".artifact-") {
			t.Fatal("cancelled export retained named spool")
		}
	}
}
