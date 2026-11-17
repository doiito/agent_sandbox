package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type portMemoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (a *portMemoryAudit) Append(e AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("injected audit failure")
	}
	a.events = append(a.events, e)
	return nil
}
func (a *portMemoryAudit) Err() error { return nil }

func portLauncherFixture(t *testing.T, s *Session, owner *tenantRuntime, audit AuditRecorder, uid int) *LauncherSessionClient {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "launcher.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	options := LauncherOptions{AllowedUID: uid, Audit: audit, PortAuth: &Authenticator{tenants: map[[32]byte]*tenantRuntime{{}: owner}}}
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				handleLauncherConnection(ctx, conn, s.manager, options, slog.New(slog.NewTextHandler(io.Discard, nil)))
			}()
		}
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close(); <-accepted; workers.Wait() })
	return &LauncherSessionClient{id: s.info.ID, tenant: owner.policy.ID, socketPath: path}
}

func portEchoGuest(t *testing.T, c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
	t.Helper()
	if r.Operation != "open" {
		sendPortControlInfo(c, r, "cancelled")
		return
	}
	if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
		return
	}
	var data []byte
	for {
		kind, part, err := readTestPortFrame(reader)
		if err != nil {
			return
		}
		if kind == portEOFFrame {
			break
		}
		if kind != portDataFrame {
			t.Error("bad data frame")
			return
		}
		data = append(data, part...)
	}
	packet := testPortFrame(portEOFFrame, nil)
	if len(data) > 0 {
		packet = append(testPortFrame(portDataFrame, data), packet...)
	}
	body, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed", SentBytes: uint64(len(data)), ReceivedBytes: uint64(len(data))})
	packet = append(packet, testPortFrame(portFinishedFrame, body)...)
	_ = writePortBytes(c, packet)
}

func TestLauncherPortProductionDispatchBinaryHalfCloseAndTerminalAudit(t *testing.T) {
	s, owner := portTestSession(t, 2, func(c net.Conn, r *bufio.Reader, w linuxPortRequest) { portEchoGuest(t, c, r, w) })
	audit := &portMemoryAudit{}
	h := portLauncherFixture(t, s, owner, audit, os.Geteuid())
	h.mu.Lock()
	defer h.mu.Unlock() // independent of the owner connection's RPC lock
	r := portOpenRequest(1)
	start, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := h.OpenPort(start, context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	data := []byte("private-app-payload\x00\xff")
	if _, err := p.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for {
		f, err := p.Next()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f.Data...)
		if f.Info != nil {
			if f.Info.Status != "completed" {
				t.Fatal(f)
			}
			break
		}
	}
	if string(out) != string(data) {
		t.Fatal("binary payload lost")
	}
	info, err := h.PortControl(context.Background(), r.ID, r.Port, "info")
	if err != nil || info.Status != "completed" {
		t.Fatal(info, err)
	}
	waitWarm(t, func() bool { return len(owner.portSem) == 0 })
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var terminal bool
	for _, e := range audit.events {
		body, _ := json.Marshal(e)
		if strings.Contains(string(body), "private-app-payload") || strings.Contains(string(body), "nonce") {
			t.Fatal("application data or nonce logged")
		}
		if e.Event == "session.port.terminal" {
			terminal = true
			if e.ConnectionID != r.ID || e.Port != r.Port || e.SentBytes != uint64(len(data)) || e.ReceivedBytes != uint64(len(data)) {
				t.Fatal(e)
			}
		}
	}
	if !terminal {
		t.Fatal("missing terminal audit")
	}
}

func TestLauncherPortPreservesDataCoalescedWithFirstJSONLine(t *testing.T) {
	s, owner := portTestSession(t, 1, func(c net.Conn, r *bufio.Reader, w linuxPortRequest) { portEchoGuest(t, c, r, w) })
	h := portLauncherFixture(t, s, owner, nil, os.Geteuid())
	conn, err := net.Dial("unix", h.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	r := portOpenRequest(1)
	request := launcherPortRequest{Protocol: launcherPortProtocol, Tenant: h.tenant, SessionID: h.id, Nonce: strings.Repeat("d", 64), Operation: "open", ID: r.ID, Port: r.Port, Limits: &r.Limits}
	first, _ := json.Marshal(request)
	packet := append(first, '\n')
	packet = append(packet, testPortFrame(portDataFrame, []byte("coalesced"))...)
	packet = append(packet, testPortFrame(portEOFFrame, nil)...)
	if err := writePortBytes(conn, packet); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response launcherPortResponse
	if codeDecode(line, &response) != nil || response.Error != nil || response.Nonce != request.Nonce {
		t.Fatal(string(line))
	}
	kind, data, err := readTestPortFrame(reader)
	if err != nil || kind != portDataFrame || string(data) != "coalesced" {
		t.Fatal(kind, string(data), err)
	}
	if kind, _, err = readTestPortFrame(reader); err != nil || kind != portEOFFrame {
		t.Fatal(kind, err)
	}
	if kind, _, err = readTestPortFrame(reader); err != nil || kind != portFinishedFrame {
		t.Fatal(kind, err)
	}
}

func TestLauncherPortRejectsWrongPeerWrongTenantAndDisabledPolicyWithoutGuestDial(t *testing.T) {
	for _, mode := range []string{"peer", "tenant", "policy", "template", "closed"} {
		t.Run(mode, func(t *testing.T) {
			var dials atomic.Int32
			s, owner := portTestSession(t, 1, func(net.Conn, *bufio.Reader, linuxPortRequest) { dials.Add(1) })
			uid := os.Geteuid()
			if mode == "peer" {
				uid++
			}
			if mode == "policy" {
				owner.policy.Ports = nil
			}
			if mode == "template" {
				s.manager.manifest.Protocol = "osv-sandbox-artifacts/v5"
			}
			h := portLauncherFixture(t, s, owner, nil, uid)
			if mode == "tenant" {
				h.tenant = "tenant-b"
			}
			if mode == "closed" {
				h.closed.Store(true)
			}
			_, err := h.OpenPort(context.Background(), context.Background(), portOpenRequest(1))
			if err == nil {
				t.Fatal("unauthorized open succeeded")
			}
			if dials.Load() != 0 || len(owner.portSem) != 0 {
				t.Fatal("denied request consumed guest/capacity")
			}
		})
	}
}

func TestLauncherPortCancelIgnoresRevokedNewOpenPolicyAndOwnerCloseUnblocksStream(t *testing.T) {
	s, owner := portTestSession(t, 1, func(c net.Conn, r *bufio.Reader, w linuxPortRequest) {
		if w.Operation == "open" {
			if writePortBytes(c, testPortJSON(testPortReply(w))) != nil {
				return
			}
			_, _ = io.Copy(io.Discard, r)
			return
		}
		sendPortControlInfo(c, w, "cancelled")
	})
	h := portLauncherFixture(t, s, owner, nil, os.Geteuid())
	r := portOpenRequest(1)
	p, err := h.OpenPort(context.Background(), context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	h.tenant = "tenant-b"
	if _, err := h.PortControl(context.Background(), r.ID, r.Port, "cancel"); err == nil {
		t.Fatal("other tenant cancelled owner")
	}
	h.tenant = "tenant-a"
	// The same owned session remains cleanable through a root policy which
	// denies every new port. No mutation of an in-use immutable policy is needed.
	denied := &tenantRuntime{policy: TenantPolicy{ID: owner.policy.ID}}
	cleanupClient := portLauncherFixture(t, s, denied, nil, os.Geteuid())
	_, err = cleanupClient.OpenPort(context.Background(), context.Background(), portOpenRequest(99))
	portErrorIs(t, err, "denied")
	info, err := cleanupClient.PortControl(context.Background(), r.ID, r.Port, "cancel")
	if err != nil || info.Status != "cancelled" {
		t.Fatal(info, err)
	}
	waitWarm(t, func() bool { return len(owner.portSem) == 0 })
	// New open, then the original session owner ends; the port is no new owner.
	p2, err := h.OpenPort(context.Background(), context.Background(), portOpenRequest(2))
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	done := make(chan error, 1)
	go func() { _, err := p2.Next(); done <- err }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed owner stream succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("owner close retained port stream")
	}
	if len(owner.portSem) != 0 {
		t.Fatal("destroyed owner retained tenant slots")
	}
}

func TestLauncherPortAuditFailurePreventsGuestOpen(t *testing.T) {
	s, owner := portTestSession(t, 1, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("audit-denied open reached guest") })
	h := portLauncherFixture(t, s, owner, &portMemoryAudit{fail: true}, os.Geteuid())
	_, err := h.OpenPort(context.Background(), context.Background(), portOpenRequest(1))
	portErrorIs(t, err, "unavailable")
	if len(owner.portSem) != 0 {
		t.Fatal("audit failure reserved capacity")
	}
}

func TestLauncherPortServeLoadsSameAuthPolicyAndRequiresValidPolicyPath(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := portTestSession(t, 1, func(c net.Conn, r *bufio.Reader, w linuxPortRequest) { portEchoGuest(t, c, r, w) })
			dir, err := os.MkdirTemp("/tmp", "ls-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			options := LauncherOptions{AllowedUID: os.Geteuid(), SocketUID: os.Geteuid(), SocketGID: os.Getegid(), SocketMode: 0o600, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			path := filepath.Join(dir, "launcher.sock")
			listener, err := ListenLauncher(path, options)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if mode != "missing" {
				policy := TenantPolicy{ID: "tenant-a", TokenSHA256: strings.Repeat("a", 64), AllowedEntrypoints: []string{"*"}, RequestsPerSecond: 10, Burst: 10, MaxConcurrent: 1,
					Ports: &PortPolicy{AllowedPorts: []PortRange{{8080, 8080}}, MaxConcurrent: 1}}
				if mode == "invalid" {
					policy.Ports.MaxConcurrent = 0
				}
				body, _ := json.Marshal(AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []TenantPolicy{policy}})
				s.manager.config.AuthPolicyPath = filepath.Join(dir, "auth.json")
				if err := os.WriteFile(s.manager.config.AuthPolicyPath, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode != "valid" {
				if err := ServeLauncher(ctx, listener, s.manager, options); err == nil {
					t.Fatal("missing/invalid port policy accepted")
				}
				return
			}
			done := make(chan error, 1)
			go func() { done <- ServeLauncher(ctx, listener, s.manager, options) }()
			defer func() {
				_ = s.Close()
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(3 * time.Second):
					t.Error("launcher did not stop")
				}
			}()
			h := &LauncherSessionClient{id: s.info.ID, tenant: "tenant-a", socketPath: path}
			p, err := h.OpenPort(context.Background(), context.Background(), portOpenRequest(1))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if err = p.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			for {
				f, err := p.Next()
				if err != nil {
					t.Fatal(err)
				}
				if f.Info != nil {
					break
				}
			}
		})
	}
}
