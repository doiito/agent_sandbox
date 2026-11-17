package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func portTestSession(t *testing.T, maximum int, serve func(net.Conn, *bufio.Reader, linuxPortRequest)) (*Session, *tenantRuntime) {
	t.Helper()
	backend, wire, work := portTransportFixture(t, false, serve)
	config := capacityConfig()
	config.Jailer = nil
	m := &Manager{config: config, backend: backend, capacity: newResourceLedger(config), manifest: &SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v6", Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}, digestSHA256: strings.Repeat("a", 64)}}
	physical, active, err := m.capacity.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	vm := &vmInstance{manager: m, ctx: ctx, cancel: cancel, physical: physical, state: vmActive}
	m.instances = map[*vmInstance]struct{}{vm: {}}
	s := &Session{manager: m, backend: backend, ctx: ctx, cancel: cancel, instance: vm, active: active, workdir: work,
		info: SessionInfo{ID: wire.SessionID, State: "running", Backend: config.Backend, ArtifactManifestSHA256: m.manifest.digestSHA256}, hardDeadline: time.Now().Add(time.Minute)}
	if err := m.registerOwnedSession(s, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	s.opMu.Lock() // port opens and controls must not wait behind foreground Run
	t.Cleanup(func() { cancel(); _ = s.Close(); s.opMu.Unlock() })
	owner := &tenantRuntime{policy: TenantPolicy{ID: "tenant-a", Ports: &PortPolicy{AllowedPorts: []PortRange{{1024, 65535}}, MaxConcurrent: maximum}}, portSem: make(chan struct{}, maximum)}
	return s, owner
}

func portOpenRequest(n int) SessionPortRequest {
	return SessionPortRequest{ID: fmt.Sprintf("%024x", n), Port: 8080, Limits: SessionPortLimits{MaxBytes: portByteLimit, TimeoutMS: 3000, IdleTimeoutMS: 2000}}
}

func sendPortControlInfo(c net.Conn, r linuxPortRequest, status string) {
	reply := testPortReply(r)
	reply.Response.Status = status
	if status == "cancelled" {
		code := "cancelled"
		reply.Response.Error = &code
	}
	_ = writePortBytes(c, testPortJSON(reply))
}

func TestSessionPortNormalFinishReturnsCapacityAndPinsIdentity(t *testing.T) {
	var opens atomic.Int32
	s, owner := portTestSession(t, 1, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
		opens.Add(1)
		if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
			return
		}
		kind, data, err := readTestPortFrame(reader)
		if err != nil || kind != portDataFrame || string(data) != "data" {
			t.Error(kind, string(data), err)
			return
		}
		if kind, _, err = readTestPortFrame(reader); err != nil || kind != portEOFFrame {
			t.Error(kind, err)
			return
		}
		body, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed", SentBytes: 4, ReceivedBytes: 4})
		packet := append(testPortFrame(portDataFrame, []byte("data")), testPortFrame(portEOFFrame, nil)...)
		packet = append(packet, testPortFrame(portFinishedFrame, body)...)
		_ = writePortBytes(c, packet)
	})
	r := portOpenRequest(1)
	p, err := s.openSessionPort(context.Background(), r, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(owner.portSem) != 1 {
		t.Fatal("missing tenant reservation")
	}
	if _, err = p.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err = p.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		f, err := p.Next()
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 && (f.Info == nil || f.Info.Status != "completed") {
			t.Fatal(f)
		}
	}
	if len(owner.portSem) != 0 {
		t.Fatal("terminal proof retained reservation")
	}
	p.Close()
	_, err = s.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "conflict")
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "info")
	if err != nil || info.SentBytes != 4 || info.Status != "completed" {
		t.Fatal(info, err)
	}
	if opens.Load() != 1 {
		t.Fatal("duplicate open replayed")
	}
}

func TestSessionPortCancelBeforeOpenAndJournalCannotBeReplayed(t *testing.T) {
	s, owner := portTestSession(t, 1, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("local tombstone contacted guest") })
	r := portOpenRequest(1)
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel")
	if err != nil || info.Status != "cancelled" {
		t.Fatal(info, err)
	}
	*info.Error = "mutated"
	info, err = s.sessionPortControl(context.Background(), r.ID, r.Port, "info")
	if err != nil || *info.Error != "cancelled" {
		t.Fatal(info, err)
	}
	_, err = s.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "cancelled")
	_, err = s.sessionPortControl(context.Background(), r.ID, r.Port+1, "cancel")
	portErrorIs(t, err, "invalid_binding")
	for i := 2; i <= sessionPortHistoryLimit; i++ {
		r = portOpenRequest(i)
		if _, err = s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel"); err != nil {
			t.Fatal(err)
		}
	}
	r = portOpenRequest(257)
	_, err = s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel")
	portErrorIs(t, err, "quota")
	r = portOpenRequest(1)
	if _, err = s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel"); err != nil {
		t.Fatal("known cancel blocked at quota", err)
	}
	if len(owner.portSem) != 0 {
		t.Fatal("tombstone consumed tenant capacity")
	}
}

func TestSessionPortSaturatedQuotaStillAllowsCancelAndWaitsForTerminalProof(t *testing.T) {
	var terminal atomic.Bool
	s, owner := portTestSession(t, 16, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
		if r.Operation == "open" {
			if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
				return
			}
			_, _ = io.Copy(io.Discard, reader)
			return
		}
		status := "cancelling"
		if terminal.Load() {
			status = "cancelled"
		}
		sendPortControlInfo(c, r, status)
	})
	for i := 1; i <= 8; i++ {
		if _, err := s.openSessionPort(context.Background(), portOpenRequest(i), owner); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.openSessionPort(context.Background(), portOpenRequest(9), owner)
	portErrorIs(t, err, "quota")
	r := portOpenRequest(1)
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel")
	if err != nil || info.Status != "cancelling" {
		t.Fatal(info, err)
	}
	if len(owner.portSem) != 8 {
		t.Fatal("cancel ACK released unconfirmed capacity")
	}
	terminal.Store(true)
	waitWarm(t, func() bool { return len(owner.portSem) == 7 })
	if _, err := s.openSessionPort(context.Background(), portOpenRequest(9), owner); err != nil {
		t.Fatal("slot not reusable", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(owner.portSem) != 0 || s.manager.Capacity().Active != 0 {
		t.Fatal("owner destroy retained capacity")
	}
}

func TestSessionPortTenantQuotaIsSharedAcrossSessionsAndPolicyDenialsDoNotDial(t *testing.T) {
	serve := func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
		if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
			return
		}
		_, _ = io.Copy(io.Discard, reader)
	}
	s, owner := portTestSession(t, 1, serve)
	other, _ := portTestSession(t, 1, serve)
	r := portOpenRequest(1)
	if _, err := s.openSessionPort(context.Background(), r, owner); err != nil {
		t.Fatal(err)
	}
	_, err := other.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "quota")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	r.Port = 3128
	_, err = other.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "denied")
	r.Port = 80
	_, err = other.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "denied")
	r.Port = 8080
	wrong := &tenantRuntime{policy: TenantPolicy{ID: "tenant-b"}}
	if _, err = other.openSessionPort(context.Background(), r, wrong); !errors.Is(err, ErrSessionClosed) {
		t.Fatal(err)
	}
	if _, err = other.openSessionPort(context.Background(), r, owner); err != nil {
		t.Fatal("global tenant slot not restored", err)
	}
}

func TestSessionPortConcurrentCancelDuringLostOpenAckPreventsLateReplay(t *testing.T) {
	seen, release := make(chan struct{}), make(chan struct{})
	var opens atomic.Int32
	s, owner := portTestSession(t, 1, func(c net.Conn, _ *bufio.Reader, r linuxPortRequest) {
		if r.Operation == "open" {
			opens.Add(1)
			close(seen)
			<-release
			_ = writePortBytes(c, testPortJSON(testPortReply(r)))
			return
		}
		sendPortControlInfo(c, r, "cancelled")
	})
	defer close(release)
	r := portOpenRequest(1)
	done := make(chan error, 1)
	go func() {
		p, err := s.openSessionPort(context.Background(), r, owner)
		if p != nil {
			p.Close()
		}
		done <- err
	}()
	<-seen
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel")
	if err != nil || info.Status != "cancelled" {
		t.Fatal(info, err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled open succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("open ignored cancellation")
	}
	waitWarm(t, func() bool { return len(owner.portSem) == 0 })
	_, err = s.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "cancelled")
	if opens.Load() != 1 {
		t.Fatal("late duplicate replayed")
	}
}

func TestSessionPortUnknownDeliveryRetainsSlotUntilIndependentCleanupProof(t *testing.T) {
	s, owner := portTestSession(t, 1, func(c net.Conn, _ *bufio.Reader, r linuxPortRequest) {
		if r.Operation == "open" {
			return
		} // consumed request, lost ACK
		sendPortControlInfo(c, r, "cancelled")
	})
	r := portOpenRequest(1)
	_, err := s.openSessionPort(context.Background(), r, owner)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	waitWarm(t, func() bool { return len(owner.portSem) == 0 })
	if s.closed.Load() {
		t.Fatal("confirmed cleanup destroyed usable owner")
	}
	_, err = s.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "conflict")
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "info")
	if err != nil || info.Status != "cancelled" {
		t.Fatal(info, err)
	}
}

func TestSessionPortUnconfirmedCleanupDestroysOwnerAndDestroyFailureRetainsSlots(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "destroyed", true: "cleanup_failed"}[fail], func(t *testing.T) {
			s, owner := portTestSession(t, 1, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
				if r.Operation == "open" {
					if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
						return
					}
					_, _ = io.Copy(io.Discard, reader)
					return
				}
				_, _ = io.Copy(io.Discard, reader) // no control ACK; absolute cleanup deadline applies
			})
			if fail {
				s.manager.config.Jailer = &JailerConfig{ParentCgroup: "../invalid-cgroup"}
				s.instance.workdir = t.TempDir()
			}
			p, err := s.openSessionPort(context.Background(), portOpenRequest(1), owner)
			if err != nil {
				t.Fatal(err)
			}
			p.Close()
			if len(owner.portSem) != 1 {
				t.Fatal("uncertain cleanup released slot")
			}
			waitWarm(t, func() bool { return s.closed.Load() })
			err = s.Close() // waits for the actual synchronous Destroy outcome
			if fail {
				if err == nil || len(owner.portSem) != 1 || !s.manager.cleanupFailed.Load() || s.manager.Capacity().Active != 1 {
					t.Fatal("failed cleanup released capacity", err, len(owner.portSem))
				}
			} else if err != nil || len(owner.portSem) != 0 || s.manager.Capacity().Active != 0 {
				t.Fatal("successful destroy retained capacity", err)
			}
		})
	}
}

func TestSessionPortExpiredDeadAndUnsignedOwnerCannotAdmit(t *testing.T) {
	for _, mode := range []string{"lease", "vm", "digest", "backend_flag", "old_profile", "session_digest", "session_backend"} {
		t.Run(mode, func(t *testing.T) {
			s, owner := portTestSession(t, 1, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("unavailable owner dialed") })
			want := ErrPortUnsupported
			switch mode {
			case "lease":
				s.lifecycleMu.Lock()
				s.leaseDeadline = time.Now().Add(-time.Second)
				s.lifecycleMu.Unlock()
				want = ErrSessionClosed
			case "vm":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				s.instance.ctx = ctx
				want = ErrSessionClosed
			case "digest":
				s.manager.manifest.digestSHA256 = ""
			case "backend_flag":
				s.backend.PortForward = false
			case "old_profile":
				s.manager.manifest.Protocol = "osv-sandbox-artifacts/v5"
			case "session_digest":
				s.info.ArtifactManifestSHA256 = strings.Repeat("b", 64)
			case "session_backend":
				s.info.Backend = "firecracker-osv"
			}
			if _, err := s.openSessionPort(context.Background(), portOpenRequest(1), owner); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if len(owner.portSem) != 0 {
				t.Fatal("unavailable owner reserved capacity")
			}
		})
	}
}

func TestSessionPortTenantTemplateRestrictionBlocksOpenButAllowsLocalCleanup(t *testing.T) {
	s, owner := portTestSession(t, 1, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("denied template dialed") })
	owner.policy.AllowedTemplates = &[]TemplateSelector{}
	r := portOpenRequest(1)
	_, err := s.openSessionPort(context.Background(), r, owner)
	portErrorIs(t, err, "denied")
	info, err := s.sessionPortControl(context.Background(), r.ID, r.Port, "cancel")
	if err != nil || info.Status != "cancelled" || len(owner.portSem) != 0 {
		t.Fatal(info, err)
	}
}
