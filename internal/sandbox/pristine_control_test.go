package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Real CONNECT and fc-agent frames over Unix sockets exercise the common
// transport. These tests do not claim to emulate a VMM or guest isolation.
type pristineControlFixture struct {
	backend    linuxPristineVMBackend
	workdir    string
	handshakes atomic.Int32
	requests   chan linuxJobRequest
	closed     chan struct{}
}

func newPristineControlFixture(t *testing.T, workdir string, serve func(net.Conn, linuxJobRequest)) *pristineControlFixture {
	t.Helper()
	if workdir == "" {
		var err error
		workdir, err = os.MkdirTemp("/tmp", "pc-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(workdir) })
	}
	f := &pristineControlFixture{backend: linuxPristineVMBackend{FirecrackerLinuxBackend{Path: "/bin/firecracker", Pristine: true,
		Guest: LinuxGuestConfig{VsockPort: 5000}}}, workdir: workdir, requests: make(chan linuxJobRequest, 64), closed: make(chan struct{}, 64)}
	path, err := f.backend.vsockPath(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// Helper-process workdirs can exceed sockaddr_un's length limit.
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), filepath.Base(path)))
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var active sync.Map
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			active.Store(conn, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { _ = conn.Close(); active.Delete(conn); f.closed <- struct{}{} }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				if line, err := reader.ReadString('\n'); err != nil || line != "CONNECT 5000\n" {
					return
				}
				f.handshakes.Add(1)
				if _, err := io.WriteString(conn, "OK 42\n"); err != nil {
					return
				}
				var request linuxJobRequest
				if json.NewDecoder(reader).Decode(&request) != nil {
					return
				}
				f.requests <- request
				if serve != nil {
					serve(conn, request)
					return
				}
				writePristineControlResult(conn, request)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepted // No further workers.Add can race with Wait.
		active.Range(func(conn, _ any) bool { _ = conn.(net.Conn).Close(); return true })
		workers.Wait()
		_ = directory.Close()
	})
	return f
}

func writePristineControlResult(conn net.Conn, request linuxJobRequest) {
	result := map[string]any{"protocol": linuxPristineProtocol, "job_id": request.JobID, "ok": true,
		"guest_state": "pristine", "pristine_revision": 2, "remaining_lifetime_ms": 600000, "proxy_revision": 1}
	if request.Prepare != nil {
		result["guest_state"], result["binding"], result["remaining_lifetime_ms"] = "prepared", request.Prepare.Binding, request.Prepare.TTLMS
	}
	data, _ := json.Marshal(result)
	_, _ = conn.Write(append(append([]byte(linuxResultPrefix), data...), '\n'))
}

func pristineControlTestVM(t *testing.T, workdir string) *vmInstance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	v := &vmInstance{ctx: ctx, cancel: cancel, workdir: workdir}
	t.Cleanup(func() { cancel(); v.closePristineControl() })
	return v
}

func pristineControlPreparation(t *testing.T) pristinePreparation {
	t.Helper()
	binding, err := newPristineBinding("0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	return pristinePreparation{Binding: binding, Mode: "session", TTLMS: 30000,
		InputFiles: []InputFile{{Path: "input", Data: []byte("binary\x00input")}}}
}

func awaitPristineControlClosed(t *testing.T, f *pristineControlFixture) {
	t.Helper()
	select {
	case <-f.closed:
	case <-time.After(time.Second):
		t.Fatal("control connection was not closed")
	}
}

func TestPristineControlHandshakeBeforePayloadAndSingleConsumption(t *testing.T) {
	f := newPristineControlFixture(t, "", nil)
	v := pristineControlTestVM(t, f.workdir)
	arm, cancelArm := context.WithCancel(context.Background())
	defer cancelArm()
	if err := v.armPristineControl(arm, f.backend.FirecrackerLinuxBackend); err != nil {
		t.Fatal(err)
	}
	cancelArm()
	if f.handshakes.Load() != 1 || len(f.requests) != 0 || v.idleControl.Load() == nil {
		t.Fatal("arming did not finish CONNECT without sending a tenant frame")
	}
	request := pristineControlPreparation(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.backend.prepareVMWithDial(ctx, request, v.workdir, v.takePristineControl); err != nil {
		t.Fatal(err)
	}
	got := <-f.requests
	if got.Protocol != linuxPristineProtocol || got.Operation != "prepare" || got.Prepare == nil ||
		got.Prepare.Binding != request.Binding.linux() || string(got.Prepare.InputFiles[0].Data) != "binary\x00input" {
		t.Fatal("preconnected prepare lost protocol, unique binding or input bytes")
	}
	if v.idleControl.Load() != nil || f.handshakes.Load() != 1 {
		t.Fatal("prepare retained a reusable connection or dialed a second one")
	}
	if err := f.backend.prepareVMWithDial(ctx, request, v.workdir, v.takePristineControl); !errors.Is(err, errPristinePrepareNotSent) {
		t.Fatal("a consumed connection allowed another preparation")
	}
	awaitPristineControlClosed(t, f)
	if len(f.requests) != 0 || f.handshakes.Load() != 1 {
		t.Fatal("second preparation reached the guest")
	}
}

func TestPristineControlReplacesArmDeadlineWithCurrentRPC(t *testing.T) {
	f := newPristineControlFixture(t, "", func(c net.Conn, r linuxJobRequest) {
		time.Sleep(400 * time.Millisecond)
		writePristineControlResult(c, r)
	})
	v := pristineControlTestVM(t, f.workdir)
	arm, cancelArm := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelArm()
	if err := v.armPristineControl(arm, f.backend.FirecrackerLinuxBackend); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.backend.prepareVMWithDial(ctx, pristineControlPreparation(t), v.workdir, v.takePristineControl); err != nil {
		t.Fatalf("old arm deadline interrupted a new RPC: %v", err)
	}
}

func TestPristineControlRejectsUnsentInvalidConnection(t *testing.T) {
	for _, failure := range []string{"missing", "expired", "endpoint", "port", "cancelled", "owner-cancelled"} {
		t.Run(failure, func(t *testing.T) {
			f := newPristineControlFixture(t, "", nil)
			v := pristineControlTestVM(t, f.workdir)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			dial := firecrackerVsockDial(v.takePristineControl)
			backend, workdir := f.backend, v.workdir
			if failure != "missing" {
				if err := v.armPristineControl(ctx, backend.FirecrackerLinuxBackend); err != nil {
					t.Fatal(err)
				}
			}
			switch failure {
			case "expired":
				future := v.idleControl.Load().expiresAt
				dial = func(ctx context.Context, path string, port uint32) (net.Conn, *bufio.Reader, func() bool, error) {
					return v.takePristineControlAt(ctx, path, port, future)
				}
			case "endpoint":
				workdir += "/foreign"
			case "port":
				backend.Guest.VsockPort++
			case "cancelled":
				cancel()
			case "owner-cancelled":
				v.cancel()
			}
			err := backend.prepareVMWithDial(ctx, pristineControlPreparation(t), workdir, dial)
			if !errors.Is(err, errPristinePrepareNotSent) || v.idleControl.Load() != nil {
				t.Fatalf("invalid connection sent preparation or remained usable: %v", err)
			}
			if failure != "missing" {
				awaitPristineControlClosed(t, f)
			}
			if len(f.requests) != 0 {
				t.Fatal("invalid connection sent tenant bytes")
			}
		})
	}
}

func TestPristineControlForeignVMCannotConsumeOrCloseOwnerConnection(t *testing.T) {
	f := newPristineControlFixture(t, "", nil)
	owner, foreign := pristineControlTestVM(t, f.workdir), pristineControlTestVM(t, f.workdir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owner.armPristineControl(ctx, f.backend.FirecrackerLinuxBackend); err != nil {
		t.Fatal(err)
	}
	foreign.idleControl.Store(owner.idleControl.Load())
	request := pristineControlPreparation(t)
	if err := f.backend.prepareVMWithDial(ctx, request, foreign.workdir, foreign.takePristineControl); !errors.Is(err, errPristinePrepareNotSent) {
		t.Fatal("foreign VM acquired the connection")
	}
	if len(f.requests) != 0 {
		t.Fatal("foreign VM sent a payload")
	}
	if err := f.backend.prepareVMWithDial(ctx, request, owner.workdir, owner.takePristineControl); err != nil {
		t.Fatalf("foreign VM closed the owner's connection: %v", err)
	}
}

func TestPristineControlLostPrepareAckRemainsUncertain(t *testing.T) {
	f := newPristineControlFixture(t, "", func(net.Conn, linuxJobRequest) {})
	v := pristineControlTestVM(t, f.workdir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := v.armPristineControl(ctx, f.backend.FirecrackerLinuxBackend); err != nil {
		t.Fatal(err)
	}
	err := f.backend.prepareVMWithDial(ctx, pristineControlPreparation(t), v.workdir, v.takePristineControl)
	if err == nil || errors.Is(err, errPristinePrepareNotSent) {
		t.Fatal("lost ACK was accepted or marked safe to retry")
	}
	if len(f.requests) != 1 || f.handshakes.Load() != 1 || v.idleControl.Load() != nil {
		t.Fatal("uncertain preparation was replayed or retained its connection")
	}
}

func TestPristineControlOwnerAndRPCCancelCloseConnections(t *testing.T) {
	for _, stage := range []string{"idle-owner", "active-owner", "active-rpc"} {
		t.Run(stage, func(t *testing.T) {
			entered := make(chan struct{})
			f := newPristineControlFixture(t, "", func(c net.Conn, _ linuxJobRequest) {
				close(entered)
				_, _ = io.Copy(io.Discard, c)
			})
			v := pristineControlTestVM(t, f.workdir)
			if err := v.armPristineControl(context.Background(), f.backend.FirecrackerLinuxBackend); err != nil {
				t.Fatal(err)
			}
			if stage == "idle-owner" {
				v.cancel()
				awaitPristineControlClosed(t, f)
				return
			}
			p := &warmPool{backend: f.backend, config: WarmPoolConfig{HealthIntervalMS: 1000}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			request := pristineControlPreparation(t)
			done := make(chan error, 1)
			go func() { done <- p.prepareGuest(ctx, v, request) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("prepare did not reach guest")
			}
			if stage == "active-owner" {
				v.cancel()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil || errors.Is(err, errPristinePrepareNotSent) {
					t.Fatal("cancelled, sent preparation was accepted or retryable")
				}
			case <-time.After(time.Second):
				t.Fatal("active connection ignored cancellation")
			}
			awaitPristineControlClosed(t, f)
		})
	}
}

func TestPristineControlHealthConsumesAndRearmsForCurrentVM(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.HealthIntervalMS = 1000
	startFakeWarmPool(t, m)
	p.mu.Lock()
	v := p.profiles[0].ready[0]
	p.profiles[0].ready = nil
	p.foreground++ // Detach from background workers before changing the driver.
	p.mu.Unlock()
	v.controlMu.Lock()
	defer v.controlMu.Unlock()
	f := newPristineControlFixture(t, v.workdir, nil)
	p.backend = f.backend
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := v.armPristineControl(ctx, f.backend.FirecrackerLinuxBackend); err != nil {
		t.Fatal(err)
	}
	previous := v.idleControl.Load()
	remaining, err := p.probeGuest(ctx, v)
	if err != nil || remaining != 600*time.Second {
		t.Fatalf("health exchange failed: remaining=%v err=%v", remaining, err)
	}
	cancel()
	current := v.idleControl.Load()
	if current == nil || current == previous || current.owner != v || f.handshakes.Load() != 2 {
		t.Fatal("health did not consume and replace this VM's connection")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.prepareGuest(ctx, v, pristineControlPreparation(t)); err != nil {
		t.Fatalf("health context cancellation closed the new connection: %v", err)
	}
	if (<-f.requests).Operation != "ping" || (<-f.requests).Operation != "prepare" || f.handshakes.Load() != 2 {
		t.Fatal("health and preparation did not each consume a single connection")
	}
}

func TestPristineControlCancellationTakeRaceClosesEveryConnection(t *testing.T) {
	for range 64 {
		v := pristineControlTestVM(t, "/unused")
		conn, peer := net.Pipe()
		control := &pristineControlConnection{owner: v, socketPath: "/unused/agent.vsock", port: 5000,
			conn: conn, reader: bufio.NewReader(conn), expiresAt: time.Now().Add(time.Second)}
		control.stopOwner = context.AfterFunc(v.ctx, func() { _ = conn.Close() })
		v.idleControl.Store(control)
		ctx, cancel := context.WithCancel(context.Background())
		stopOwner := context.AfterFunc(v.ctx, cancel)
		start, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			<-start
			c, _, stop, err := v.takePristineControl(ctx, control.socketPath, control.port)
			if err == nil {
				<-ctx.Done()
				stop()
				_ = c.Close()
			}
		}()
		close(start)
		v.cancel()
		v.closePristineControl()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cancellation raced into an unowned connection")
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("connection leaked after take/cancel: %v", err)
		}
		_ = peer.Close()
		stopOwner()
		cancel()
	}
}

func TestPristineControlDestroyClosesSynchronouslyWhileControlLocked(t *testing.T) {
	m, p := fakeWarmManager(t, 1)
	p.config.HealthIntervalMS = 30000
	startFakeWarmPool(t, m)
	p.mu.Lock()
	v := p.profiles[0].ready[0]
	p.profiles[0].ready = nil
	p.foreground++
	p.mu.Unlock()
	v.controlMu.Lock()
	defer v.controlMu.Unlock()
	conn, peer := net.Pipe()
	defer peer.Close()
	blocked, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	control := &pristineControlConnection{owner: v, conn: conn}
	control.stopOwner = context.AfterFunc(v.ctx, func() {
		close(blocked)
		<-release
		_ = conn.Close()
	})
	v.idleControl.Store(control)
	v.cancel()
	<-blocked // Force Destroy to close without help from the owner callback.
	done := make(chan error, 1)
	go func() { done <- v.Destroy() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Destroy blocked on controlMu or the owner callback")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF || v.idleControl.Load() != nil {
		t.Fatal("Destroy returned with an idle descriptor still open")
	}
}

func TestPristineControlMaintenanceDuringForegroundUsesBoundedHealthSlots(t *testing.T) {
	for _, urgent := range []bool{false, true} {
		t.Run(fmt.Sprint(urgent), func(t *testing.T) {
			m, p := fakeWarmManager(t, 1)
			p.config.HealthIntervalMS = 1000
			startFakeWarmPool(t, m)
			entered, release := make(chan struct{}, 1), make(chan struct{})
			defer close(release)
			p.mu.Lock()
			v := p.profiles[0].ready[0]
			v.controlMu.Lock()
			// A locked control prevents any concurrent health operation while
			// the test installs its observation point.
			p.probe = func(ctx context.Context, _ *vmInstance) (time.Duration, error) {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
					return 600 * time.Second, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			p.foreground++
			p.config.CheckTimeoutMS = 2000
			v.checkedAt = time.Now().Add(-1600 * time.Millisecond)
			expires := time.Now().Add(time.Second)
			if urgent {
				expires = time.Now().Add(400 * time.Millisecond)
			}
			v.idleControl.Store(&pristineControlConnection{owner: v, expiresAt: expires})
			v.controlMu.Unlock()
			p.mu.Unlock()
			// Reaching the original limit must suppress even urgent checks.
			p.mu.Lock()
			p.checking = 4
			p.mu.Unlock()
			p.maintain()
			if len(entered) != 0 {
				t.Fatal("maintenance exceeded the four health workers")
			}
			p.mu.Lock()
			p.checking = 0
			p.mu.Unlock()
			p.maintain()
			if urgent {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("foreground suppressed necessary control maintenance")
				}
			} else if len(entered) != 0 {
				t.Fatal("ordinary health check ignored foreground priority")
			}
			// No real connection was installed in this scheduling-only test.
			v.idleControl.Store(nil)
		})
	}
}
