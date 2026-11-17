package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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

// This fixture validates host transport against actual UDS sockets. Guest PID1,
// TCP, vsock and same-package acceptance are separate evidence, not simulated here.
func portTransportFixture(t *testing.T, prepared bool, serve func(net.Conn, *bufio.Reader, linuxPortRequest)) (FirecrackerLinuxBackend, linuxPortRequest, string) {
	t.Helper()
	b := FirecrackerLinuxBackend{Path: "/bin/firecracker", PortForward: true, Pristine: prepared, Guest: LinuxGuestConfig{VsockPort: 5000}}
	work, err := os.MkdirTemp("/tmp", "pv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	socket, err := b.vsockPath(work)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
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
				r := bufio.NewReader(c)
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if line != "CONNECT 5004\n" {
					t.Errorf("wrong relay port %q", line)
					return
				}
				if writePortBytes(c, []byte("OK 1073742000\n")) != nil {
					return
				}
				var request linuxPortRequest
				if readPortJSON(r, &request) != nil {
					return
				}
				if request.Protocol != linuxPortProtocol {
					t.Error("missing protocol")
					return
				}
				serve(c, r, request)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-accepted; workers.Wait() })
	r := linuxPortRequest{SessionID: strings.Repeat("a", 24), Nonce: strings.Repeat("b", 64), ID: strings.Repeat("c", 24),
		Operation: "open", Port: 8080, Limits: &SessionPortLimits{MaxBytes: portByteLimit, TimeoutMS: 3000, IdleTimeoutMS: 2000}}
	if prepared {
		binding, err := newLinuxGuestBinding(r.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		r.Binding = &binding
	}
	return b, r, work
}

func testPortReply(r linuxPortRequest) linuxPortReply {
	return linuxPortReply{Protocol: linuxPortProtocol, SessionID: r.SessionID, Nonce: r.Nonce, Binding: r.Binding, ID: r.ID, Port: r.Port,
		Response: &SessionPortInfo{ID: r.ID, Port: r.Port, Status: "open"}}
}

func testPortJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	return append(header[:], data...)
}

func testPortFrame(kind byte, data []byte) []byte {
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	return append(header[:], data...)
}

func readTestPortFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > portDataLimit {
		return 0, nil, errPortProtocol
	}
	data := make([]byte, int(size))
	_, err := io.ReadFull(r, data)
	return header[0], data, err
}

func TestPortTransportCoalescedBinaryFramesAndBothHalfCloses(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "prepared"}[prepared], func(t *testing.T) {
			input := bytes.Repeat([]byte{0, 0xff, 42, 10, 13}, 14000)
			output := []byte{0xff, 0, 10, 100, 0}
			b, r, work := portTransportFixture(t, prepared, func(c net.Conn, reader *bufio.Reader, request linuxPortRequest) {
				packet := testPortJSON(testPortReply(request))
				packet = append(packet, testPortFrame(portDataFrame, output)...)
				packet = append(packet, testPortFrame(portEOFFrame, nil)...)
				if writePortBytes(c, packet) != nil {
					return
				}
				var data []byte
				for {
					kind, part, err := readTestPortFrame(reader)
					if err != nil {
						t.Error(err)
						return
					}
					if kind == portEOFFrame {
						if len(part) != 0 {
							t.Error("nonempty EOF")
						}
						break
					}
					if kind != portDataFrame || len(part) == 0 {
						t.Error("invalid input frame")
						return
					}
					data = append(data, part...)
				}
				if !bytes.Equal(data, input) {
					t.Error("binary input lost")
				}
				info := SessionPortInfo{ID: request.ID, Port: request.Port, Status: "completed", SentBytes: uint64(len(data)), ReceivedBytes: uint64(len(output))}
				body, _ := json.Marshal(info)
				_ = writePortBytes(c, testPortFrame(portFinishedFrame, body))
			})
			start, cancelStart := context.WithCancel(context.Background())
			defer cancelStart()
			s, err := b.openPort(start, context.Background(), r, work)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			cancelStart()
			r.Limits.MaxBytes = 1 // the live request owns a frozen copy
			frame, err := s.Next()
			if err != nil || frame.Kind != portDataFrame || !bytes.Equal(frame.Data, output) {
				t.Fatal(frame, err)
			}
			frame, err = s.Next()
			if err != nil || frame.Kind != portEOFFrame {
				t.Fatal(frame, err)
			}
			if n, err := s.Write(input); err != nil || n != len(input) {
				t.Fatal(n, err)
			}
			if err = s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err = s.CloseWrite(); err != nil {
				t.Fatal("duplicate EOF", err)
			}
			if _, err = s.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			frame, err = s.Next()
			if err != nil || frame.Kind != portFinishedFrame || frame.Info.Status != "completed" {
				t.Fatal(frame, err)
			}
			if _, err = s.Next(); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
		})
	}
}

func TestPortControlIndependentOfBlockedDataAndLifetimeCancelsBothDirections(t *testing.T) {
	opened, release := make(chan struct{}), make(chan struct{})
	b, r, work := portTransportFixture(t, true, func(c net.Conn, _ *bufio.Reader, request linuxPortRequest) {
		reply := testPortReply(request)
		if request.Operation == "open" {
			if writePortBytes(c, testPortJSON(reply)) != nil {
				return
			}
			close(opened)
			<-release // no DATA reads: exercise actual UDS backpressure
		} else {
			if request.Operation != "cancel" || request.Limits != nil {
				t.Error("invalid control request")
			}
			reply.Response.Status = "cancelling"
			_ = writePortBytes(c, testPortJSON(reply))
		}
	})
	defer close(release)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := b.openPort(context.Background(), lifetime, r, work)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	<-opened
	writeDone, readDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.Write(make([]byte, 8*1024*1024)); writeDone <- err }()
	go func() { _, err := s.Next(); readDone <- err }()
	select {
	case err := <-writeDone:
		t.Fatal("write did not exercise backpressure", err)
	case <-time.After(100 * time.Millisecond):
	}
	r.Operation, r.Limits = "cancel", nil
	r.Nonce = strings.Repeat("d", 64)
	info, err := b.exchangePortControl(context.Background(), lifetime, r, work)
	if err != nil || info.Status != "cancelling" || info.terminal() {
		t.Fatal(info, err)
	}
	cancel()
	for _, done := range []chan error{writeDone, readDone} {
		select {
		case err := <-done:
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("lifetime cancellation left blocked IO")
		}
	}
}

func TestPortTransportRejectsMisboundHandshakeAndMalformedReply(t *testing.T) {
	for _, name := range []string{"protocol", "session", "nonce", "binding", "id", "port", "both", "missing", "error", "counter", "status", "missing_count", "null_count", "extra"} {
		t.Run(name, func(t *testing.T) {
			b, r, work := portTransportFixture(t, true, func(c net.Conn, _ *bufio.Reader, request linuxPortRequest) {
				reply := testPortReply(request)
				switch name {
				case "protocol":
					reply.Protocol = "other"
				case "session":
					reply.SessionID = strings.Repeat("d", 24)
				case "nonce":
					reply.Nonce = strings.Repeat("d", 64)
				case "binding":
					binding := *reply.Binding
					binding.Nonce = strings.Repeat("d", 64)
					reply.Binding = &binding
				case "id":
					reply.ID = strings.Repeat("d", 24)
				case "port":
					reply.Port++
				case "both":
					code := "quota"
					reply.Error = &code
				case "missing":
					reply.Response = nil
				case "error":
					code := "arbitrary guest text"
					reply.Error = &code
					reply.Response = nil
				case "counter":
					reply.Response.SentBytes = 1
				case "status":
					reply.Response.Status = "completed"
				}
				if name == "missing_count" || name == "null_count" || name == "extra" {
					body, _ := json.Marshal(reply)
					var fields map[string]any
					_ = json.Unmarshal(body, &fields)
					info := fields["response"].(map[string]any)
					switch name {
					case "missing_count":
						delete(info, "sent_bytes")
					case "null_count":
						info["sent_bytes"] = nil
					case "extra":
						info["address"] = "127.0.0.1"
					}
					_ = writePortBytes(c, testPortJSON(fields))
					return
				}
				_ = writePortBytes(c, testPortJSON(reply))
			})
			s, err := b.openPort(context.Background(), context.Background(), r, work)
			if s != nil {
				s.Close()
			}
			if !errors.Is(err, errPortProtocol) {
				t.Fatal(err)
			}
		})
	}
}

func TestPortTransportRejectsInvalidFramesAndNeverTreatsLostFinishAsSuccess(t *testing.T) {
	for _, name := range []string{"empty_data", "large_data", "guest_cancel", "data_after_eof", "duplicate_eof", "partial_header", "partial_data", "missing_finish", "completed_without_eof", "wrong_id", "wrong_count", "wrong_status", "missing_error"} {
		t.Run(name, func(t *testing.T) {
			b, r, work := portTransportFixture(t, false, func(c net.Conn, reader *bufio.Reader, request linuxPortRequest) {
				if writePortBytes(c, testPortJSON(testPortReply(request))) != nil {
					return
				}
				if kind, _, err := readTestPortFrame(reader); err != nil || kind != portEOFFrame {
					t.Error(kind, err)
					return
				}
				info := SessionPortInfo{ID: request.ID, Port: request.Port, Status: "completed"}
				var packet []byte
				switch name {
				case "empty_data":
					packet = testPortFrame(portDataFrame, nil)
				case "large_data":
					packet = testPortFrame(portDataFrame, make([]byte, portDataLimit+1))[:5]
				case "guest_cancel":
					packet = testPortFrame(3, nil)
				case "data_after_eof":
					packet = append(testPortFrame(portEOFFrame, nil), testPortFrame(portDataFrame, []byte("late"))...)
				case "duplicate_eof":
					packet = append(testPortFrame(portEOFFrame, nil), testPortFrame(portEOFFrame, nil)...)
				case "partial_header":
					packet = []byte{1, 0}
				case "partial_data":
					packet = testPortFrame(portDataFrame, []byte("abcdefgh"))[:8]
				case "missing_finish":
					packet = testPortFrame(portEOFFrame, nil)
				default:
					switch name {
					case "wrong_id":
						info.ID = strings.Repeat("d", 24)
					case "wrong_count":
						info.ReceivedBytes = 1
					case "wrong_status":
						info.Status = "open"
					}
					body, _ := json.Marshal(info)
					if name == "missing_error" {
						var fields map[string]any
						_ = json.Unmarshal(body, &fields)
						delete(fields, "error")
						body, _ = json.Marshal(fields)
					}
					if name != "completed_without_eof" {
						packet = testPortFrame(portEOFFrame, nil)
					}
					packet = append(packet, testPortFrame(portFinishedFrame, body)...)
				}
				_ = writePortBytes(c, packet)
			})
			s, err := b.openPort(context.Background(), context.Background(), r, work)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			for {
				frame, readErr := s.Next()
				if readErr != nil {
					err = readErr
					break
				}
				if frame.Info != nil {
					t.Fatal("unverified terminal frame accepted", frame)
				}
			}
			want := errPortProtocol
			if name == "partial_header" || name == "partial_data" || name == "missing_finish" {
				want = ErrUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatal(err)
			}
		})
	}
}

func TestPortTypedErrorAndCancelBeforeOpenControl(t *testing.T) {
	b, r, work := portTransportFixture(t, true, func(c net.Conn, _ *bufio.Reader, request linuxPortRequest) {
		reply := testPortReply(request)
		code := "cancelled"
		if request.Operation == "open" {
			reply.Response = nil
			reply.Error = &code
		} else {
			reply.Response.Status = "cancelled"
			reply.Response.Error = &code
		}
		_ = writePortBytes(c, testPortJSON(reply))
	})
	control := r
	control.Operation = "cancel"
	control.Limits = nil
	info, err := b.exchangePortControl(context.Background(), context.Background(), control, work)
	if err != nil || !info.terminal() || info.Status != "cancelled" {
		t.Fatal(info, err)
	}
	_, err = b.openPort(context.Background(), context.Background(), r, work)
	var typed *PortRequestError
	if !errors.As(err, &typed) || typed.Code != "cancelled" {
		t.Fatal(err)
	}
}

func TestPortHandshakeCancellationAndAbsoluteDurationCloseIdleTransport(t *testing.T) {
	for _, name := range []string{"start", "lifetime", "duration"} {
		t.Run(name, func(t *testing.T) {
			arrived, closed := make(chan struct{}), make(chan struct{})
			b, r, work := portTransportFixture(t, false, func(c net.Conn, reader *bufio.Reader, request linuxPortRequest) {
				defer close(closed)
				if name == "duration" {
					if writePortBytes(c, testPortJSON(testPortReply(request))) != nil {
						return
					}
				}
				close(arrived)
				_, _ = io.Copy(io.Discard, reader)
			})
			start, cancelStart := context.WithCancel(context.Background())
			defer cancelStart()
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			done := make(chan error, 1)
			if name == "duration" {
				r.Limits.TimeoutMS = 120
			}
			go func() {
				s, err := b.openPort(start, lifetime, r, work)
				if s != nil {
					defer s.Close()
					_, err = s.Next()
				}
				done <- err
			}()
			<-arrived
			switch name {
			case "start":
				cancelStart()
			case "lifetime":
				cancelLifetime()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled transport succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("transport ignored deadline/cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("socket retained")
			}
		})
	}
}

func TestPortRequestValidationRequiresFeatureBindingAndBoundedLimits(t *testing.T) {
	b := FirecrackerLinuxBackend{}
	if err := b.validatePortRequest(linuxPortRequest{}); !errors.Is(err, ErrPortUnsupported) {
		t.Fatal(err)
	}
	b.PortForward = true
	r := linuxPortRequest{SessionID: strings.Repeat("a", 24), ID: strings.Repeat("b", 24), Nonce: strings.Repeat("c", 64), Port: 8080, Operation: "open", Limits: &SessionPortLimits{MaxBytes: 1, TimeoutMS: 1, IdleTimeoutMS: 1}}
	if err := b.validatePortRequest(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*linuxPortRequest){func(r *linuxPortRequest) { r.Port = 0 }, func(r *linuxPortRequest) { r.Limits = nil }, func(r *linuxPortRequest) { r.Limits.MaxBytes = portByteLimit + 1 }, func(r *linuxPortRequest) { r.Limits.TimeoutMS = portDurationLimitMS + 1 }, func(r *linuxPortRequest) { r.Limits.IdleTimeoutMS = 0 }, func(r *linuxPortRequest) { r.Operation = "cancel" }, func(r *linuxPortRequest) {
		r.Binding = &linuxGuestBinding{SessionID: r.SessionID, Nonce: strings.Repeat("e", 64)}
	}} {
		copy := r
		limits := *r.Limits
		copy.Limits = &limits
		mutate(&copy)
		if err := b.validatePortRequest(copy); !errors.Is(err, errPortProtocol) {
			t.Fatal(err)
		}
	}
	b.Pristine = true
	if err := b.validatePortRequest(r); !errors.Is(err, errPortProtocol) {
		t.Fatal(err)
	}
}

func TestPortTransportEnforcesExactInputAndOutputBudgets(t *testing.T) {
	for _, excess := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "excess_output"}[excess], func(t *testing.T) {
			b, r, work := portTransportFixture(t, false, func(c net.Conn, reader *bufio.Reader, request linuxPortRequest) {
				if writePortBytes(c, testPortJSON(testPortReply(request))) != nil {
					return
				}
				kind, data, err := readTestPortFrame(reader)
				if err != nil || kind != portDataFrame || string(data) != "abcd" {
					t.Error("bad input", kind, string(data), err)
					return
				}
				if kind, _, err = readTestPortFrame(reader); err != nil || kind != portEOFFrame {
					t.Error(kind, err)
					return
				}
				output := []byte("abcd")
				if excess {
					output = append(output, 'e')
				}
				packet := testPortFrame(portDataFrame, output)
				packet = append(packet, testPortFrame(portEOFFrame, nil)...)
				body, _ := json.Marshal(SessionPortInfo{ID: request.ID, Port: request.Port, Status: "completed", SentBytes: 4, ReceivedBytes: uint64(len(output))})
				packet = append(packet, testPortFrame(portFinishedFrame, body)...)
				_ = writePortBytes(c, packet)
			})
			r.Limits.MaxBytes = 4
			s, err := b.openPort(context.Background(), context.Background(), r, work)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if n, err := s.Write([]byte("excess")); n != 0 || err == nil {
				t.Fatal(n, err)
			}
			if n, err := s.Write([]byte("abcd")); n != 4 || err != nil {
				t.Fatal(n, err)
			}
			if err := s.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			frame, err := s.Next()
			if excess {
				if !errors.Is(err, errPortProtocol) {
					t.Fatal(err)
				}
				return
			}
			if err != nil || string(frame.Data) != "abcd" {
				t.Fatal(frame, err)
			}
			if frame, err = s.Next(); err != nil || frame.Kind != portEOFFrame {
				t.Fatal(frame, err)
			}
			if frame, err = s.Next(); err != nil || frame.Info == nil || frame.Info.Status != "completed" {
				t.Fatal(frame, err)
			}
		})
	}
}

func TestPortBootFlagIsExplicitAndExecutionPortCannotCollide(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			artifacts, work := t.TempDir(), filepath.Join(t.TempDir(), "port-boot")
			if err := os.Mkdir(work, 0o700); err != nil {
				t.Fatal(err)
			}
			kernel, image := filepath.Join(artifacts, "kernel"), filepath.Join(artifacts, "rootfs")
			for _, path := range []string{kernel, image} {
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			b := FirecrackerLinuxBackend{Path: "/bin/firecracker", PortForward: enabled,
				Guest:  LinuxGuestConfig{VsockPort: 5000, ScratchMiB: 8, MkfsPath: "/bin/true"},
				Jailer: &JailerConfig{Path: "/bin/jailer", UID: os.Getuid(), GID: os.Getgid(), CgroupVersion: 2, MemoryOverheadMiB: 128, NoFileLimit: 128}}
			_, err := b.Command(context.Background(), RunRequest{MemoryMiB: 128, VCPUs: 1}, ResolvedArtifacts{KernelPath: kernel, ImagePath: image, Format: "raw"}, work)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(work, "jailer", "firecracker", "port-boot", "root", "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "agent.port=5004") != enabled {
				t.Fatal("incorrect boot capability", string(data))
			}
			if strings.Contains(string(data), "agent.egress") || strings.Contains(string(data), "agent.proxy") {
				t.Fatal("inbound port enabled egress")
			}
		})
	}
	b := FirecrackerLinuxBackend{PortForward: true, Guest: LinuxGuestConfig{VsockPort: 5004}}
	if _, err := b.Command(context.Background(), RunRequest{}, ResolvedArtifacts{}, ""); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatal(err)
	}
}

func TestPortExistingProfilesDoNotAdvertiseIncompleteFeature(t *testing.T) {
	for _, version := range []string{"v1", "v3", "v4", "v5"} {
		m := &Manager{config: Config{Backend: "firecracker-linux"}, backend: FirecrackerLinuxBackend{PortForward: true}, manifest: &SignedArtifactManifest{
			Protocol: "osv-sandbox-artifacts/" + version, Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}, digestSHA256: strings.Repeat("a", 64)}}
		report, err := m.Capabilities()
		if err != nil || report.Features.PortForward {
			t.Fatal("old profile advertised port relay", version, report.Features, err)
		}
	}
}
