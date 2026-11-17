package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func watchTransportFixture(t *testing.T, prepared bool, serve func(net.Conn, *bufio.Reader, linuxWatchRequest)) (FirecrackerLinuxBackend, linuxWatchRequest, string) {
	t.Helper()
	backend := FirecrackerLinuxBackend{Path: "/bin/firecracker", FileWatch: true, Pristine: prepared, Guest: LinuxGuestConfig{VsockPort: 5000}}
	workdir, err := os.MkdirTemp("/tmp", "wv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workdir) })
	socket, err := backend.vsockPath(workdir)
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
	t.Cleanup(func() { _ = listener.Close() })
	request := linuxWatchRequest{SessionID: "0123456789abcdef01234567", WatchID: "abcdef0123456789abcdef01", Nonce: strings.Repeat("c", 64), Path: "/workspace"}
	if prepared {
		binding, err := newLinuxGuestBinding(request.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		request.Binding = &binding
	}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(connection)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line != "CONNECT 5002\n" {
			t.Errorf("watch used workload port: %q", line)
			return
		}
		if _, err = io.WriteString(connection, "OK 1073742000\n"); err != nil {
			return
		}
		var received linuxWatchRequest
		if json.NewDecoder(reader).Decode(&received) != nil {
			return
		}
		serve(connection, reader, received)
	}()
	return backend, request, workdir
}

func watchFrame(request linuxWatchRequest, kind string, event *SessionWatchEvent) linuxWatchFrame {
	return linuxWatchFrame{Protocol: linuxWatchProtocol, SessionID: request.SessionID, WatchID: request.WatchID, Nonce: request.Nonce, Binding: request.Binding, Kind: kind, Event: event}
}
func sendWatchFrame(connection io.Writer, frame linuxWatchFrame) {
	encoded, _ := json.Marshal(frame)
	_, _ = connection.Write(append(append([]byte(linuxWatchPrefix), encoded...), '\n'))
}

func TestDirectoryWatchTransportLossBeforeReadinessIsUnavailable(t *testing.T) {
	backend, request, work := watchTransportFixture(t, false, func(net.Conn, *bufio.Reader, linuxWatchRequest) {})
	_, err := backend.openFileWatch(context.Background(), context.Background(), request, work)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("valid watch transport loss classified as invalid request", err)
	}
}

func TestDirectoryWatchTransportUsesIndependentLifetimeAndReleasesIdleRead(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "prepared"}[prepared], func(t *testing.T) {
			closed := make(chan struct{})
			backend, request, workdir := watchTransportFixture(t, prepared, func(c net.Conn, r *bufio.Reader, received linuxWatchRequest) {
				defer close(closed)
				writer := bufio.NewWriter(c)
				sendWatchFrame(writer, watchFrame(received, "ready", nil))
				sendWatchFrame(writer, watchFrame(received, "event", &SessionWatchEvent{Sequence: 1, Name: "live", Type: "create"}))
				_ = writer.Flush()
				_, _ = io.Copy(io.Discard, r)
			})
			start, cancelStart := context.WithCancel(context.Background())
			defer cancelStart()
			lifetime, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := backend.openFileWatch(start, lifetime, request, workdir)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			cancelStart() // HTTP create completion must not cancel the live watcher.
			event, code, err := stream.Next()
			if err != nil || code != "" || event == nil || event.Sequence != 1 || event.Name != "live" {
				t.Fatal("buffered watch event lost", event, code, err)
			}
			done := make(chan error, 1)
			go func() { _, _, err := stream.Next(); done <- err }()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled watch read succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("idle watch ignored cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("watch bridge retained its connection")
			}
		})
	}
}

func TestDirectoryWatchTransportRejectsMisboundOrInvalidEvents(t *testing.T) {
	for _, name := range []string{"session", "watch", "nonce", "binding", "sequence", "type", "path", "metadata"} {
		t.Run(name, func(t *testing.T) {
			backend, request, workdir := watchTransportFixture(t, true, func(c net.Conn, _ *bufio.Reader, received linuxWatchRequest) {
				sendWatchFrame(c, watchFrame(received, "ready", nil))
				frame := watchFrame(received, "event", &SessionWatchEvent{Sequence: 1, Name: "live", Type: "create"})
				switch name {
				case "session":
					frame.SessionID = "1123456789abcdef01234567"
				case "watch":
					frame.WatchID = "1123456789abcdef01234567"
				case "nonce":
					frame.Nonce = strings.Repeat("d", 64)
				case "binding":
					frame.Binding.Nonce = strings.Repeat("e", 64)
				case "sequence":
					frame.Event.Sequence = 2
				case "type":
					frame.Event.Type = "unknown"
				case "path":
					frame.Event.Name = "../escape"
				case "metadata":
					frame.Event.Entry = &SessionFileInfo{Path: "/outside"}
				}
				sendWatchFrame(c, frame)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stream, err := backend.openFileWatch(ctx, ctx, request, workdir)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, _, err = stream.Next(); err == nil {
				t.Fatal("invalid guest event was accepted")
			}
		})
	}
}

func TestDirectoryWatchCreateCancellationBeforeReadyClosesTransport(t *testing.T) {
	for _, cancelLifetime := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "session"}[cancelLifetime], func(t *testing.T) {
			blocked, closed := make(chan struct{}), make(chan struct{})
			backend, request, workdir := watchTransportFixture(t, false, func(c net.Conn, r *bufio.Reader, _ linuxWatchRequest) {
				defer close(closed)
				close(blocked)
				_, _ = io.Copy(io.Discard, r)
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lifetime, stopLifetime := context.WithCancel(context.Background())
			defer stopLifetime()
			done := make(chan error, 1)
			go func() {
				stream, err := backend.openFileWatch(ctx, lifetime, request, workdir)
				if stream != nil {
					stream.Close()
				}
				done <- err
			}()
			select {
			case <-blocked:
			case <-time.After(time.Second):
				t.Fatal("watch did not reach handshake")
			}
			if cancelLifetime {
				stopLifetime()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled watch start succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("watch start ignored cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("watch handshake leaked transport")
			}
		})
	}
}
