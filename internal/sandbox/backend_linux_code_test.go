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

func codeTransportFixture(t *testing.T, prepared bool, serve func(net.Conn, *bufio.Reader, linuxCodeRequest)) (FirecrackerLinuxBackend, linuxCodeRequest, string) {
	t.Helper()
	backend := FirecrackerLinuxBackend{Path: "/bin/firecracker", CodeContexts: true, CodePrewarm: "python", Pristine: prepared, Guest: LinuxGuestConfig{VsockPort: 5000}}
	work, err := os.MkdirTemp("/tmp", "cv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	socket, err := backend.vsockPath(work)
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
	request := linuxCodeRequest{SessionID: strings.Repeat("a", 24), Nonce: strings.Repeat("b", 64), Request: CodeCommand{Operation: "default", Language: "python"}}
	if prepared {
		binding, _ := newLinuxGuestBinding(request.SessionID)
		request.Binding = &binding
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
				reader := bufio.NewReader(connection)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line != "CONNECT 5003\n" {
					t.Errorf("wrong code port %q", line)
					return
				}
				_, _ = io.WriteString(connection, "OK 1073742000\n")
				line, err = reader.ReadString('\n')
				if err != nil {
					return
				}
				var received linuxCodeRequest
				if codeDecode([]byte(line), &received) != nil {
					t.Error("bad code request")
					return
				}
				serve(connection, reader, received)
			}()
		}
	}()
	return backend, request, work
}
func sendCodeReply(connection io.Writer, request linuxCodeRequest, response *CodeResponse, err *CodeRequestError) {
	bytes, _ := codeJSON(linuxCodeReply{Protocol: linuxCodeProtocol, SessionID: request.SessionID, Nonce: request.Nonce, Binding: request.Binding, Response: response, Error: err})
	_, _ = io.WriteString(connection, linuxCodePrefix+string(bytes)+"\n")
}
func TestCodeTransportUsesIndependentPortAndPreparedIdentity(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "prepared"}[prepared], func(t *testing.T) {
			backend, request, work := codeTransportFixture(t, prepared, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
				ctx := testCodeContext()
				sendCodeReply(c, r, &CodeResponse{Kind: "context", Context: &ctx}, nil)
			})
			response, err := backend.exchangeCode(context.Background(), context.Background(), request, work)
			if err != nil || response.Context.ID != testCodeContext().ID {
				t.Fatal(response, err)
			}
		})
	}
}
func TestCodeTransportRejectsForgedIdentityAndMalformedResults(t *testing.T) {
	for _, kind := range []string{"nonce", "binding", "context", "state", "pid", "session", "error-and-value"} {
		t.Run(kind, func(t *testing.T) {
			backend, request, work := codeTransportFixture(t, true, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
				ctx := testCodeContext()
				reply := linuxCodeReply{Protocol: linuxCodeProtocol, SessionID: r.SessionID, Nonce: r.Nonce, Binding: r.Binding, Response: &CodeResponse{Kind: "context", Context: &ctx}}
				switch kind {
				case "nonce":
					reply.Nonce = strings.Repeat("c", 64)
				case "binding":
					reply.Binding = nil
				case "context":
					ctx.Language = "ruby"
				case "state":
					ctx.State = "ready"
				case "pid":
					pid := uint32(1)
					ctx.PID = &pid
				case "session":
					ctx.SessionID = r.SessionID
				case "error-and-value":
					reply.Error = &CodeRequestError{Code: "busy", Message: "busy"}
				}
				bytes, _ := codeJSON(reply)
				_, _ = io.WriteString(c, linuxCodePrefix+string(bytes)+"\n")
			})
			if _, err := backend.exchangeCode(context.Background(), context.Background(), request, work); !errors.Is(err, errCodeProtocol) {
				t.Fatal("malformed response accepted", kind, err)
			}
		})
	}
}
func TestCodeTransportLossRetainsUnknownDeliveryAndCancellationReleasesRead(t *testing.T) {
	backend, request, work := codeTransportFixture(t, false, func(net.Conn, *bufio.Reader, linuxCodeRequest) {})
	if _, err := backend.exchangeCode(context.Background(), context.Background(), request, work); !errors.Is(err, ErrUnavailable) || errors.Is(err, errCodeProtocol) {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	peerClosed := make(chan struct{})
	backend, request, work = codeTransportFixture(t, false, func(_ net.Conn, reader *bufio.Reader, _ linuxCodeRequest) {
		close(entered)
		_, _ = io.Copy(io.Discard, reader)
		close(peerClosed)
	})
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := backend.exchangeCode(context.Background(), lifetime, request, work); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("code RPC ignored lifetime cancellation")
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("code transport leaked")
	}
}
func TestCodeReadinessOnlyAppliesToInitialAdmission(t *testing.T) {
	b := FirecrackerLinuxBackend{CodeContexts: true, CodePrewarm: "python"}
	missing := json.RawMessage(`{"ok":true}`)
	if b.validateCodeReadiness(linuxJobRequest{Operation: "ping"}, missing) != nil {
		t.Fatal("ordinary heartbeat requires a pristine interpreter")
	}
	if b.validateCodeReadiness(linuxJobRequest{Operation: "ping", requireCodeReady: true}, missing) == nil {
		t.Fatal("unproved prewarm admitted")
	}
	valid := json.RawMessage(`{"ok":true,"code_service":{"revision":1,"kernel_protocol":"osv-code-kernel/v2","prewarm_language":"python"}}`)
	if b.validateCodeReadiness(linuxJobRequest{Operation: "ping", requireCodeReady: true}, valid) != nil {
		t.Fatal("valid prewarm refused")
	}
	b.CodePrewarm = "typescript"
	if b.validateCodeReadiness(linuxJobRequest{Operation: "ping", requireCodeReady: true}, valid) == nil {
		t.Fatal("wrong prewarm language accepted")
	}
}
