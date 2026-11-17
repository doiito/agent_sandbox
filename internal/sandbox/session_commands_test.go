package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func streamBackendFixture(t *testing.T, serve func(net.Conn, *bufio.Reader, linuxJobRequest)) (FirecrackerLinuxBackend, string) {
	t.Helper()
	b := FirecrackerLinuxBackend{Path: "/bin/firecracker", Guest: LinuxGuestConfig{VsockPort: 5000}, OutputLimit: 65536}
	work, err := os.MkdirTemp("/tmp", "stream-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	path, err := b.vsockPath(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err = reader.ReadString('\n'); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "OK 1\n")
		var request linuxJobRequest
		frame, readErr := reader.ReadBytes('\n')
		if readErr != nil || json.Unmarshal(frame, &request) != nil {
			return
		}
		serve(conn, reader, request)
	}()
	return b, work
}

func TestStreamedBackendEventsAndCancellationAreBound(t *testing.T) {
	for _, bad := range []string{"", "sequence", "job", "bytes", "stream", "nonce"} {
		t.Run(bad, func(t *testing.T) {
			cancel := make(chan struct{})
			received := 0
			b, work := streamBackendFixture(t, func(conn net.Conn, reader *bufio.Reader, request linuxJobRequest) {
				_, _ = fmt.Fprintf(conn, "FC_AGENT_STARTED {\"protocol\":\"%s\",\"job_id\":\"%s\",\"pid\":42}\n", request.Protocol, request.JobID)
				event := linuxCommandOutput{Protocol: linuxSessionProtocol, JobID: request.JobID, Sequence: 1, Stream: "stdout", DataBase64: "AP8="}
				switch bad {
				case "sequence":
					event.Sequence = 2
				case "job":
					event.JobID = strings.Repeat("c", 24)
				case "bytes":
					event.DataBase64 = "AP8=\n"
				case "stream":
					event.Stream = "serial"
				case "nonce":
					event.Binding = &linuxGuestBinding{SessionID: strings.Repeat("d", 24), Nonce: strings.Repeat("e", 64)}
				}
				data, _ := json.Marshal(event)
				_, _ = fmt.Fprintf(conn, "FC_AGENT_EVENT %s\n", data)
				if bad != "" {
					return
				}
				line, _ := reader.ReadString('\n')
				if line != "cancel\n" {
					return
				}
				_, _ = fmt.Fprintf(conn, "FC_AGENT_RESULT {\"protocol\":\"%s\",\"job_id\":\"%s\",\"ok\":false,\"exit_code\":137,\"timed_out\":false,\"stdout\":\"\",\"stderr\":\"\",\"error\":\"command cancelled\"}\n", request.Protocol, request.JobID)
			})
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			raw, ok, err := b.ExchangeSession(ctx, linuxJobRequest{JobID: strings.Repeat("a", 24), Operation: "run_stream", Argv: []string{"/bin/sh"}, TimeoutMS: 1000,
				commandCancel: cancel, onOutput: func(event SessionOutputEvent) error { received++; close(cancel); return nil }}, work)
			if bad != "" {
				if err == nil || received != 0 {
					t.Fatalf("invalid event accepted: %s", raw)
				}
				return
			}
			if err != nil || ok || received != 1 {
				t.Fatalf("bound stream cancellation failed: %s %v", raw, err)
			}
		})
	}
}

func TestCommandJournalPagesHistoryAndCancellation(t *testing.T) {
	s := &Session{info: SessionInfo{ID: strings.Repeat("a", 24)}, commands: map[string]*commandRecord{}}
	id := strings.Repeat("b", 24)
	r := &commandRecord{info: SessionCommandInfo{ID: id, SessionID: s.info.ID, State: "running"}, cancel: make(chan struct{})}
	for i := 1; i <= 130; i++ {
		r.events = append(r.events, SessionOutputEvent{Sequence: i, Stream: "stdout", DataBase64: "eA=="})
	}
	s.commands[id] = r
	s.commandOrder = []string{id}
	for cursor, want := range map[int]int{0: 64, 64: 64, 128: 2, 130: 0} {
		page, err := s.PollCommand(id, cursor)
		if err != nil || len(page.Events) != want || page.NextSequence != cursor+want || page.Complete {
			t.Fatalf("bad journal page: %+v %v", page, err)
		}
	}
	page, _ := s.PollCommand(id, 0)
	page.Events[0].Sequence = 999
	if r.events[0].Sequence != 1 {
		t.Fatal("reader mutated stored output")
	}
	if _, err := s.PollCommand(id, 131); err == nil {
		t.Fatal("future cursor accepted")
	}
	if _, err := s.PollCommand(strings.Repeat("c", 24), 0); err != ErrCommandNotFound {
		t.Fatal("missing handle exposed")
	}
	if killed, err := s.CancelCommand(id); !killed || err != nil {
		t.Fatal("first cancel failed")
	}
	if killed, err := s.CancelCommand(id); killed || err != nil {
		t.Fatal("repeat cancel was not idempotent")
	}
	select {
	case <-r.cancel:
	default:
		t.Fatal("cancellation was not delivered")
	}
	r.finished = true
	r.info.State = "cancelled"
	page, _ = s.PollCommand(id, 130)
	if !page.Complete {
		t.Fatal("terminal cursor not complete")
	}
}

func TestSessionExecutionEnvironmentAndWorkdirBounds(t *testing.T) {
	config := testConfig()
	config.AllowedEntrypoints = []string{"/bin/bash"}
	request := SessionCommandRequest{Entrypoint: "/bin/bash", Environment: map[string]string{"KEY": "中文 value", "LD_LIBRARY_PATH": "/workspace/lib"}, Cwd: "/workspace/sub"}
	request.Normalize(config)
	if err := request.Validate(config, 128, 1); err != nil {
		t.Fatal(err)
	}
	for _, env := range []map[string]string{{"bad key": "x"}, {"1bad": "x"}, {"KEY": "a\x00b"}, {"KEY": strings.Repeat("x", 1025)}} {
		request.Environment = env
		if request.Validate(config, 128, 1) == nil {
			t.Fatalf("invalid env accepted: %+v", env)
		}
	}
	request.Environment = nil
	for _, cwd := range []string{"relative", "/workspace/\x00bad", "/workspace/\n"} {
		request.Cwd = cwd
		if request.Validate(config, 128, 1) == nil {
			t.Fatalf("invalid cwd accepted: %q", cwd)
		}
	}
}

func TestCommandStartedFrameRequiresValidPIDAndBinding(t *testing.T) {
	for _, bad := range []string{"valid", "pid-one", "pid-overflow", "job", "protocol", "nonce", "missing", "duplicate"} {
		t.Run(bad, func(t *testing.T) {
			b, work := streamBackendFixture(t, func(conn net.Conn, _ *bufio.Reader, request linuxJobRequest) {
				start := linuxCommandStarted{Protocol: request.Protocol, JobID: request.JobID, PID: 42}
				switch bad {
				case "pid-one":
					start.PID = 1
				case "pid-overflow":
					start.PID = 1<<30 + 1
				case "job":
					start.JobID = strings.Repeat("c", 24)
				case "protocol":
					start.Protocol = "wrong/v1"
				case "nonce":
					start.Binding = &linuxGuestBinding{SessionID: strings.Repeat("d", 24), Nonce: strings.Repeat("e", 64)}
				}
				frame, _ := json.Marshal(start)
				if bad != "missing" {
					fmt.Fprintf(conn, "FC_AGENT_STARTED %s\n", frame)
				}
				if bad == "duplicate" {
					fmt.Fprintf(conn, "FC_AGENT_STARTED %s\n", frame)
				}
				fmt.Fprintf(conn, "FC_AGENT_RESULT {\"protocol\":\"%s\",\"job_id\":\"%s\",\"ok\":true,\"exit_code\":0,\"timed_out\":false,\"stdout\":\"\",\"stderr\":\"\"}\n", request.Protocol, request.JobID)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			pid := 0
			_, ok, err := b.ExchangeSession(ctx, linuxJobRequest{JobID: strings.Repeat("a", 24), Operation: "run_stream", Argv: []string{"/bin/bash"}, TimeoutMS: 1000, onStarted: func(value int) error { pid = value; return nil }}, work)
			if bad == "valid" {
				if err != nil || !ok || pid != 42 {
					t.Fatalf("valid started frame failed: %v %v %d", err, ok, pid)
				}
			} else if err == nil {
				t.Fatal("invalid started frame accepted")
			}
		})
	}
}
