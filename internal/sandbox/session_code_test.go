package sandbox

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The guest actor is exercised by the real QEMU suite. Here real Unix sockets
// exercise host ownership, typed replies, independent control and uncertainty.
func codeTestSession(t *testing.T, serve func(net.Conn, *bufio.Reader, linuxCodeRequest)) *Session {
	t.Helper()
	backend, wire, work := codeTransportFixture(t, false, serve)
	config := capacityConfig()
	config.Jailer = nil
	config.AllowedEntrypoints = []string{"/bin/sh", codeEntrypoint("python"), codeEntrypoint("javascript")}
	m := &Manager{config: config, backend: backend, capacity: newResourceLedger(config), manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v5", Backend: "firecracker-linux", AgentFeatures: []string{"code-contexts-v1"}, CodeRuntime: testCodeProfile(), digestSHA256: strings.Repeat("a", 64)}}
	physical, active, err := m.capacity.reserveCold(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	vm := &vmInstance{manager: m, ctx: ctx, cancel: cancel, physical: physical, state: vmActive}
	m.instances = map[*vmInstance]struct{}{vm: {}}
	s := &Session{manager: m, backend: backend, ctx: ctx, cancel: cancel, instance: vm, active: active, workdir: work, info: SessionInfo{ID: wire.SessionID, State: "running", CreatedAt: time.Now().UTC()}, hardDeadline: time.Now().Add(time.Minute)}
	s.opMu.Lock() // Code must work while a synchronous shell owns this lock.
	t.Cleanup(func() { cancel(); _ = s.Close(); s.opMu.Unlock() })
	return s
}

func codeErrorIs(t *testing.T, err error, code string) {
	t.Helper()
	var typed *CodeRequestError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestCodeSessionReservesUncertainSubmissionAndPreventsReplay(t *testing.T) {
	var submitted atomic.Int32
	s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
		switch r.Request.Operation {
		case "info":
			ctx := testCodeContext()
			sendCodeReply(c, r, &CodeResponse{Kind: "context", Context: &ctx}, nil)
		case "execute":
			submitted.Add(1) // Simulate an accepted submission with a lost reply.
		case "cancel":
			sendCodeReply(c, r, &CodeResponse{Kind: "accepted"}, nil)
		case "execution":
			page := CodeExecutionPage{ID: r.Request.ExecutionID, ContextID: testCodeContext().ID, Generation: 1, Status: "cancelled", Events: []CodeSequencedEvent{{Sequence: 1, Event: CodeEvent{Type: "finished", Status: "cancelled", ContextUsable: codeBool(true)}}}, LastSequence: 1, NextSequence: 1, Failure: codeText("cancelled_before_submit")}
			sendCodeReply(c, r, &CodeResponse{Kind: "execution", Execution: &page}, nil)
		}
	})
	eid := strings.Repeat("e", 24)
	command := CodeCommand{Operation: "execute", ContextID: testCodeContext().ID, Generation: 1, ExecutionID: eid, Code: "side_effect()"}
	if _, err := s.Code(context.Background(), command); !errors.Is(err, ErrUnavailable) || s.closed.Load() {
		t.Fatal("uncertain delivery destroyed owner", err)
	}
	_, err := s.Code(context.Background(), command)
	codeErrorIs(t, err, "conflict")
	if submitted.Load() != 1 {
		t.Fatal("submission replayed")
	}
	command.Operation = "cancel"
	if _, err = s.Code(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	command.Generation++
	_, err = s.Code(context.Background(), command)
	codeErrorIs(t, err, "conflict")
	response, err := s.Code(context.Background(), CodeCommand{Operation: "execution", ExecutionID: eid})
	if err != nil || response.Execution.SessionID != s.info.ID || response.Execution.Language != "python" {
		t.Fatal("execution lost owner or language binding", response, err)
	}
	_, err = s.Code(context.Background(), CodeCommand{Operation: "execution", ExecutionID: strings.Repeat("f", 24)})
	codeErrorIs(t, err, "not_found")
}

func TestCodeSessionRejectsReboundResultsAndReleasesReservations(t *testing.T) {
	for _, malformed := range []string{"nonce", "execution-binding", "context-language"} {
		t.Run(malformed, func(t *testing.T) {
			var infos atomic.Int32
			s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
				switch r.Request.Operation {
				case "info":
					ctx := testCodeContext()
					if malformed == "context-language" && infos.Add(1) > 1 {
						ctx.Language = "javascript"
					}
					sendCodeReply(c, r, &CodeResponse{Kind: "context", Context: &ctx}, nil)
				case "cancel":
					if malformed == "nonce" {
						r.Nonce = strings.Repeat("0", 64)
					}
					sendCodeReply(c, r, &CodeResponse{Kind: "accepted"}, nil)
				case "execution":
					page := CodeExecutionPage{ID: r.Request.ExecutionID, ContextID: strings.Repeat("d", 24), Generation: 1, Status: "running", Events: []CodeSequencedEvent{{Sequence: 1, Event: CodeEvent{Type: "started"}}}, LastSequence: 1, NextSequence: 1}
					sendCodeReply(c, r, &CodeResponse{Kind: "execution", Execution: &page}, nil)
				}
			})
			if _, err := s.Code(context.Background(), CodeCommand{Operation: "info", ContextID: testCodeContext().ID}); err != nil {
				t.Fatal(err)
			}
			command := CodeCommand{Operation: "cancel", ContextID: testCodeContext().ID, Generation: 1, ExecutionID: strings.Repeat("e", 24)}
			_, err := s.Code(context.Background(), command)
			if malformed == "execution-binding" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = s.Code(context.Background(), CodeCommand{Operation: "execution", ExecutionID: command.ExecutionID})
			} else if malformed == "context-language" {
				_, err = s.Code(context.Background(), CodeCommand{Operation: "info", ContextID: command.ContextID})
			}
			if !errors.Is(err, ErrUnavailable) || !s.closed.Load() {
				t.Fatal("forged result retained owner", err)
			}
			if capacity := s.manager.Capacity(); capacity.Active != 0 || capacity.Instances != 0 {
				t.Fatal("closed code session leaked reservations", capacity)
			}
		})
	}
}

func TestCodeSessionTemplatePolicyQuotaAndLease(t *testing.T) {
	var calls atomic.Int32
	s := codeTestSession(t, func(c net.Conn, _ *bufio.Reader, r linuxCodeRequest) {
		calls.Add(1)
		sendCodeReply(c, r, &CodeResponse{Kind: "accepted"}, nil)
	})
	s.manager.config.AllowedEntrypoints = []string{"/bin/sh"}
	_, err := s.Code(context.Background(), CodeCommand{Operation: "default", Language: "python"})
	codeErrorIs(t, err, "denied")
	s.codeContexts = map[string]string{testCodeContext().ID: "python"}
	s.codeExecutions = map[string]codeExecutionBinding{}
	for i := 0; i < 256; i++ {
		s.codeExecutions[strings.Repeat("x", i+1)] = codeExecutionBinding{}
	}
	_, err = s.Code(context.Background(), CodeCommand{Operation: "cancel", ContextID: testCodeContext().ID, Generation: 1, ExecutionID: strings.Repeat("e", 24)})
	codeErrorIs(t, err, "quota")
	s.lifecycleMu.Lock()
	s.leaseDeadline = time.Now().Add(-time.Second)
	s.lifecycleMu.Unlock()
	if _, err = s.Code(context.Background(), CodeCommand{Operation: "list"}); !errors.Is(err, ErrSessionClosed) || calls.Load() != 0 {
		t.Fatal("expired/denied/quota request reached guest", err, calls.Load())
	}
}
