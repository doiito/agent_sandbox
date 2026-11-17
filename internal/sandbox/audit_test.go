package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type faultyAuditWriter struct {
	bytes.Buffer
	writes, failAt int
	short          bool
}

func TestAuditRestartRefusesIncompleteRecord(t *testing.T) {
	for _, body := range []string{"", "{\"event\":\"run.admitted\"}\n", "{\"event\":\"run.admitted\""} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		err = validateAuditTail(file)
		file.Close()
		if (err == nil) != (body == "" || body[len(body)-1] == '\n') {
			t.Fatalf("invalid restart decision for partial audit: %v", err)
		}
	}
}

func (w *faultyAuditWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, errors.New("disk full")
	}
	return w.Buffer.Write(p)
}

func TestAuditLatchesWriteShortWriteAndSyncFailure(t *testing.T) {
	for _, mode := range []string{"write", "short", "sync"} {
		t.Run(mode, func(t *testing.T) {
			writer := &faultyAuditWriter{failAt: 1, short: mode == "short"}
			if mode == "sync" {
				writer.failAt = 0
			}
			syncs := 0
			audit := &AuditLog{writer: writer, sync: func() error { syncs++; return errors.New("sync failed") }}
			err := audit.Append(AuditEvent{Event: "run.admitted"})
			if err == nil || audit.Err() == nil {
				t.Fatal("persistence failure was ignored")
			}
			if mode == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
			if err := audit.Append(AuditEvent{Event: "run.admitted"}); err == nil {
				t.Fatal("failed recorder recovered without restart")
			}
			if writer.writes != 1 || (mode != "sync" && syncs != 0) {
				t.Fatalf("audit continued after record loss: writes=%d syncs=%d", writer.writes, syncs)
			}
		})
	}
}

func TestAuditSerializesConcurrentCompleteRecords(t *testing.T) {
	var buffer bytes.Buffer
	syncs := 0
	audit := &AuditLog{writer: &buffer, sync: func() error { syncs++; return nil }}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := audit.Append(AuditEvent{Event: "run.admitted", RequestID: fmt.Sprint(i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := make(map[string]bool)
	for _, line := range bytes.Split(bytes.TrimSpace(buffer.Bytes()), []byte{'\n'}) {
		var event AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event.Protocol != "osv-sandbox-audit/v1" || event.At.IsZero() || seen[event.RequestID] {
			t.Fatalf("invalid/interleaved event: %+v", event)
		}
		seen[event.RequestID] = true
	}
	if len(seen) != 64 || syncs != 64 {
		t.Fatalf("missing durable events: %d/%d", len(seen), syncs)
	}
}

type countedBackend struct{ calls *atomic.Int32 }

func (b countedBackend) Name() string { return "counted-helper" }
func (b countedBackend) Command(ctx context.Context, req RunRequest, a ResolvedArtifacts, dir string) (*exec.Cmd, error) {
	b.calls.Add(1)
	return (helperBackend{mode: "output"}).Command(ctx, req, a, dir)
}

func auditedLauncher(t *testing.T, audit AuditRecorder) (LauncherClient, *Manager, *atomic.Int32) {
	t.Helper()
	options := LauncherOptions{AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: audit}
	socket := filepath.Join(t.TempDir(), "l.sock")
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, "output")
	calls := &atomic.Int32{}
	manager.backend = countedBackend{calls: calls}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeLauncher(ctx, listener, manager, options) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}, manager, calls
}

func TestAuditAdmissionFailureNeverInvokesBackend(t *testing.T) {
	for _, mode := range []string{"write", "sync"} {
		t.Run(mode, func(t *testing.T) {
			writer := &faultyAuditWriter{}
			if mode == "write" {
				writer.failAt = 1
			}
			audit := &AuditLog{writer: writer, sync: func() error {
				if mode == "sync" {
					return errors.New("sync failed")
				}
				return nil
			}}
			client, manager, calls := auditedLauncher(t, audit)
			_, err := client.Run(context.Background(), RunRequest{TimeoutMS: 5000})
			if !errors.Is(err, ErrUnavailable) || calls.Load() != 0 {
				t.Fatalf("audit failed after executing guest: calls=%d err=%v", calls.Load(), err)
			}
			jobs, _ := filepath.Glob(filepath.Join(manager.config.RunRoot, "job-*"))
			if len(jobs) != 0 {
				t.Fatal("audit failure allocated job directory")
			}
			report := client.Doctor()
			found := false
			for _, check := range report.Checks {
				if check.Name == "audit" {
					found = true
					if check.OK {
						t.Fatal("unhealthy audit reported ready")
					}
				}
			}
			if !found || report.Ready {
				t.Fatal("missing audit readiness failure")
			}
		})
	}
}

func TestAuditCompletionFailureRejectsNextAdmission(t *testing.T) {
	syncs := 0
	audit := &AuditLog{writer: io.Discard, sync: func() error {
		syncs++
		if syncs == 2 {
			return errors.New("sync failed")
		}
		return nil
	}}
	client, _, calls := auditedLauncher(t, audit)
	if _, err := client.Run(context.Background(), RunRequest{TimeoutMS: 5000}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("acknowledged non-durable completion: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("expected one admitted execution")
	}
	if _, err := client.Run(context.Background(), RunRequest{TimeoutMS: 5000}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted after audit loss")
	}
	if calls.Load() != 1 {
		t.Fatal("executed new guest after audit loss")
	}
}

func TestAuditAdmissionAndCompletionShareRequestIdentity(t *testing.T) {
	var buffer bytes.Buffer
	audit := &AuditLog{writer: &buffer, sync: func() error { return nil }}
	client, _, _ := auditedLauncher(t, audit)
	result, err := client.Run(context.Background(), RunRequest{TimeoutMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	lines := bytes.Split(bytes.TrimSpace(buffer.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("expected admission/completion: %d", len(lines))
	}
	var before, after AuditEvent
	if err := json.Unmarshal(lines[0], &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &after); err != nil {
		t.Fatal(err)
	}
	if before.Event != "run.admitted" || after.Event != "run.completed" || before.RequestID == "" || before.RequestID != after.RequestID || after.JobID != result.ID {
		t.Fatalf("unbound audit lifecycle: %+v %+v", before, after)
	}
}
