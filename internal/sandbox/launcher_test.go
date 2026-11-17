package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHTTPDisconnectCancelsLauncherAndReapsVM(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "launcher.sock")
	options := LauncherOptions{AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, "sleep")
	serverCtx, stop := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeLauncher(serverCtx, listener, manager, options) }()
	defer func() {
		stop()
		if err := <-serverDone; err != nil {
			t.Error(err)
		}
	}()
	api := httptest.NewServer(NewAPI(LauncherClient{SocketPath: socket, Timeout: 10 * time.Second}, "secret", options.Logger))
	defer api.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.URL+"/v1/jobs", bytes.NewBufferString(`{"entrypoint":"/agent","timeout_ms":5000}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	done := make(chan error, 1)
	go func() {
		response, err := api.Client().Do(req)
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		leases, _ := filepath.Glob(filepath.Join(manager.config.RunRoot, "job-*", "lease.json"))
		if len(leases) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP request did not start VM")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTP request was not cancelled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP client did not disconnect")
	}
	deadline = time.Now().Add(time.Second)
	for {
		jobs, _ := filepath.Glob(filepath.Join(manager.config.RunRoot, "job-*"))
		if capacity := manager.Capacity(); len(jobs) == 0 && capacity.Active == 0 && capacity.Instances == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP cancellation left jobs/capacity: %v %d", jobs, manager.Capacity().Active)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLauncherCrashReturnsServiceUnavailable(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "launcher.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("Unix listeners are blocked by the test sandbox")
		}
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var request launcherRequest
		_ = json.NewDecoder(conn).Decode(&request)
		// Emulate SIGKILL after accepting the job, before a response is sent.
	}()
	api := NewAPI(LauncherClient{SocketPath: socket, Timeout: 2 * time.Second},
		"secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodPost, "/v1/jobs", strings.NewReader(`{"entrypoint":"/agent"}`))
	req.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	api.ServeHTTP(response, req)
	<-serverDone
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("launcher crash returned %d: %s", response.Code, response.Body.String())
	}
}

func TestLauncherClientInterruptsBlockedResponse(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "launcher.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received, closed := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(closed)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var request launcherRequest
				if json.NewDecoder(conn).Decode(&request) != nil {
					return
				}
				close(received)
				_, _ = io.Copy(io.Discard, conn)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := LauncherClient{SocketPath: socket, Timeout: 2 * time.Second}
			if mode == "timeout" {
				client.Timeout = 100 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { _, err := client.Run(ctx, RunRequest{}); done <- err }()
			select {
			case <-received:
			case <-time.After(2 * time.Second):
				t.Fatal("server received no request")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked RPC succeeded")
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation cause: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("client did not interrupt blocked response")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("peer connection was not closed")
			}
		})
	}
}

func TestLauncherCancellationReapsVMAndReleasesCapacity(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "launcher.sock")
	options := LauncherOptions{AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, "sleep")
	serverCtx, stop := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeLauncher(serverCtx, listener, manager, options) }()
	defer func() {
		stop()
		if err := <-serverDone; err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { _, err := client.Run(ctx, RunRequest{TimeoutMS: 5000}); done <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		jobs, _ := filepath.Glob(filepath.Join(manager.config.RunRoot, "job-*", "lease.json"))
		if len(jobs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("VM did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not return")
	}
	deadline = time.Now().Add(time.Second)
	for {
		jobs, _ := filepath.Glob(filepath.Join(manager.config.RunRoot, "job-*"))
		if capacity := manager.Capacity(); len(jobs) == 0 && capacity.Active == 0 && capacity.Instances == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancel leaked directories/capacity: %v, %d", jobs, manager.Capacity().Active)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A second job must be admitted immediately after cleanup.
	result, err := client.Run(context.Background(), RunRequest{TimeoutMS: 30})
	if err != nil || result.State != "timed_out" {
		t.Fatalf("capacity not reusable: %+v %v", result, err)
	}
}

func TestLauncherRoundTripAndPeerCredentials(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "launcher.sock")
	options := LauncherOptions{
		AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(),
		SocketMode: 0o600, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("Unix listeners are blocked by the test sandbox")
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	manager := testManager(t, "output")
	now := time.Now()
	manager.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), digestSHA256: strings.Repeat("a", 64)}
	go func() { done <- ServeLauncher(ctx, listener, manager, options) }()
	client := LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}
	result, err := client.Run(context.Background(), RunRequest{TimeoutMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "succeeded" || !result.ProtocolOK {
		t.Fatalf("unexpected launcher result: %+v", result)
	}
	if report := client.Doctor(); len(report.Checks) == 0 {
		t.Fatalf("launcher doctor omitted checks: %+v", report)
	}
	if _, err := client.Run(context.Background(), RunRequest{Entrypoint: "/agent", Backend: "wrong",
		ArtifactManifestSHA256: strings.Repeat("a", 64)}); !errors.Is(err, ErrTemplateMismatch) {
		t.Fatalf("launcher lost typed template mismatch: %v", err)
	}
	capabilities, err := client.Capabilities()
	if err != nil || capabilities.Protocol != "osv-sandbox-capabilities/v1" || capabilities.Backend != manager.config.Backend {
		t.Fatalf("launcher capabilities diverged from manager: %+v %v", capabilities, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLauncherRefusesToReplaceRegularFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "launcher.sock")
	if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLauncher(path, LauncherOptions{}); err == nil {
		t.Fatal("expected regular launcher path to be preserved")
	}
}

func TestLauncherFailsClosedWhenAuditSyncFails(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "launcher.sock")
	options := LauncherOptions{
		AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(), SocketMode: 0o600,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: &AuditLog{writer: io.Discard, sync: func() error { return errors.New("disk failure") }},
	}
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("Unix listeners are blocked by the test sandbox")
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeLauncher(ctx, listener, testManager(t, "output"), options) }()
	client := LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}
	if _, err := client.Run(context.Background(), RunRequest{TimeoutMS: 1000}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("launcher acknowledged a result without durable audit: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestSessionCreateDisconnectMonitorDoesNotConsumeNextFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := watchSessionCreateDisconnect(server, cancel)
	stop()
	if ctx.Err() != nil {
		t.Fatal("stopping create monitor canceled a healthy request")
	}
	done := make(chan error, 1)
	go func() { _, err := client.Write([]byte("x")); done <- err }()
	var next [1]byte
	if _, err := server.Read(next[:]); err != nil || next[0] != 'x' {
		t.Fatalf("next frame was consumed: %q %v", next, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionCreateDisconnectImmediatelyCancelsPreparation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := watchSessionCreateDisconnect(server, cancel)
	defer stop()
	_ = client.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("creation waited for its TTL after disconnect")
	}
}
