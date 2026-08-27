package sandbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

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
	go func() { done <- ServeLauncher(ctx, listener, manager, options) }()
	client := LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}
	result, err := client.Run(context.Background(), RunRequest{TimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "succeeded" || !result.ProtocolOK {
		t.Fatalf("unexpected launcher result: %+v", result)
	}
	if report := client.Doctor(); len(report.Checks) == 0 {
		t.Fatalf("launcher doctor omitted checks: %+v", report)
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
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AuditSync: func() error { return errors.New("disk failure") },
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
	if _, err := client.Run(context.Background(), RunRequest{TimeoutMS: 1000}); err == nil || err.Error() != "audit durability failure" {
		t.Fatalf("launcher acknowledged a result without durable audit: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
