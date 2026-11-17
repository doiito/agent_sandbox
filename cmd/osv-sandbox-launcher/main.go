package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	configPath := flag.String("config", "config.json", "strict production policy configuration")
	allowedUID := flag.Int("allowed-uid", -1, "only this API process uid may use the launcher")
	socketUID := flag.Int("socket-uid", -1, "owner uid for the private launcher socket")
	socketGID := flag.Int("socket-gid", 0, "owner gid for the private launcher socket")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Geteuid() != 0 {
		logger.Error("production launcher must start as root")
		os.Exit(1)
	}
	config, err := sandbox.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}
	if !config.Production {
		logger.Error("launcher refuses a configuration without production=true")
		os.Exit(1)
	}
	audit, err := sandbox.OpenAuditLog(config.AuditLogPath)
	if err != nil {
		logger.Error("open append-only audit log", "error", err)
		os.Exit(1)
	}
	defer audit.Close()
	if *allowedUID < 1 {
		logger.Error("allowed-uid must be a non-root uid")
		os.Exit(1)
	}
	if *socketUID < 0 {
		*socketUID = *allowedUID
	}
	manager, err := sandbox.NewManager(config)
	if err != nil {
		logger.Error("initialize launcher manager", "error", err)
		os.Exit(1)
	}
	options := sandbox.LauncherOptions{
		AllowedUID: *allowedUID, SocketUID: *socketUID, SocketGID: *socketGID,
		SocketMode: 0o600, Logger: logger, Audit: audit,
	}
	listener, err := sandbox.ListenLauncher(config.LauncherSocket, options)
	if err != nil {
		logger.Error("listen on launcher socket", "error", err)
		os.Exit(1)
	}
	defer os.Remove(config.LauncherSocket)
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdown := func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err := manager.Shutdown(cleanup); err != nil {
			logger.Error("cleanup launcher startup", "error", err)
		}
	}
	if err := manager.StartWarmPool(ctx, audit); err != nil {
		logger.Error("initialize warm pool", "error", err)
		shutdown()
		os.Exit(1)
	}
	if err := audit.Append(sandbox.AuditEvent{Event: "launcher.ready"}); err != nil {
		logger.Error("persist launcher readiness", "error", err)
		shutdown()
		os.Exit(1)
	}
	if err := sandbox.NotifySystemdReady(); err != nil {
		logger.Error("notify systemd readiness", "error", err)
		shutdown()
		os.Exit(1)
	}
	logger.Info("sandbox launcher ready", "socket", config.LauncherSocket, "allowed_uid", *allowedUID)
	if err := sandbox.ServeLauncher(ctx, listener, manager, options); err != nil {
		logger.Error("launcher stopped", "error", err)
		os.Exit(1)
	}
}
