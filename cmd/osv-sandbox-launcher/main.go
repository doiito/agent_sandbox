package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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
	if err := sandbox.ValidateAuditLogTarget(config.AuditLogPath); err != nil {
		logger.Error("validate audit log target", "error", err)
		os.Exit(1)
	}
	auditFile, err := os.OpenFile(config.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		logger.Error("open append-only audit log", "error", err)
		os.Exit(1)
	}
	defer auditFile.Close()
	logger = slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stderr, auditFile), nil))
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
		SocketMode: 0o600, Logger: logger, AuditSync: auditFile.Sync,
	}
	listener, err := sandbox.ListenLauncher(config.LauncherSocket, options)
	if err != nil {
		logger.Error("listen on launcher socket", "error", err)
		os.Exit(1)
	}
	defer os.Remove(config.LauncherSocket)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("sandbox launcher ready", "socket", config.LauncherSocket, "allowed_uid", *allowedUID)
	if err := sandbox.ServeLauncher(ctx, listener, manager, options); err != nil {
		logger.Error("launcher stopped", "error", err)
		os.Exit(1)
	}
}
