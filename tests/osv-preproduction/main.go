// This executable exercises the OSv cross-process path before the production
// gate is opened. It is a test fixture and is not shipped in offline releases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	role := flag.String("role", "", "launcher or api")
	configPath := flag.String("config", "", "absolute diagnostic configuration path")
	apiUID := flag.Int("api-uid", -1, "non-root API uid for launcher peer checks")
	flag.Parse()
	if err := run(*role, *configPath, *apiUID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(role, configPath string, apiUID int) (runErr error) {
	config, err := sandbox.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if config.Production || config.Backend != "firecracker-osv" || config.ArtifactManifest == nil ||
		config.TLS == nil || config.AuthPolicyPath == "" || config.AuditLogPath == "" ||
		config.LauncherSocket == "" || apiUID < 1 {
		return errors.New("fixture requires diagnostic OSv, signed template, mTLS, tenant policy, audit, socket, and non-root API uid")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch role {
	case "launcher":
		if os.Geteuid() != 0 {
			return errors.New("fixture launcher requires root")
		}
		manager, err := sandbox.NewManager(config)
		if err != nil {
			return err
		}
		audit, err := sandbox.OpenAuditLog(config.AuditLogPath)
		if err != nil {
			return err
		}
		defer audit.Close()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			runErr = errors.Join(runErr, manager.Shutdown(shutdownCtx))
		}()
		if err := manager.StartWarmPool(ctx, audit); err != nil {
			return err
		}
		options := sandbox.LauncherOptions{AllowedUID: apiUID, SocketUID: apiUID, SocketGID: 0,
			SocketMode: 0o600, Logger: logger, Audit: audit}
		listener, err := sandbox.ListenLauncher(config.LauncherSocket, options)
		if err != nil {
			return err
		}
		defer listener.Close()
		defer os.Remove(config.LauncherSocket)
		if err := audit.Append(sandbox.AuditEvent{Event: "launcher.ready"}); err != nil {
			return err
		}
		return sandbox.ServeLauncher(ctx, listener, manager, options)
	case "api":
		if os.Geteuid() != apiUID {
			return errors.New("fixture API must run as configured non-root uid")
		}
		if err := sandbox.LauncherSocketSecure(config.LauncherSocket); err != nil {
			return err
		}
		auth, err := sandbox.LoadAuthenticator(config.AuthPolicyPath)
		if err != nil {
			return err
		}
		tlsConfig, err := sandbox.LoadServerTLS(config.TLS)
		if err != nil {
			return err
		}
		runner := sandbox.LauncherClient{SocketPath: config.LauncherSocket,
			Timeout: time.Duration(config.Limits.MaxTimeoutMS+10_000) * time.Millisecond}
		server := &http.Server{Addr: config.Listen,
			Handler:   sandbox.NewAPIWithAuthenticator(runner, auth, logger),
			TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: time.Duration(config.Limits.MaxTimeoutMS+10_000) * time.Millisecond,
			IdleTimeout:  30 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	default:
		return errors.New("role must be launcher or api")
	}
}
