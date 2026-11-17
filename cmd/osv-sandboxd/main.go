package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/controlgrpc"
	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	configPath := flag.String("config", "config.json", "path to JSON configuration")
	requireProduction := flag.Bool("require-production", false, "refuse to start unless production=true")
	doctor := flag.Bool("doctor", false, "run host readiness checks and exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	config, err := loadConfig(*configPath, *requireProduction)
	if err != nil {
		log.Error("load configuration", "error", err)
		os.Exit(1)
	}
	var runner sandbox.Runner
	if config.Production {
		if os.Geteuid() == 0 {
			log.Error("production API must run as a non-root user")
			os.Exit(1)
		}
		if err := sandbox.LauncherSocketSecure(config.LauncherSocket); err != nil {
			log.Error("validate launcher socket", "error", err)
			os.Exit(1)
		}
		runner = sandbox.LauncherClient{SocketPath: config.LauncherSocket, Timeout: time.Duration(config.Limits.MaxTimeoutMS+10_000) * time.Millisecond}
	} else {
		manager, managerErr := sandbox.NewManager(config)
		if managerErr != nil {
			log.Error("initialize sandbox", "error", managerErr)
			os.Exit(1)
		}
		runner = manager
	}
	if *doctor {
		report := runner.Doctor()
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if !report.Ready {
			os.Exit(2)
		}
		return
	}
	token := os.Getenv("OSV_SANDBOX_TOKEN")
	auth := sandbox.NewSingleTokenAuthenticator(token)
	if config.Production {
		auth, err = sandbox.LoadAuthenticator(config.AuthPolicyPath)
		if err != nil {
			log.Error("load tenant auth policy", "error", err)
			os.Exit(1)
		}
	}
	var controlTLS, previewTLS *tls.Config
	if config.Production {
		controlTLS, err = sandbox.LoadServerTLS(config.TLS)
		if err != nil {
			log.Error("load mTLS configuration", "error", err)
			os.Exit(1)
		}
	}
	if config.Preview != nil {
		previewTLS, err = sandbox.LoadPreviewTLS(config.Preview)
		if err != nil {
			log.Error("load preview TLS configuration", "error", err)
			os.Exit(1)
		}
	}
	handler, previewHandler, err := sandbox.NewAPIWithTelemetry(runner, auth, log, config.EgressSocket, config.Preview, config.OTLP)
	if err != nil {
		log.Error("configure API services", "error", err)
		os.Exit(1)
	}
	grpcHandler, err := controlgrpc.New(handler, auth)
	if err != nil {
		_ = closeTelemetry(handler)
		log.Error("configure native gRPC control", "error", err)
		os.Exit(1)
	}
	handler = grpcHandler
	server := &http.Server{
		Addr:              config.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Duration(config.Limits.MaxTimeoutMS+10_000) * time.Millisecond,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         controlTLS,
	}
	var previewServer *http.Server
	if config.Preview != nil {
		previewServer = &http.Server{Addr: config.Preview.Listen, Handler: previewHandler, TLSConfig: previewTLS,
			ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var shutdownManager func()
	if manager, local := runner.(*sandbox.Manager); local {
		shutdownManager = func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := manager.Shutdown(cleanup); err != nil {
				log.Error("cleanup local runtime", "error", err)
			}
		}
		if err := manager.StartWarmPool(shutdownContext, nil); err != nil {
			log.Error("initialize local runtime", "error", err)
			shutdownManager()
			os.Exit(1)
		}
		defer shutdownManager()
	}
	log.Info("osv sandbox listening", "address", server.Addr, "backend", config.Backend, "production", config.Production)
	if err := serveServers(shutdownContext, server, previewServer); err != nil {
		log.Error("server stopped", "error", err)
		if shutdownManager != nil {
			shutdownManager()
		}
		os.Exit(1)
	}
}

func loadConfig(path string, requireProduction bool) (sandbox.Config, error) {
	config, err := sandbox.LoadConfig(path)
	if err != nil {
		return sandbox.Config{}, err
	}
	if requireProduction && !config.Production {
		return sandbox.Config{}, errors.New("this API instance requires production=true")
	}
	return config, nil
}
