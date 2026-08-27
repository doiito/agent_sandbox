package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	configPath := flag.String("config", "config.json", "path to JSON configuration")
	doctor := flag.Bool("doctor", false, "run host readiness checks and exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	config, err := loadConfig(*configPath)
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
	server := &http.Server{
		Addr:              config.Listen,
		Handler:           sandbox.NewAPIWithAuthenticator(runner, auth, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Duration(config.Limits.MaxTimeoutMS+10_000) * time.Millisecond,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if config.Production {
		server.TLSConfig, err = sandbox.LoadServerTLS(config.TLS)
		if err != nil {
			log.Error("load mTLS configuration", "error", err)
			os.Exit(1)
		}
	}
	log.Info("osv sandbox listening", "address", server.Addr, "backend", config.Backend, "production", config.Production)
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(deadline)
	}()
	serve := server.ListenAndServe
	if config.Production {
		serve = func() error { return server.ListenAndServeTLS("", "") }
	}
	if err := serve(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (sandbox.Config, error) { return sandbox.LoadConfig(path) }
