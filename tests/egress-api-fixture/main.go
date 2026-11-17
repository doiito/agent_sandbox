// Validation-only API handler fixture. It never launches or simulates guest work.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type fixture struct{}

func (fixture) Run(context.Context, sandbox.RunRequest) (sandbox.RunResult, error) {
	return sandbox.RunResult{}, errors.New("network fixture cannot execute guest work")
}
func (fixture) Doctor() sandbox.DoctorReport { return sandbox.DoctorReport{Ready: true} }
func (fixture) Capabilities() (sandbox.CapabilityReport, error) {
	return sandbox.CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: "network-api-fixture", AllowedEntrypoints: []string{}, Methods: []string{"GET /v1/capabilities"}}, nil
}
func main() {
	authPath := flag.String("auth", "", "test auth policy")
	socket := flag.String("socket", "", "egress Unix socket")
	tlsDir := flag.String("tls", "", "test TLS directory")
	ready := flag.String("ready", "", "write selected listener address")
	flag.Parse()
	auth, err := sandbox.LoadAuthenticator(*authPath)
	if err != nil {
		panic(err)
	}
	tlsConfig, err := sandbox.LoadServerTLS(&sandbox.TLSConfig{CertFile: *tlsDir + "/server.crt", KeyFile: *tlsDir + "/server.key", ClientCAFile: *tlsDir + "/ca.crt"})
	if err != nil {
		panic(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Handler: sandbox.NewAPIWithEgress(fixture{}, auth, slog.Default(), *socket), TLSConfig: tlsConfig, ReadHeaderTimeout: 3 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	data, _ := json.Marshal(map[string]string{"address": listener.Addr().String()})
	if os.WriteFile(*ready, data, 0o600) != nil {
		panic("ready file")
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
