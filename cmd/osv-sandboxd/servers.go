package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Bind every listener before serving either origin. A failed preview bind must
// not leave a control API advertising an unavailable browser endpoint.
func serveServers(ctx context.Context, control, preview *http.Server) error {
	servers := []*http.Server{control}
	if preview != nil {
		servers = append(servers, preview)
	}
	listeners := make([]net.Listener, 0, len(servers))
	for _, server := range servers {
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			for _, old := range listeners {
				_ = old.Close()
			}
			return errors.Join(fmt.Errorf("bind %s: %w", server.Addr, err), closeTelemetry(control.Handler))
		}
		listeners = append(listeners, listener)
	}
	return serveBoundServers(ctx, servers, listeners)
}

func serveBoundServers(ctx context.Context, servers []*http.Server, listeners []net.Listener) error {
	control := servers[0]
	var stopping atomic.Bool
	results := make(chan error, len(servers))
	for index, server := range servers {
		listener := listeners[index]
		go func(server *http.Server, listener net.Listener) {
			var err error
			if server.TLSConfig == nil {
				err = server.Serve(listener)
			} else {
				err = server.ServeTLS(listener, "", "")
			}
			if errors.Is(err, http.ErrServerClosed) || stopping.Load() && errors.Is(err, net.ErrClosed) {
				err = nil
			}
			results <- err
		}(server, listener)
	}
	remaining := len(servers)
	var result error
	select {
	case <-ctx.Done():
	case result = <-results:
		remaining--
	}
	deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Close admission before an application drain can wait for long-running
	// RPCs. HTTP shutdown then sends HTTP/2 GOAWAY while the owner closes
	// upgraded connections and observes the same shared drain deadline.
	stopping.Store(true)
	for _, listener := range listeners {
		_ = listener.Close()
	}
	shutdowns := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *http.Server) {
			err := server.Shutdown(deadline)
			if errors.Is(err, net.ErrClosed) {
				err = nil
			}
			if err != nil {
				_ = server.Close()
			}
			shutdowns <- err
		}(server)
	}
	if handler, ok := control.Handler.(interface{ Shutdown(context.Context) error }); ok {
		result = errors.Join(result, handler.Shutdown(deadline))
	}
	for range servers {
		result = errors.Join(result, <-shutdowns)
	}
	for remaining > 0 {
		result = errors.Join(result, <-results)
		remaining--
	}
	return errors.Join(result, closeTelemetry(control.Handler))
}

// HTTP draining owns its own deadline. Telemetry gets a separate bounded tail
// so a long-running final request is recorded before the worker is closed.
func closeTelemetry(handler http.Handler) error {
	if handler, ok := handler.(interface{ CloseTelemetry(context.Context) error }); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return handler.CloseTelemetry(ctx)
	}
	return nil
}
