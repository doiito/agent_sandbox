package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shutdownProbe struct {
	stop        chan struct{}
	started     chan struct{}
	mu          sync.Mutex
	connections []net.Conn
	workers     sync.WaitGroup
}

type telemetryShutdownProbe struct {
	started, release, draining, requestDone chan struct{}
	closed                                  atomic.Int32
	closeErr                                error
}

func (p *telemetryShutdownProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, "started\n")
	w.(http.Flusher).Flush()
	close(p.started)
	<-p.release
	close(p.requestDone)
}
func (p *telemetryShutdownProbe) Shutdown(ctx context.Context) error {
	close(p.draining)
	return nil
}
func (p *telemetryShutdownProbe) CloseTelemetry(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
		return errors.New("telemetry shutdown did not receive a fresh bounded deadline")
	}
	if p.requestDone != nil {
		select {
		case <-p.requestDone:
		default:
			return errors.New("telemetry closed before the last HTTP request returned")
		}
	}
	p.closed.Add(1)
	return p.closeErr
}

func TestOTLPServerFlushesOnlyAfterLastHTTPRequestAndPreservesLoss(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			probe := &telemetryShutdownProbe{started: make(chan struct{}), release: make(chan struct{}),
				draining: make(chan struct{}), requestDone: make(chan struct{})}
			if fail {
				probe.closeErr = errors.New("known-telemetry-loss")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- serveBoundServers(ctx, []*http.Server{{Handler: probe}}, []net.Listener{listener}) }()
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Get("http://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			<-probe.started
			cancel()
			select {
			case <-probe.draining:
			case <-time.After(time.Second):
				t.Fatal("HTTP draining did not begin")
			}
			if probe.closed.Load() != 0 {
				t.Fatal("telemetry closed with an active HTTP request")
			}
			close(probe.release)
			select {
			case err := <-finished:
				if !errors.Is(err, probe.closeErr) || probe.closed.Load() != 1 {
					t.Fatal("final telemetry result was lost", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP and telemetry shutdown did not finish")
			}
		})
	}
}

func TestOTLPServerBindFailureClosesUnservedTelemetry(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	probe := &telemetryShutdownProbe{}
	err = serveServers(context.Background(), &http.Server{Addr: "127.0.0.1:0", Handler: probe}, &http.Server{Addr: reserved.Addr().String()})
	if err == nil || probe.closed.Load() != 1 {
		t.Fatal("bind failure left telemetry unclosed", err)
	}
}

func (p *shutdownProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.workers.Add(1)
	defer p.workers.Done()
	if r.URL.Path == "/ws" {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		p.mu.Lock()
		p.connections = append(p.connections, conn)
		p.mu.Unlock()
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffered.Flush()
		p.started <- struct{}{}
		_, _ = io.Copy(io.Discard, buffered.Reader)
		return
	}
	_, _ = w.Write([]byte("first\n"))
	w.(http.Flusher).Flush()
	p.started <- struct{}{}
	<-p.stop
}
func (p *shutdownProbe) Shutdown(ctx context.Context) error {
	close(p.stop)
	p.mu.Lock()
	for _, conn := range p.connections {
		_ = conn.Close()
	}
	p.mu.Unlock()
	done := make(chan struct{})
	go func() { p.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestServeServersBindFailureClosesOtherListener(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := first.Addr().String()
	_ = first.Close()
	if err := serveServers(context.Background(), &http.Server{Addr: address}, &http.Server{Addr: reserved.Addr().String()}); err == nil {
		t.Fatal("conflicting preview listener accepted")
	}
	reopened, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("control listener leaked on preview bind failure", err)
	}
	_ = reopened.Close()
}
func TestServeServersCancellationJoinsControlStreamAndPreviewUpgrade(t *testing.T) {
	probe := &shutdownProbe{stop: make(chan struct{}), started: make(chan struct{}, 2)}
	var listeners []net.Listener
	for i := 0; i < 2; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
	}
	servers := []*http.Server{{Handler: probe}, {Handler: probe}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- serveBoundServers(ctx, servers, listeners) }()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + listeners[0].Addr().String() + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	front, err := net.DialTimeout("tcp", listeners[1].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	_ = front.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(front, "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(front)
	upgrade, err := http.ReadResponse(reader, nil)
	if err != nil || upgrade.StatusCode != 101 {
		t.Fatal("upgrade", err)
	}
	<-probe.started
	<-probe.started
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("main returned before streams were joined or failed to stop")
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("upgraded socket remained open")
	}
}
