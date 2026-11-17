package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// A TCP view of the framed native stream. The HTTP transport owns reuse; it
// never gets a host socket/address. Closing cancels and joins current native IO.
type previewConn struct {
	service  *previewService
	grant    *previewGrant
	mu       sync.Mutex
	readMu   sync.Mutex
	io       sync.WaitGroup
	closed   bool
	done     chan struct{}
	cancel   context.CancelFunc
	stream   *linuxPortStream
	buffer   []byte
	eof      bool
	deadline *time.Timer
}

func (p *previewService) transportFor(g *previewGrant) *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "guest.invalid:80" {
			return nil, errors.New("invalid preview upstream target")
		}
		return p.dial(ctx, g)
	}, MaxConnsPerHost: 8, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 15 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10, ForceAttemptHTTP2: false, DisableCompression: true}
}
func (p *previewService) dial(start context.Context, g *previewGrant) (net.Conn, error) {
	lifetime, cancel := context.WithCancel(g.ctx)
	c := &previewConn{service: p, grant: g, cancel: cancel, done: make(chan struct{})}
	p.mu.Lock()
	if p.closed || g.info.Status != "active" || len(g.connections) >= 8 {
		p.mu.Unlock()
		cancel()
		return nil, ErrUnavailable
	}
	g.connections[c] = struct{}{}
	p.dials.Add(1)
	p.mu.Unlock()
	defer p.dials.Done()
	failed := true
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	if err := g.session.tenant.consumeRequestToken(); err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, ErrUnavailable
	}
	remaining := time.Until(g.info.ExpiresAt)
	ms := (remaining + time.Millisecond - 1) / time.Millisecond
	if ms <= 0 {
		return nil, ErrSessionClosed
	}
	request := SessionPortRequest{ID: id, Port: g.info.Port, Limits: SessionPortLimits{MaxBytes: portByteLimit, TimeoutMS: uint64(ms), IdleTimeoutMS: uint64(ms)}}
	ctx, stop := context.WithTimeout(start, 2*time.Second)
	defer stop()
	stream, err := g.session.handle.OpenPreviewPort(ctx, lifetime, request, g.info.ID)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	closed := c.closed
	if !closed {
		c.stream = stream
	}
	c.mu.Unlock()
	if closed {
		stream.Close()
		return nil, context.Canceled
	}
	failed = false
	return c, nil
}
func (c *previewConn) begin() (*linuxPortStream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.stream == nil {
		return nil, net.ErrClosed
	}
	c.io.Add(1)
	return c.stream, nil
}
func (c *previewConn) Read(data []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	stream, err := c.begin()
	if err != nil {
		return 0, err
	}
	defer c.io.Done()
	if len(data) == 0 {
		return 0, nil
	}
	if len(c.buffer) > 0 {
		n := copy(data, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}
	if c.eof {
		return 0, io.EOF
	}
	frame, err := stream.Next()
	if err != nil {
		return 0, err
	}
	if frame.Kind == portDataFrame {
		n := copy(data, frame.Data)
		c.buffer = frame.Data[n:]
		return n, nil
	}
	if frame.Kind == portEOFFrame {
		c.eof = true
		return 0, io.EOF
	}
	return 0, ErrUnavailable // no normal EOF without the application's EOF frame
}
func (c *previewConn) Write(data []byte) (int, error) {
	stream, err := c.begin()
	if err != nil {
		return 0, err
	}
	defer c.io.Done()
	return stream.Write(data)
}
func (c *previewConn) CloseWrite() error {
	stream, err := c.begin()
	if err != nil {
		return err
	}
	defer c.io.Done()
	return stream.CloseWrite()
}
func (c *previewConn) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.done
		c.mu.Unlock()
		<-done
		return nil
	}
	c.closed = true
	stream := c.stream
	if c.deadline != nil {
		c.deadline.Stop()
	}
	c.mu.Unlock()
	c.cancel()
	if stream != nil {
		stream.Close()
	}
	c.io.Wait()
	c.service.mu.Lock()
	delete(c.grant.connections, c)
	c.service.mu.Unlock()
	close(c.done)
	return nil
}

type previewAddr string

func (a previewAddr) Network() string      { return "vsock" }
func (a previewAddr) String() string       { return string(a) }
func (c *previewConn) LocalAddr() net.Addr { return previewAddr("api-preview") }
func (c *previewConn) RemoteAddr() net.Addr {
	return previewAddr("guest-loopback:" + strconv.Itoa(int(c.grant.info.Port)))
}
func (c *previewConn) SetDeadline(at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.deadline != nil {
		c.deadline.Stop()
		c.deadline = nil
	}
	if !at.IsZero() {
		c.deadline = time.AfterFunc(time.Until(at), func() { _ = c.Close() })
	}
	return nil
}
func (c *previewConn) SetReadDeadline(at time.Time) error  { return c.SetDeadline(at) }
func (c *previewConn) SetWriteDeadline(at time.Time) error { return c.SetDeadline(at) }
