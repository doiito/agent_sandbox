package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreviewHTTPStreamingRevokeAndFullDuplexUpload(t *testing.T) {
	t.Run("stream-revoke", func(t *testing.T) {
		closed := make(chan struct{})
		f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(closed)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: first\n\n"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		info := f.create(t, strings.Repeat("6", 24), 5000)
		cookie := f.bootstrap(t, info)
		response := f.request(t, "GET", info.Origin+"/events", cookie, nil, nil)
		defer response.Body.Close()
		first := make([]byte, len("data: first\n\n"))
		if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "data: first\n\n" {
			t.Fatal("response was buffered", err)
		}
		status, _ := f.control(t, "DELETE", "/v2/sessions/"+info.SessionID+"/previews/"+info.ID, "token-a", nil)
		if status != 200 {
			t.Fatal(status)
		}
		if _, err := response.Body.Read(first); err == nil {
			t.Fatal("revoked stream remained readable")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("application TCP not closed")
		}
	})
	t.Run("duplex-upload", func(t *testing.T) {
		f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = http.NewResponseController(w).EnableFullDuplex()
			_, _ = w.Write([]byte("ready\n"))
			w.(http.Flusher).Flush()
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return
			}
			_, _ = w.Write(data)
		}))
		info := f.create(t, strings.Repeat("7", 24), 5000)
		cookie := f.bootstrap(t, info)
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		r, _ := http.NewRequestWithContext(ctx, "POST", info.Origin+"/duplex", reader)
		r.AddCookie(cookie)
		type reply struct {
			response *http.Response
			err      error
		}
		done := make(chan reply, 1)
		go func() { response, err := f.browser.Do(r); done <- reply{response, err} }()
		if _, err := writer.Write([]byte("prefix")); err != nil {
			t.Fatal(err)
		}
		result := <-done
		if result.err != nil {
			t.Fatal("response did not start during upload", result.err)
		}
		defer result.response.Body.Close()
		first := make([]byte, 6)
		if _, err := io.ReadFull(result.response.Body, first); err != nil || string(first) != "ready\n" {
			t.Fatal("early response lost", err)
		}
		payload := bytes.Repeat([]byte{0, 255, 42}, 10000)
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		rest, err := io.ReadAll(result.response.Body)
		if err != nil || !bytes.Equal(rest, append([]byte("prefix"), payload...)) {
			t.Fatal("duplex body mismatch", err)
		}
	})
}

func TestPreviewHTTPNeverReplaysAnUncertainRequestOnReusedConnection(t *testing.T) {
	var received atomic.Int32
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prime" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		received.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	info := f.create(t, strings.Repeat("8", 24), 5000)
	cookie := f.bootstrap(t, info)
	response := f.request(t, "GET", info.Origin+"/prime", cookie, nil, nil)
	previewRead(t, response)
	response = f.request(t, "GET", info.Origin+"/side-effect", cookie, nil, nil)
	if response.StatusCode != 502 {
		t.Fatal("unknown request appeared successful", response.StatusCode)
	}
	previewRead(t, response)
	if received.Load() != 1 {
		t.Fatal("uncertain request replayed", received.Load())
	}
}

func testWSFrame(data []byte, masked bool) []byte {
	var header []byte
	switch {
	case len(data) < 126:
		header = []byte{0x82, byte(len(data))}
	case len(data) < 65536:
		header = []byte{0x82, 126, byte(len(data) >> 8), byte(len(data))}
	default:
		header = make([]byte, 10)
		header[0], header[1] = 0x82, 127
		binary.BigEndian.PutUint64(header[2:], uint64(len(data)))
	}
	if !masked {
		return append(header, data...)
	}
	header[1] |= 0x80
	mask := []byte{1, 2, 3, 4}
	header = append(header, mask...)
	for i, value := range data {
		header = append(header, value^mask[i%4])
	}
	return header
}
func readTestWSFrame(reader io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(reader, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x82 {
		return nil, fmt.Errorf("unexpected WS opcode")
	}
	size := uint64(h[1] & 127)
	if size == 126 {
		var n [2]byte
		if _, err := io.ReadFull(reader, n[:]); err != nil {
			return nil, err
		}
		size = uint64(binary.BigEndian.Uint16(n[:]))
	}
	if size == 127 {
		var n [8]byte
		if _, err := io.ReadFull(reader, n[:]); err != nil {
			return nil, err
		}
		size = binary.BigEndian.Uint64(n[:])
	}
	if size > 1<<20 {
		return nil, fmt.Errorf("fixture frame oversized")
	}
	var mask [4]byte
	if h[1]&128 != 0 {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return nil, err
		}
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	if h[1]&128 != 0 {
		for i := range data {
			data[i] ^= mask[i%4]
		}
	}
	return data, nil
}
func (f *previewFixture) websocket(t *testing.T, info PreviewGrantInfo, cookie *http.Cookie, first []byte) (net.Conn, *bufio.Reader) {
	t.Helper()
	origin, _ := url.Parse(info.Origin)
	config := f.browserTLS.Clone()
	config.ServerName = origin.Hostname()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.front.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	text := fmt.Sprintf("GET /ws HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nCookie: %s=%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", origin.Host, info.Origin, cookie.Name, cookie.Value)
	if err := writePortBytes(conn, append([]byte(text), first...)); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		_ = conn.Close()
		t.Fatal("WS upgrade failed", err)
	}
	if response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("WS handshake changed")
	}
	return conn, reader
}

func TestPreviewWebSocketCoalescedBinaryDuplexAndRevoke(t *testing.T) {
	closed := make(chan struct{})
	first := []byte{0, 255, 42}
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(closed)
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_, _ = buffered.Write(testWSFrame(first, false))
		if buffered.Flush() != nil {
			return
		}
		data, err := readTestWSFrame(buffered.Reader)
		if err != nil {
			return
		}
		if writePortBytes(conn, testWSFrame(data, false)) != nil {
			return
		}
		_, _ = io.Copy(io.Discard, buffered.Reader)
	}))
	info := f.create(t, strings.Repeat("9", 24), 5000)
	cookie := f.bootstrap(t, info)
	payload := bytes.Repeat([]byte{0, 255, 9, 7, 2}, 40000)
	conn, reader := f.websocket(t, info, cookie, testWSFrame(payload, true))
	defer conn.Close()
	if data, err := readTestWSFrame(reader); err != nil || !bytes.Equal(data, first) {
		t.Fatal("coalesced server frame lost", err)
	}
	if data, err := readTestWSFrame(reader); err != nil || !bytes.Equal(data, payload) {
		t.Fatal("coalesced client frame or binary echo lost", err)
	}
	status, _ := f.control(t, "DELETE", "/v2/sessions/"+info.SessionID+"/previews/"+info.ID, "token-a", nil)
	if status != 200 {
		t.Fatal(status)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("revoked WebSocket still open")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("application WebSocket TCP not reclaimed")
	}
	f.service.mu.Lock()
	active := f.service.inflight
	f.service.mu.Unlock()
	if active != 0 {
		t.Fatal("WebSocket copies not joined")
	}
}

func TestPreviewWebSocketSlowReaderShutdownJoinsBothDirections(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	var completed atomic.Bool
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(closed)
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		if buffered.Flush() != nil {
			return
		}
		close(started)
		frame := testWSFrame(make([]byte, 16384), false)
		for i := 0; i < 1024; i++ {
			if writePortBytes(conn, frame) != nil {
				return
			}
		}
		completed.Store(true)
	}))
	info := f.create(t, strings.Repeat("a", 24), 5000)
	cookie := f.bootstrap(t, info)
	conn, _ := f.websocket(t, info, cookie, nil)
	defer conn.Close()
	<-started
	time.Sleep(50 * time.Millisecond)
	if completed.Load() {
		t.Fatal("fixture did not create backpressure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.api.handler.Shutdown(ctx); err != nil {
		t.Fatal("preview shutdown did not join", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("slow application not closed")
	}
}
