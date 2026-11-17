package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type previewRequest struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	front   net.Conn
	writer  http.ResponseWriter
	request *http.Request
}

func (q *previewRequest) force() {
	q.mu.Lock()
	front := q.front
	q.mu.Unlock()
	if front != nil {
		_ = front.Close()
		return
	}
	controller := http.NewResponseController(q.writer)
	_ = controller.SetReadDeadline(time.Now())
	_ = controller.SetWriteDeadline(time.Now())
	if q.request.Body != nil {
		_ = q.request.Body.Close()
	}
}
func (q *previewRequest) bind(conn net.Conn) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.front = conn
	if q.ctx.Err() != nil {
		_ = conn.Close()
		return false
	}
	return true
}

func (p *previewService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Origin-Agent-Cluster", "?1")
	g, ok := p.authenticate(w, r)
	if !ok {
		return
	}
	if r.Method == "CONNECT" || r.Method == "TRACE" {
		writeJobError(w, 405, "preview_method_denied", "method unavailable", true)
		return
	}
	ws := headerToken(r.Header, "Connection", "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if r.Header.Get("Upgrade") != "" && !ws || ws && (r.Method != "GET" || r.ProtoMajor != 1 || r.ProtoMinor != 1) {
		writeJobError(w, 400, "preview_upgrade_denied", "only HTTP/1.1 WebSocket upgrade is supported", true)
		return
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") && (ws || r.Method != "GET" && r.Method != "HEAD") {
		writeJobError(w, 403, "preview_origin_denied", "cross-site preview request denied", true)
		return
	}
	if r.ContentLength > previewRequestBytes {
		writeJobError(w, 413, "preview_request_too_large", "preview request body exceeds limit", true)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	q := &previewRequest{ctx: ctx, cancel: cancel, writer: w, request: r}
	p.mu.Lock()
	if p.closed || g.info.Status != "active" || !time.Now().Before(g.info.ExpiresAt) {
		p.mu.Unlock()
		cancel()
		writeJobError(w, 410, "preview_expired", "preview unavailable", true)
		return
	}
	if p.inflight >= previewGlobalRequestLimit || len(g.requests) >= previewRequestLimit {
		p.mu.Unlock()
		cancel()
		writeJobError(w, 429, "preview_quota", "preview request limit reached", true)
		return
	}
	g.requests[q] = struct{}{}
	p.inflight++
	p.handlers.Add(1)
	p.mu.Unlock()
	stopGrant := context.AfterFunc(g.ctx, cancel)
	forced := make(chan struct{})
	stopForce := context.AfterFunc(ctx, func() { defer close(forced); q.force() })
	defer func() {
		stopGrant()
		if !stopForce() {
			<-forced
		}
		cancel()
		p.mu.Lock()
		delete(g.requests, q)
		p.inflight--
		p.mu.Unlock()
		p.handlers.Done()
	}()
	// HTTP/1 uploads and response streams may make progress concurrently.
	_ = http.NewResponseController(w).EnableFullDuplex()
	request := r.Clone(ctx)
	request.RequestURI = ""
	request.TLS = nil
	request.RemoteAddr = ""
	request.URL.Scheme = "http"
	request.URL.Host = "guest.invalid"
	request.Host = g.host
	request.Close = false
	request.GetBody = nil
	if r.Body == nil || r.Body == http.NoBody {
		request.Body = http.NoBody
	} else {
		request.Body = http.MaxBytesReader(w, r.Body, previewRequestBytes)
	}
	cleanPreviewRequest(request, p.api.auth, g.host)
	if ws {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
	}
	var attempts atomic.Int32
	upstreamContext, stopUpstream := context.WithCancel(ctx)
	defer stopUpstream()
	trace := &httptrace.ClientTrace{GetConn: func(string) {
		if attempts.Add(1) > 1 {
			stopUpstream()
		}
	}, GotConn: func(info httptrace.GotConnInfo) {
		if attempts.Load() > 1 {
			_ = info.Conn.Close()
		}
	}}
	request = request.WithContext(httptrace.WithClientTrace(upstreamContext, trace))
	response, err := g.transport.RoundTrip(request)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var portError *PortRequestError
		if errors.As(err, &tooLarge) {
			writeJobError(w, 413, "preview_request_too_large", "preview request body exceeds limit", true)
		} else if errors.As(err, &portError) {
			writePortError(w, portError)
		} else {
			writeJobError(w, 502, "preview_upstream_unavailable", "preview application unavailable", true)
		}
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 101 {
		if !ws || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || !headerToken(response.Header, "Connection", "upgrade") {
			writeJobError(w, 502, "preview_bad_upgrade", "invalid application upgrade", true)
			return
		}
		p.webSocket(q, w, response)
		return
	}
	cleanPreviewResponse(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Origin-Agent-Cluster", "?1")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	trailers := []string{}
	for key := range response.Trailer {
		if safePreviewTrailer(key) {
			trailers = append(trailers, key)
		}
	}
	if len(trailers) > 0 {
		w.Header().Set("Trailer", strings.Join(trailers, ", "))
	}
	w.WriteHeader(response.StatusCode)
	if r.Method == "HEAD" {
		return
	}
	controller := http.NewResponseController(w)
	buffer := make([]byte, portDataLimit)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			_ = controller.SetWriteDeadline(time.Now().Add(2 * time.Second))
			written, writeErr := w.Write(buffer[:n])
			if writeErr != nil || written != n {
				return
			}
			if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
				return
			}
			_ = controller.SetWriteDeadline(time.Time{})
		}
		if readErr != nil {
			if readErr != io.EOF {
				panic(http.ErrAbortHandler)
			}
			break
		}
		if ctx.Err() != nil {
			return
		}
	}
	for _, key := range trailers {
		w.Header()[http.TrailerPrefix+key] = response.Trailer.Values(key)
	}
}

func (p *previewService) webSocket(q *previewRequest, w http.ResponseWriter, response *http.Response) {
	backend, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		writeJobError(w, 502, "preview_bad_upgrade", "application upgrade is not duplex", true)
		return
	}
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if !q.bind(conn) {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	cleanPreviewResponse(response.Header)
	response.Header.Set("Connection", "Upgrade")
	response.Header.Set("Upgrade", "websocket")
	response.Header.Set("Cache-Control", "no-store")
	response.Header.Set("Referrer-Policy", "no-referrer")
	response.Header.Set("Origin-Agent-Cluster", "?1")
	response.Header.Set("X-Content-Type-Options", "nosniff")
	response.Body = nil
	if response.Write(buffered) != nil || buffered.Flush() != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	finished := make(chan struct{}, 2)
	go func() {
		defer func() { finished <- struct{}{} }()
		_, _ = io.CopyBuffer(backend, buffered.Reader, make([]byte, portDataLimit))
	}()
	go func() {
		defer func() { finished <- struct{}{} }()
		_, _ = io.CopyBuffer(conn, backend, make([]byte, portDataLimit))
	}()
	<-finished
	_ = backend.Close()
	_ = conn.Close()
	<-finished
}

func headerToken(header http.Header, key, want string) bool {
	for _, line := range header.Values(key) {
		for _, part := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}
func removePreviewHop(header http.Header) {
	for _, line := range header.Values("Connection") {
		for _, part := range strings.Split(line, ",") {
			header.Del(strings.TrimSpace(part))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(key)
	}
}
func cleanPreviewRequest(request *http.Request, auth *Authenticator, host string) {
	removePreviewHop(request.Header)
	for _, value := range request.Header.Values("Authorization") {
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if _, control := auth.Authenticate("Bearer " + parts[1]); control {
				request.Header.Del("Authorization")
				break
			}
		}
	}
	for key := range request.Header {
		lower := strings.ToLower(key)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-osv-") {
			request.Header.Del(key)
		}
	}
	cookies := request.Cookies()
	request.Header.Del("Cookie")
	for _, cookie := range cookies {
		if !strings.EqualFold(cookie.Name, previewCookie) {
			request.AddCookie(cookie)
		}
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", host)
	for key := range request.Trailer {
		if !safePreviewTrailer(key) {
			request.Trailer.Del(key)
		}
	}
}
func cleanPreviewResponse(header http.Header) {
	cookies := header.Values("Set-Cookie")
	removePreviewHop(header)
	header.Del("Set-Cookie")
	for _, raw := range cookies {
		parsed := (&http.Response{Header: http.Header{"Set-Cookie": {raw}}}).Cookies()
		if len(parsed) != 1 || parsed[0].Domain != "" || strings.EqualFold(parsed[0].Name, previewCookie) {
			continue
		}
		domain := false
		for _, attribute := range strings.Split(raw, ";")[1:] {
			name, _, _ := strings.Cut(attribute, "=")
			if strings.EqualFold(strings.TrimSpace(name), "domain") {
				domain = true
			}
		}
		if !domain {
			header.Add("Set-Cookie", raw)
		}
	}
	for key := range header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "access-control-") || strings.HasPrefix(lower, "x-osv-") {
			header.Del(key)
		}
	}
}
func safePreviewTrailer(key string) bool {
	lower := strings.ToLower(key)
	if strings.HasPrefix(lower, "x-osv-") || strings.HasPrefix(lower, "access-control-") {
		return false
	}
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "connection", "content-length", "transfer-encoding", "trailer", "host", "upgrade":
		return false
	}
	return true
}
