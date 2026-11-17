package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const guestProxyUpgrade = "osv-guest-proxy/1"
const guestProxyHeaderLimit = 16 << 10
const guestProxyHelloLimit = 16 << 10
const inferenceProxyGlobalHeadroom = 16
const inferenceProxyTenantHeadroom = 4

type egressPeerKey struct{}

// This endpoint trusts only the launcher's kernel-verified UID, never a UID or
// tenant asserted by a guest. Ordinary fetch still requires its Bearer token.
func (s *EgressServer) guestProxyUpgrade(w http.ResponseWriter, r *http.Request) {
	var tracked net.Conn
	// This is the last deferred action: shutdown also waits for the audit and
	// slot release, not just the end of the socket relay.
	defer func() {
		if tracked != nil {
			s.unregisterGuestProxy(tracked)
		}
	}()
	uid, known := r.Context().Value(egressPeerKey{}).(uint32)
	if !s.GuestProxy || !known || uid != 0 {
		writeJobError(w, 403, "egress_proxy_disabled", "guest proxy requires a trusted launcher", true)
		return
	}
	if r.Method != "POST" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		r.Header.Get("Upgrade") != guestProxyUpgrade || !strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
		writeJobError(w, 400, "egress_proxy_request", "invalid guest proxy upgrade", true)
		return
	}
	tenantID, vmID, leaseID := r.Header.Get("X-OSV-Tenant"), r.Header.Get("X-OSV-VM"), r.Header.Get("X-OSV-Lease")
	taskID, inferenceGrant := r.Header.Get("X-OSV-Task"), r.Header.Get("X-OSV-Inference")
	inferencePolicy := r.Header.Get("X-OSV-Inference-Policy")
	if !safeTenantID(tenantID) || !canonicalJobID(vmID) || !canonicalJobID(leaseID) {
		writeJobError(w, 400, "egress_proxy_identity", "invalid guest proxy identity", true)
		return
	}
	if inferenceGrant != "" && (inferenceGrant != "remote-infer-v1" || !canonicalJobID(taskID) || !validSHA256Hex(inferencePolicy)) || inferenceGrant == "" && inferencePolicy != "" {
		writeJobError(w, 400, "egress_proxy_identity", "invalid guest inference binding", true)
		return
	}
	var tenant *tenantRuntime
	for _, candidate := range s.auth.tenants {
		if candidate.policy.ID == tenantID {
			tenant = candidate
			break
		}
	}
	if tenant == nil || tenant.egress == nil {
		writeJobError(w, 403, "egress_disabled", "egress disabled for tenant", true)
		return
	}
	if inferenceGrant != "" && (s.inference == nil || inferencePolicy != inferenceTenantPolicyDigest(tenant)) {
		writeJobError(w, 503, "inference_policy_unavailable", "guest inference policy unavailable", true)
		return
	}
	if s.audit.Err() != nil {
		writeJobError(w, 503, "egress_audit", "network audit unavailable", true)
		return
	}
	requestID, err := randomID()
	if err != nil {
		writeJobError(w, 503, "unavailable", "network identity unavailable", true)
		return
	}
	record := EgressAuditEvent{Event: "net.deny", RequestID: requestID, Tenant: tenantID, VMID: vmID, LeaseID: leaseID}
	started := time.Now()
	defer func() {
		record.DurationMS = time.Since(started).Milliseconds()
		// CONNECT is streaming: completion cannot retract bytes already sent.
		// AuditLog keeps failures sticky and rejects subsequent admissions.
		_ = s.audit.AppendNetwork(record)
	}()
	var release func()
	if inferenceGrant == "remote-infer-v1" {
		release, err = s.acquireInferenceProxyIngress(tenant)
	} else {
		release, err = s.acquireProxySlot(tenant)
	}
	if err != nil {
		failure := err.(*EgressError)
		record.Code = failure.Code
		writeJobError(w, failure.Status, failure.Code, "network proxy admission rejected", true)
		return
	}
	defer release()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		record.Code = "egress_proxy_transport"
		writeJobError(w, 503, record.Code, "proxy transport unavailable", true)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		record.Code = "egress_proxy_transport"
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(tenant.egress.policy.TimeoutMS)*time.Millisecond)
	defer cancel()
	if !s.registerGuestProxy(conn, cancel) {
		record.Code = "egress_unavailable"
		return
	}
	tracked = conn
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", guestProxyUpgrade); err != nil || buffered.Flush() != nil {
		record.Code = "egress_proxy_transport"
		return
	}
	// Hijack's reader still wraps net/http.connReader, whose read-error hook
	// cancels the outer request even after hijack. Preserve its buffered bytes
	// and detach before guest EOF/deadline monitoring can touch that hook.
	pending, _ := buffered.Reader.Peek(buffered.Reader.Buffered())
	prefix := append([]byte(nil), pending...)
	_, _ = buffered.Reader.Discard(len(prefix))
	detached := bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), conn))
	request, reader, err := readGuestProxyRequest(detached)
	if err != nil {
		record.Code = "egress_proxy_request"
		writeGuestProxyError(conn, egressError(400, record.Code))
		return
	}
	if len(request.Method) <= 16 {
		record.Method = request.Method
	}
	if reservedInferenceRequest(request) {
		record.TaskID = taskID
		record.Status, record.Code = s.serveInferenceGuest(ctx, conn, reader, request,
			inferenceBinding{Tenant: tenantID, TaskID: taskID, VMID: vmID, LeaseID: leaseID}, inferenceGrant == "remote-infer-v1")
		if record.Code == "" {
			record.Event = "net.complete"
		}
		return
	}
	if inferenceGrant == "remote-infer-v1" {
		// A v7 transport slot never authorizes ordinary outbound work.
		releaseWork, workErr := s.acquireProxyCapacity(tenant)
		if workErr != nil {
			failure := workErr.(*EgressError)
			record.Code = failure.Code
			writeGuestProxyError(conn, failure)
			return
		}
		defer releaseWork()
	}
	allow := func(origin, method, ip string, hop int) error {
		event := record
		event.Event, event.Origin, event.Method, event.IP, event.Hop = "net.allow", origin, method, ip, hop
		if s.audit.AppendNetwork(event) != nil {
			return egressError(503, "egress_audit")
		}
		return nil
	}
	admit := record
	admit.Event = "net.admit"
	if s.audit.AppendNetwork(admit) != nil {
		record.Code = "egress_audit"
		writeGuestProxyError(conn, egressError(503, record.Code))
		return
	}
	if request.Method == http.MethodConnect {
		err = s.connectGuestProxy(ctx, conn, reader, request, tenant.egress, &record, allow)
	} else {
		err = s.fetchGuestProxy(ctx, conn, request, tenant.egress, &record, allow)
	}
	if err != nil {
		var failure *EgressError
		if !errors.As(err, &failure) {
			failure = egressErrorFor(ctx, "egress_proxy_transport").(*EgressError)
		}
		record.Code = failure.Code
		// After CONNECT's 200, errors must close TLS, never inject plaintext.
		if record.Status != 200 || request.Method != http.MethodConnect {
			writeGuestProxyError(conn, failure)
		}
		return
	}
	record.Event = "net.complete"
}

func (s *EgressServer) acquireProxySlot(tenant *tenantRuntime) (func(), error) {
	if tenant.consumeRequestToken() != nil {
		return nil, egressError(429, "egress_rate_limit")
	}
	return s.acquireProxyCapacity(tenant)
}

func (s *EgressServer) acquireProxyCapacity(tenant *tenantRuntime) (func(), error) {
	select {
	case tenant.netSem <- struct{}{}:
	default:
		return nil, egressError(429, "egress_busy")
	}
	select {
	case s.slots <- struct{}{}:
	default:
		<-tenant.netSem
		return nil, egressError(429, "egress_busy")
	}
	return func() { <-s.slots; <-tenant.netSem }, nil
}

// Only authenticated v7 root grants use this bounded transport lane. Reserve
// observation headroom beyond the maximum model work, without allowing slow
// headers or ordinary egress to consume unbounded connections. Rate admission
// happens once here; work capacity is acquired only after parsing the route.
func (s *EgressServer) acquireInferenceProxyIngress(tenant *tenantRuntime) (func(), error) {
	if tenant.consumeRequestToken() != nil {
		return nil, egressError(429, "egress_rate_limit")
	}
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.proxyClosing {
		return nil, egressError(503, "egress_unavailable")
	}
	if s.proxyInferenceIngress >= cap(s.slots)+inferenceProxyGlobalHeadroom || s.proxyInferenceTenants[tenant] >= cap(tenant.netSem)+inferenceProxyTenantHeadroom {
		return nil, egressError(429, "egress_busy")
	}
	if s.proxyInferenceTenants == nil {
		s.proxyInferenceTenants = make(map[*tenantRuntime]int)
	}
	s.proxyInferenceIngress++
	s.proxyInferenceTenants[tenant]++
	return func() {
		s.proxyMu.Lock()
		defer s.proxyMu.Unlock()
		s.proxyInferenceIngress--
		s.proxyInferenceTenants[tenant]--
		if s.proxyInferenceTenants[tenant] == 0 {
			delete(s.proxyInferenceTenants, tenant)
		}
	}, nil
}

func (s *EgressServer) registerGuestProxy(conn net.Conn, cancel context.CancelFunc) bool {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.proxyClosing {
		return false
	}
	if s.proxyConnections == nil {
		s.proxyConnections = make(map[net.Conn]context.CancelFunc)
	}
	s.proxyConnections[conn] = cancel
	s.proxyWG.Add(1)
	return true
}
func (s *EgressServer) unregisterGuestProxy(conn net.Conn) {
	s.proxyMu.Lock()
	delete(s.proxyConnections, conn)
	s.proxyMu.Unlock()
	s.proxyWG.Done()
}
func (s *EgressServer) closeGuestProxies() {
	s.proxyMu.Lock()
	s.proxyClosing = true
	connections := make([]net.Conn, 0, len(s.proxyConnections))
	for conn, cancel := range s.proxyConnections {
		cancel()
		connections = append(connections, conn)
	}
	s.proxyMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	s.proxyWG.Wait()
}

func readGuestProxyRequest(source *bufio.Reader) (*http.Request, *bufio.Reader, error) {
	var header []byte
	for {
		line, err := source.ReadSlice('\n')
		if len(header)+len(line) > guestProxyHeaderLimit {
			return nil, nil, errors.New("proxy headers exceed limit")
		}
		header = append(header, line...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil || len(header) < 2 || header[len(header)-2] != '\r' {
			return nil, nil, errors.New("invalid proxy header framing")
		}
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			break
		}
	}
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(header), source))
	request, err := http.ReadRequest(reader)
	if err != nil || request.ProtoMajor != 1 || request.ProtoMinor > 1 || len(request.Header) > 32 || request.Header.Get("Upgrade") != "" {
		return nil, nil, errors.New("invalid proxy request")
	}
	return request, reader, nil
}

func (s *EgressServer) fetchGuestProxy(ctx context.Context, conn net.Conn, request *http.Request, rules *egressRules, record *EgressAuditEvent, allow func(string, string, string, int) error) error {
	// HTTPS must use CONNECT so certificate verification stays end-to-end.
	if request.URL.Scheme != "http" || request.URL.Host == "" || request.ContentLength > int64(rules.policy.MaxRequestBytes) || request.Header.Get("Expect") != "" {
		return egressError(400, "egress_proxy_request")
	}
	u, origin, err := egressURL(request.URL.String())
	if err != nil {
		return egressError(400, "egress_url")
	}
	record.Origin = origin
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(rules.policy.MaxRequestBytes)+1))
	if err != nil || len(body) > rules.policy.MaxRequestBytes {
		return egressError(400, "egress_request_limit")
	}
	// One request per connection. Once its body is read, further bytes/EOF mean
	// this client cannot receive this response; cancel the upstream promptly.
	ctx, cancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var next [1]byte
		_, _ = conn.Read(next[:])
		cancel()
	}()
	defer func() {
		_ = conn.SetReadDeadline(time.Now())
		<-watchDone
		cancel()
	}()
	headers := make(map[string]string)
	hopHeaders := map[string]bool{}
	for _, value := range request.Header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			hopHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range request.Header {
		if egressHeaderBlocked(name) || hopHeaders[name] {
			continue
		}
		if len(values) != 1 {
			return egressError(400, "egress_headers")
		}
		headers[name] = values[0]
	}
	result, err := s.engine.fetch(ctx, NetworkFetchRequest{URL: u.String(), Method: request.Method, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(body)}, rules, allow)
	record.RequestBytes, record.ResponseBytes = result.RequestBytes, result.ResponseBytes
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(result.BodyBase64)
	if err != nil {
		return egressError(502, "egress_protocol")
	}
	record.Status = result.Status
	completion := *record
	completion.Event = "net.response"
	if s.audit.AppendNetwork(completion) != nil {
		return egressError(503, "egress_audit")
	}
	response := &http.Response{StatusCode: result.Status, ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header(result.Headers), Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Close: true, Request: request}
	if request.Method == http.MethodHead {
		// Fetch omits upstream framing headers; do not invent Content-Length: 0
		// for a representation whose HEAD response carries no body.
		response.ContentLength = -1
	}
	return response.Write(conn)
}

func writeGuestProxyError(writer io.Writer, err error) {
	var failure *EgressError
	if !errors.As(err, &failure) {
		failure = &EgressError{502, "egress_proxy_transport"}
	}
	message := failure.Code + "\n"
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", failure.Status, http.StatusText(failure.Status), len(message), message)
}

func guestConnectURL(request *http.Request) (*url.URL, string, error) {
	host, port, err := net.SplitHostPort(request.RequestURI)
	if err != nil || host == "" || port == "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		return nil, "", egressError(400, "egress_connect_authority")
	}
	u, origin, err := egressURL("https://" + request.RequestURI)
	if err != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return nil, "", egressError(400, "egress_connect_authority")
	}
	return u, origin, nil
}

// Read only the genuine ClientHello using Go's maintained TLS parser. Writes
// are discarded: the parser's intentional abort must not inject a TLS alert.
type guestHelloConn struct {
	net.Conn
	reader io.Reader
	data   bytes.Buffer
}

func (c *guestHelloConn) Read(data []byte) (int, error) {
	remaining := guestProxyHelloLimit - c.data.Len()
	if remaining <= 0 {
		return 0, errors.New("ClientHello exceeds limit")
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	n, err := c.reader.Read(data)
	_, _ = c.data.Write(data[:n])
	return n, err
}
func (c *guestHelloConn) Write(data []byte) (int, error) { return len(data), nil }

func readGuestClientHello(ctx context.Context, conn net.Conn, reader io.Reader, host string) ([]byte, error) {
	capture := &guestHelloConn{Conn: conn, reader: reader}
	accepted := false
	stopParsing := errors.New("ClientHello inspection complete")
	inspector := tls.Server(capture, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		supported := false
		for _, version := range info.SupportedVersions {
			supported = supported || version == tls.VersionTLS12 || version == tls.VersionTLS13
		}
		if _, err := netip.ParseAddr(host); err == nil {
			accepted = supported && info.ServerName == ""
		} else {
			accepted = supported && strings.EqualFold(info.ServerName, host)
		}
		return nil, stopParsing
	}})
	err := inspector.HandshakeContext(ctx)
	if !errors.Is(err, stopParsing) || !accepted {
		return nil, egressError(403, "egress_sni_denied")
	}
	return capture.data.Bytes(), nil
}

func (s *EgressServer) connectGuestProxy(ctx context.Context, conn net.Conn, reader *bufio.Reader, request *http.Request, rules *egressRules, record *EgressAuditEvent, allow func(string, string, string, int) error) error {
	u, origin, err := guestConnectURL(request)
	if err != nil {
		return err
	}
	record.Origin = origin
	addresses, err := s.engine.approvedAddresses(ctx, u, origin, rules)
	if err != nil {
		return err
	}
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	record.Status = 200
	helloCtx, stopHello := context.WithTimeout(ctx, 3*time.Second)
	helloDeadline, _ := helloCtx.Deadline()
	_ = conn.SetReadDeadline(helloDeadline)
	hello, err := readGuestClientHello(helloCtx, conn, reader, u.Hostname())
	stopHello()
	if err != nil {
		return err
	}
	if len(hello) > rules.policy.MaxRequestBytes {
		return egressError(403, "egress_request_limit")
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	var upstream net.Conn
	for _, ip := range addresses {
		if err = allow(origin, "CONNECT", ip.Unmap().String(), 0); err != nil {
			return err
		}
		upstream, err = s.engine.dial(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), u.Port()))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return egressErrorFor(ctx, "egress_upstream")
		}
	}
	if upstream == nil {
		return egressErrorFor(ctx, "egress_upstream")
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()
	if _, err = upstream.Write(hello); err != nil {
		return egressErrorFor(ctx, "egress_upstream")
	}
	record.RequestBytes = len(hello)
	sent, received, err := relayGuestTunnel(conn, reader, upstream, int64(rules.policy.MaxRequestBytes-len(hello)), int64(rules.policy.MaxResponseBytes))
	record.RequestBytes += int(sent)
	record.ResponseBytes = int(received)
	return err
}

// EOF/error/limit in either direction ends this finite tunnel. Both copies
// finish before their slot is released; no goroutine can retain an upstream.
func relayGuestTunnel(client net.Conn, reader io.Reader, upstream net.Conn, sendLimit, receiveLimit int64) (int64, int64, error) {
	type copyResult struct {
		sent bool
		n    int64
		err  error
	}
	results := make(chan copyResult, 2)
	var closeBoth sync.Once
	copyOne := func(sent bool, writer io.Writer, source io.Reader, limit int64) {
		n, err := io.Copy(writer, io.LimitReader(source, limit))
		if err == nil && n == limit {
			err = egressError(502, "egress_tunnel_limit")
		}
		closeBoth.Do(func() { _ = client.Close(); _ = upstream.Close() })
		results <- copyResult{sent, n, err}
	}
	go copyOne(true, upstream, reader, sendLimit)
	go copyOne(false, client, upstream, receiveLimit)
	first, second := <-results, <-results
	sent, received := first.n, second.n
	if !first.sent {
		sent, received = received, sent
	}
	// The second error commonly results from closing the other direction.
	return sent, received, first.err
}
