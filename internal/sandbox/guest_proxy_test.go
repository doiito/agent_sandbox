package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const proxyTestVM = "0123456789abcdef01234567"
const proxyTestLease = "abcdef0123456789abcdef01"

func newGuestProxyTestServer(t *testing.T, policy EgressPolicy) (*EgressServer, *tenantRuntime, *egressMemoryAudit) {
	t.Helper()
	auth, tenant := egressTestAuth(t, policy)
	audit := &egressMemoryAudit{}
	server, err := NewEgressServer(auth, audit, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	server.GuestProxy = true
	return server, tenant, audit
}

func guestProxyUpgradeRequest() *http.Request {
	r := httptest.NewRequest("POST", "http://egress.invalid/v1/guest-proxy", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", guestProxyUpgrade)
	r.Header.Set("X-OSV-Tenant", "egress-a")
	r.Header.Set("X-OSV-VM", proxyTestVM)
	r.Header.Set("X-OSV-Lease", proxyTestLease)
	return r
}

func openGuestProxyTestConn(t *testing.T, path string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := guestProxyUpgradeRequest()
	if err := request.Write(conn); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		response.Body.Close()
		conn.Close()
	}
	return conn, reader, response.StatusCode
}

func requireGuestProxyRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("trusted launcher integration requires kernel UID 0")
	}
}

func TestGuestProxyTrustBoundary(t *testing.T) {
	server, _, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{"https://example.com"}})
	for _, uid := range []int{-1, 1, 10000} {
		r := guestProxyUpgradeRequest()
		if uid >= 0 {
			r = r.WithContext(context.WithValue(r.Context(), egressPeerKey{}, uint32(uid)))
		}
		r.Header.Set("X-OSV-Peer-UID", "0")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, r)
		if response.Code != 403 {
			t.Fatal("caller asserted tenant/root accepted", uid, response.Code)
		}
	}
	for _, name := range []string{"X-OSV-Tenant", "X-OSV-VM", "X-OSV-Lease", "Upgrade"} {
		r := guestProxyUpgradeRequest()
		r = r.WithContext(context.WithValue(r.Context(), egressPeerKey{}, uint32(0)))
		r.Header.Set(name, "untrusted")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, r)
		if response.Code < 400 {
			t.Fatal("invalid identity accepted", name, response.Code)
		}
	}
	r := guestProxyUpgradeRequest().WithContext(context.WithValue(context.Background(), egressPeerKey{}, uint32(0)))
	r.Header.Set("X-OSV-Tenant", "egress-b")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, r)
	if response.Code != 403 {
		t.Fatal("disabled tenant gained proxy", response.Code)
	}
	server.GuestProxy = false
	r = guestProxyUpgradeRequest().WithContext(context.WithValue(context.Background(), egressPeerKey{}, uint32(0)))
	response = httptest.NewRecorder()
	server.ServeHTTP(response, r)
	if response.Code != 403 {
		t.Fatal("proxy enabled implicitly")
	}
	response = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "http://egress.invalid/v1/fetch", strings.NewReader("{}"))
	r = r.WithContext(context.WithValue(r.Context(), egressPeerKey{}, uint32(0)))
	server.ServeHTTP(response, r)
	if response.Code != 401 {
		t.Fatal("root guest identity bypassed ordinary Bearer authentication")
	}
}

func TestGuestProxyHTTPRealSocket(t *testing.T) {
	requireGuestProxyRoot(t)
	body := []byte{'a', 0, 255, 'z'}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || !bytes.Equal(data, body) || r.Header.Get("X-Test") != "yes" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("proxy changed POST or forwarded hop credentials", r.Method, r.Header, data)
		}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(201)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	server, tenant, audit := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	path, cancel, done := startEgressTestSocket(t, server)
	conn, reader, status := openGuestProxyTestConn(t, path)
	if status != 101 {
		t.Fatal(status)
	}
	_, _ = fmt.Fprintf(conn, "POST %s/private?secret=do-not-audit HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: X-Hop\r\nX-Hop: do-not-forward\r\nProxy-Authorization: secret\r\nX-Test: yes\r\nContent-Length: %d\r\n\r\n", upstream.URL, len(body))
	_, _ = conn.Write(body)
	response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	conn.Close()
	if err != nil || response.StatusCode != 201 || !response.Close || !bytes.Equal(data, body) || response.Header.Get("X-Upstream") != "yes" {
		t.Fatal(response.StatusCode, data, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(tenant.netSem) != 0 || len(server.slots) != 0 {
		t.Fatal("network slots leaked")
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	seen := map[string]bool{}
	for _, event := range audit.events {
		seen[event.Event] = true
		if event.Tenant != "egress-a" || event.VMID != proxyTestVM || event.LeaseID != proxyTestLease || strings.Contains(event.Origin, "secret") {
			t.Fatal("proxy identity/audit binding lost", event)
		}
	}
	for _, event := range []string{"net.admit", "net.allow", "net.response", "net.complete"} {
		if !seen[event] {
			t.Fatal("missing audit", event)
		}
	}
}

func TestGuestProxyHTTPSRealTLS(t *testing.T) {
	requireGuestProxyRoot(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "encrypted end-to-end")
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	target := "https://example.com:" + parsed.Port()
	server, _, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{target}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	server.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	path, cancel, done := startEgressTestSocket(t, server)
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	proxyURL, _ := url.Parse("http://bridge.invalid:3128")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(context.Context, string, string) (net.Conn, error) {
		conn, _, status := openGuestProxyTestConn(t, path)
		if status != 101 {
			return nil, fmt.Errorf("proxy upgrade status %d", status)
		}
		return conn, nil
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(target + "/")
	if err != nil {
		t.Fatal("real end-to-end CONNECT TLS", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	transport.CloseIdleConnections()
	if err != nil || string(body) != "encrypted end-to-end" {
		t.Fatal(string(body), err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGuestProxyCONNECTPolicyBeforeDial(t *testing.T) {
	requireGuestProxyRoot(t)
	for _, tc := range []struct {
		name, authority, serverName, raw string
		addresses                        []netip.Addr
		status                           int
	}{
		{name: "wrong port", authority: "example.com:444", status: 403},
		{name: "metadata", authority: "169.254.169.254:443", status: 403},
		{name: "missing port", authority: "example.com", status: 400},
		{name: "mixed DNS", authority: "example.com:443", status: 403, addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}},
		{name: "SNI mismatch", authority: "example.com:443", status: 200, serverName: "elsewhere.example"},
		{name: "missing SNI", authority: "example.com:443", status: 200},
		{name: "not TLS", authority: "example.com:443", status: 200, raw: "GET / HTTP/1.1\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{"https://example.com"}})
			var dials atomic.Int32
			server.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				if tc.addresses != nil {
					return tc.addresses, nil
				}
				return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
			}
			server.engine.dial = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("must not dial")
			}
			path, cancel, done := startEgressTestSocket(t, server)
			conn, reader, status := openGuestProxyTestConn(t, path)
			if status != 101 {
				t.Fatal(status)
			}
			_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tc.authority, tc.authority)
			response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil || response.StatusCode != tc.status {
				t.Fatal(response, err)
			}
			if tc.status == 200 {
				if tc.raw != "" {
					_, _ = io.WriteString(conn, tc.raw)
					var data [1]byte
					if _, err := conn.Read(data[:]); err == nil {
						t.Fatal("non-TLS accepted")
					}
				} else {
					client := tls.Client(conn, &tls.Config{ServerName: tc.serverName, MinVersion: tls.VersionTLS12})
					if client.Handshake() == nil {
						t.Fatal("wrong SNI accepted")
					}
				}
			}
			conn.Close()
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if dials.Load() != 0 {
				t.Fatal("policy/SNI rejection dialed upstream")
			}
		})
	}
}

func TestGuestProxyHeaderAndAuthorityLimits(t *testing.T) {
	for _, raw := range []string{
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nLong: " + strings.Repeat("a", guestProxyHeaderLimit) + "\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\nHost: example.com\n\n",
		"GET http://example.com/ HTTP/2.0\r\nHost: example.com\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n",
	} {
		if _, _, err := readGuestProxyRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Fatal("unbounded/unsupported framing accepted")
		}
	}
	for _, authority := range []string{"example.com", "example.com:443/path", "example.com:443?query", "user@example.com:443", "[::1%eth0]:443", "example.com:0", "example.com:65536"} {
		if _, _, err := guestConnectURL(&http.Request{RequestURI: authority}); err == nil {
			t.Fatal("invalid CONNECT", authority)
		}
	}
}

func TestGuestProxyAdmissionAndShutdown(t *testing.T) {
	requireGuestProxyRoot(t)
	server, tenant, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{"https://example.com"}, MaxConcurrent: 1, TimeoutMS: 30000})
	path, cancel, done := startEgressTestSocket(t, server)
	first, _, status := openGuestProxyTestConn(t, path)
	if status != 101 {
		t.Fatal(status)
	}
	defer first.Close()
	_, _, status = openGuestProxyTestConn(t, path)
	if status != 429 {
		t.Fatal("unbounded connections", status)
	}
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown failed to close hijacked proxy")
	}
	if time.Since(started) > 2*time.Second || len(tenant.netSem) != 0 || len(server.slots) != 0 {
		t.Fatal("shutdown leaked slots")
	}
}

func TestGuestProxyHTTPClientEOFCancelsUpstream(t *testing.T) {
	requireGuestProxyRoot(t)
	started, stopped := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) }))
	defer upstream.Close()
	server, _, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.0/8"}, TimeoutMS: 30000})
	path, cancel, done := startEgressTestSocket(t, server)
	conn, _, status := openGuestProxyTestConn(t, path)
	if status != 101 {
		t.Fatal(status)
	}
	_, _ = fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: ignored\r\n\r\n", upstream.URL)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never started")
	}
	conn.Close()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("client EOF retained upstream")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGuestProxyBoundedHTTPAndAuditFailure(t *testing.T) {
	requireGuestProxyRoot(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, strings.Repeat("x", 65))
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		name, method, extra string
		failAt, status      int
	}{
		{name: "body bound", method: "POST", extra: "Content-Length: 65\r\n", status: 400},
		{name: "response bound", method: "GET", status: 502},
		{name: "audit before dial", method: "GET", failAt: 2, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls.Load()
			server, tenant, audit := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.0/8"}, MaxRequestBytes: 64, MaxResponseBytes: 64})
			audit.failAt = tc.failAt
			path, cancel, done := startEgressTestSocket(t, server)
			conn, reader, status := openGuestProxyTestConn(t, path)
			if status != 101 {
				t.Fatal(status)
			}
			_, _ = fmt.Fprintf(conn, "%s %s/ HTTP/1.1\r\nHost: ignored\r\n%s\r\n", tc.method, upstream.URL, tc.extra)
			response, err := http.ReadResponse(reader, &http.Request{Method: tc.method})
			if err != nil || response.StatusCode != tc.status {
				t.Fatal(response, err)
			}
			conn.Close()
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if tc.name != "response bound" && calls.Load() != before {
				t.Fatal("rejected request reached upstream")
			}
			if len(tenant.netSem) != 0 || len(server.slots) != 0 {
				t.Fatal("failed request leaked network slots")
			}
		})
	}
}

func TestGuestProxyCONNECTClientEOFAndServiceStop(t *testing.T) {
	requireGuestProxyRoot(t)
	for _, stopService := range []bool{false, true} {
		t.Run(fmt.Sprint("service-stop=", stopService), func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) }))
			defer upstream.Close()
			parsed, _ := url.Parse(upstream.URL)
			server, tenant, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.0/8"}, TimeoutMS: 30000})
			path, cancel, done := startEgressTestSocket(t, server)
			conn, reader, status := openGuestProxyTestConn(t, path)
			if status != 101 {
				t.Fatal(status)
			}
			_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host, parsed.Host)
			response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil || response.StatusCode != 200 {
				t.Fatal(response, err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(upstream.Certificate())
			client := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12})
			if err := client.Handshake(); err != nil {
				t.Fatal("literal IP empty-SNI TLS", err)
			}
			_, _ = io.WriteString(client, "GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("CONNECT never reached TLS upstream")
			}
			if stopService {
				cancel()
			} else {
				conn.Close()
			}
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				t.Fatal("CONNECT retained upstream on EOF/shutdown")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if len(tenant.netSem) != 0 || len(server.slots) != 0 {
				t.Fatal("CONNECT retained network slots")
			}
		})
	}
}

func TestGuestProxyTunnelByteLimits(t *testing.T) {
	for _, send := range []bool{true, false} {
		client, clientPeer := net.Pipe()
		upstream, upstreamPeer := net.Pipe()
		defer clientPeer.Close()
		defer upstreamPeer.Close()
		finished := make(chan error, 1)
		go func() {
			sent, received, err := relayGuestTunnel(client, client, upstream, 16, 16)
			if sent > 16 || received > 16 {
				err = errors.New("exceeded tunnel byte bound")
			}
			finished <- err
		}()
		if send {
			go func() { _, _ = clientPeer.Write(bytes.Repeat([]byte{1}, 32)) }()
			_, _ = io.Copy(io.Discard, upstreamPeer)
		} else {
			go func() { _, _ = upstreamPeer.Write(bytes.Repeat([]byte{1}, 32)) }()
			_, _ = io.Copy(io.Discard, clientPeer)
		}
		select {
		case err := <-finished:
			var failure *EgressError
			if !errors.As(err, &failure) || failure.Code != "egress_tunnel_limit" {
				t.Fatal("tunnel bound not reported", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("byte limit retained copy goroutine")
		}
	}
}
