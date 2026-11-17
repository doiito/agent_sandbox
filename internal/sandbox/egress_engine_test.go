package sandbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func egressTLSFixture(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"allowed.test", "other.test", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return server, roots
}
func expectEgressError(t *testing.T, err error, code string) {
	t.Helper()
	var failure *EgressError
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("got %v want %s", err, code)
	}
}

func TestEgressEnginePinsDNSAndPreservesTLSIdentity(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	seen := make(chan string, 1)
	server, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- r.TLS.ServerName + "|" + r.Host + "|" + r.Header.Get("X-Custom") + "|" + string(body)
		w.Header().Set("X-Reply", "ok")
		w.Write([]byte{0, 255, 10})
	}))
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	origin := "https://allowed.test:" + port
	rules, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{origin}})
	engine := newEgressEngine(roots)
	lookupCalls := 0
	engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookupCalls++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	var mu sync.Mutex
	var dialAddresses []string
	engine.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialAddresses = append(dialAddresses, address)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	allow := func(origin, method, ip string, hop int) error {
		if ip != "8.8.8.8" || method != "POST" || hop != 0 {
			t.Error("bad authorization", origin, method, ip, hop)
		}
		return nil
	}
	result, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: origin + "/binary?secret=not-audited", Method: "POST", BodyBase64: base64.StdEncoding.EncodeToString([]byte("request")), Headers: map[string]string{"X-Custom": "kept"}}, rules, allow)
	if err != nil || result.Status != 200 || result.BodyBase64 != base64.StdEncoding.EncodeToString([]byte{0, 255, 10}) || result.BodyBytes != 3 || result.RequestBytes != 7 {
		t.Fatal(result, err)
	}
	if got := <-seen; got != "allowed.test|allowed.test:"+port+"|kept|request" {
		t.Fatal(got)
	}
	mu.Lock()
	defer mu.Unlock()
	if lookupCalls != 1 || len(dialAddresses) != 1 || dialAddresses[0] != net.JoinHostPort("8.8.8.8", port) {
		t.Fatal("DNS was not pinned", lookupCalls, dialAddresses)
	}
}

func TestEgressEngineChecksEveryRedirectAndDropsCrossOriginHeaders(t *testing.T) {
	seen := make(chan http.Header, 4)
	var port string
	server, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cross":
			w.Header().Set("Location", "https://other.test:"+port+"/end")
			w.WriteHeader(302)
		case "/same":
			w.Header().Set("Location", "/end")
			w.WriteHeader(307)
		case "/denied":
			w.Header().Set("Location", "https://denied.test:"+port+"/end")
			w.WriteHeader(302)
		case "/downgrade":
			w.Header().Set("Location", "http://allowed.test:"+port+"/end")
			w.WriteHeader(302)
		case "/loop":
			w.Header().Set("Location", "/loop")
			w.WriteHeader(302)
		default:
			seen <- r.Header.Clone()
			w.Write([]byte(r.Method))
		}
	}))
	_, port, _ = net.SplitHostPort(server.Listener.Addr().String())
	origin := "https://allowed.test:" + port
	rules, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{origin, "https://other.test:" + port}, MaxRedirects: 2})
	engine := newEgressEngine(roots)
	lookupCalls := 0
	engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookupCalls++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	engine.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	allow := func(string, string, string, int) error { return nil }
	headers := map[string]string{"Authorization": "remote-secret", "Cookie": "cookie-secret", "X-API-Key": "custom-secret"}
	for _, path := range []string{"/same", "/cross"} {
		result, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: origin + path, Headers: headers, FollowRedirects: true}, rules, allow)
		if err != nil || result.Redirects != 1 {
			t.Fatal(result, err)
		}
		observed := <-seen
		for key, value := range headers {
			if path == "/same" && observed.Get(key) != value || path == "/cross" && observed.Get(key) != "" {
				t.Fatal("redirect credential handling", path, key, observed)
			}
		}
	}
	if lookupCalls != 4 {
		t.Fatal("each hop must resolve once", lookupCalls)
	}
	for path, code := range map[string]string{"/denied": "egress_origin_denied", "/downgrade": "egress_tls_downgrade", "/loop": "egress_redirect_limit"} {
		_, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: origin + path, FollowRedirects: true}, rules, allow)
		expectEgressError(t, err, code)
	}
	result, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: origin + "/cross"}, rules, allow)
	if err != nil || result.Status != 302 || result.Redirects != 0 {
		t.Fatal("redirect followed without opt in", result, err)
	}
}

func TestEgressEngineRejectsMixedAnswersAndRebinding(t *testing.T) {
	server, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Location", "/again"); w.WriteHeader(302) }))
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	origin := "https://allowed.test:" + port
	rules, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{origin}, MaxRedirects: 3})
	for _, mixed := range []bool{true, false} {
		engine := newEgressEngine(roots)
		lookups, dials := 0, 0
		engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			if mixed {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
			}
			if lookups == 1 {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		engine.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials++
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		_, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: origin, FollowRedirects: true}, rules, func(string, string, string, int) error { return nil })
		expectEgressError(t, err, "egress_ip_denied")
		if mixed && dials != 0 || !mixed && dials != 1 {
			t.Fatal("unchecked DNS answer dialed", mixed, lookups, dials)
		}
	}
}

func TestEgressEngineBoundsCancellationAndAuditDenial(t *testing.T) {
	entered, cancelled := make(chan struct{}, 4), make(chan struct{}, 4)
	server, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			w.Write([]byte(strings.Repeat("x", 1025)))
		case "/headers":
			w.Header().Set("X-Large", strings.Repeat("x", 20000))
			w.WriteHeader(200)
		case "/slow":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			entered <- struct{}{}
			<-r.Context().Done()
			cancelled <- struct{}{}
		default:
			w.Write([]byte("ok"))
		}
	}))
	rules, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{server.URL}, AllowedCIDRs: []string{"127.0.0.1/32"}, MaxResponseBytes: 1024, TimeoutMS: 2000})
	engine := newEgressEngine(roots)
	allow := func(string, string, string, int) error { return nil }
	_, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: server.URL + "/large"}, rules, allow)
	expectEgressError(t, err, "egress_response_limit")
	_, err = engine.fetch(context.Background(), NetworkFetchRequest{URL: server.URL + "/headers"}, rules, allow)
	expectEgressError(t, err, "egress_upstream")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := engine.fetch(ctx, NetworkFetchRequest{URL: server.URL + "/slow"}, rules, allow)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow upstream did not begin")
	}
	cancel()
	expectEgressError(t, <-done, "egress_cancelled")
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection survived cancellation")
	}
	_, err = engine.fetch(context.Background(), NetworkFetchRequest{URL: server.URL + "/slow", TimeoutMS: 500}, rules, allow)
	expectEgressError(t, err, "egress_timeout")
	<-entered
	<-cancelled
	_, err = engine.fetch(context.Background(), NetworkFetchRequest{URL: server.URL}, rules, func(string, string, string, int) error { return egressError(503, "egress_audit") })
	expectEgressError(t, err, "egress_audit")
	wrongRoots := newEgressEngine(x509.NewCertPool())
	_, err = wrongRoots.fetch(context.Background(), NetworkFetchRequest{URL: server.URL}, rules, allow)
	expectEgressError(t, err, "egress_tls")
	result, err := engine.fetch(context.Background(), NetworkFetchRequest{URL: server.URL}, rules, allow)
	if err != nil || result.Status != 200 {
		t.Fatal("slot/connection not reusable", result, err)
	}
}
