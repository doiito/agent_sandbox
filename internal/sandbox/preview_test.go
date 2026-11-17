package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type previewWireState struct {
	tcp            net.Conn
	wire           net.Conn
	once           sync.Once
	done           chan struct{}
	sent, received atomic.Uint64
	status         string
}

func (s *previewWireState) stop() { s.once.Do(func() { _ = s.tcp.Close(); _ = s.wire.Close() }) }

type previewWireGuest struct {
	port   uint16
	mu     sync.Mutex
	states map[string]*previewWireState
	opens  atomic.Int32
}

func (g *previewWireGuest) serve(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
	if r.Operation != "open" {
		g.mu.Lock()
		state := g.states[r.ID]
		g.mu.Unlock()
		if state == nil {
			sendPortControlInfo(c, r, "cancelled")
			return
		}
		if r.Operation == "cancel" {
			state.stop()
			<-state.done
		}
		status := "open"
		select {
		case <-state.done:
			status = state.status
		default:
		}
		reply := testPortReply(r)
		reply.Response.Status = status
		reply.Response.SentBytes = state.sent.Load()
		reply.Response.ReceivedBytes = state.received.Load()
		if status == "cancelled" {
			code := "cancelled"
			reply.Response.Error = &code
		}
		_ = writePortBytes(c, testPortJSON(reply))
		return
	}
	g.opens.Add(1)
	if r.Port != g.port {
		reply := testPortReply(r)
		reply.Response = nil
		code := "connection_refused"
		reply.Error = &code
		_ = writePortBytes(c, testPortJSON(reply))
		return
	}
	tcp, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(g.port))), time.Second)
	if err != nil {
		return
	}
	s := &previewWireState{tcp: tcp, wire: c, done: make(chan struct{}), status: "cancelled"}
	g.mu.Lock()
	g.states[r.ID] = s
	g.mu.Unlock()
	defer close(s.done)
	defer s.stop()
	if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
		return
	}
	finished := make(chan bool, 2)
	go func() {
		for {
			kind, data, err := readTestPortFrame(reader)
			if err != nil {
				finished <- false
				s.stop()
				return
			}
			if kind == portEOFFrame {
				if target, ok := tcp.(*net.TCPConn); ok {
					_ = target.CloseWrite()
				}
				finished <- true
				return
			}
			if kind != portDataFrame {
				finished <- false
				s.stop()
				return
			}
			if err := writePortBytes(tcp, data); err != nil {
				finished <- false
				s.stop()
				return
			}
			s.sent.Add(uint64(len(data)))
		}
	}()
	go func() {
		buffer := make([]byte, portDataLimit)
		for {
			n, err := tcp.Read(buffer)
			if n > 0 {
				if writePortBytes(c, testPortFrame(portDataFrame, buffer[:n])) != nil {
					finished <- false
					s.stop()
					return
				}
				s.received.Add(uint64(n))
			}
			if err != nil {
				if err == io.EOF && writePortBytes(c, testPortFrame(portEOFFrame, nil)) == nil {
					finished <- true
				} else {
					finished <- false
					s.stop()
				}
				return
			}
		}
	}()
	a, b := <-finished, <-finished
	_ = tcp.Close()
	if a && b {
		s.status = "completed"
		body, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed", SentBytes: s.sent.Load(), ReceivedBytes: s.received.Load()})
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_ = writePortBytes(c, testPortFrame(portFinishedFrame, body))
	}
}

type previewFixture struct {
	api        *portHTTPFixture
	service    *previewService
	front      *httptest.Server
	browser    *http.Client
	browserTLS *tls.Config
	guest      *previewWireGuest
	port       uint16
}

func previewConfigForTest() PreviewConfig {
	return PreviewConfig{Listen: "127.0.0.1:9444", OriginBase: "https://preview.test:9444", APIOrigin: "https://control.test:8443", CertFile: "/validation/preview.crt", KeyFile: "/validation/preview.key"}
}
func newPreviewFixture(t *testing.T, handler http.Handler) *previewFixture {
	t.Helper()
	app := httptest.NewServer(handler)
	_, portText, _ := net.SplitHostPort(app.Listener.Addr().String())
	number, _ := strconv.ParseUint(portText, 10, 16)
	guest := &previewWireGuest{port: uint16(number), states: map[string]*previewWireState{}}
	f := newPortHTTPFixture(t, guest.serve)
	f.owner.policy.Ports.Preview = true
	f.owner.policy.Ports.MaxConcurrent = 8
	f.owner.portSem = make(chan struct{}, 8)
	f.apiTenant.policy.Ports.Preview = true
	f.apiTenant.policy.Ports.MaxConcurrent = 8
	service, err := newPreviewService(f.handler.api, previewConfigForTest())
	if err != nil {
		t.Fatal(err)
	}
	f.handler.api.preview = service
	serverTLS, clientTLS := portTLSFixture(t, "*.preview.test")
	serverTLS.ClientAuth = tls.NoClientCert
	front := httptest.NewUnstartedServer(service)
	front.TLS = serverTLS
	front.StartTLS()
	browserTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: clientTLS.RootCAs, NextProtos: []string{"http/1.1"}}
	transport := &http.Transport{TLSClientConfig: browserTLS, ForceAttemptHTTP2: false, Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", front.Listener.Addr().String())
	}}
	fixture := &previewFixture{api: f, service: service, front: front, browserTLS: browserTLS, guest: guest, port: uint16(number), browser: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := service.shutdown(ctx); err != nil {
			t.Error(err)
		}
		f.session.close(f.handler.api)
		transport.CloseIdleConnections()
		front.Close()
		app.Close()
	})
	return fixture
}
func (f *previewFixture) control(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	r, err := http.NewRequest(method, f.api.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	response, err := f.api.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}
func (f *previewFixture) create(t *testing.T, id string, ttl uint64) PreviewGrantInfo {
	t.Helper()
	path := fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%s", f.api.session.info.ID, f.port, id)
	status, data := f.control(t, "POST", path, "token-a", map[string]any{"ttl_ms": ttl})
	if status != 201 {
		t.Fatalf("create preview: %d %s", status, data)
	}
	var info PreviewGrantInfo
	if json.Unmarshal(data, &info) != nil || info.ID != id || info.Port != f.port || info.Protocol != previewProtocol {
		t.Fatal("invalid grant creation response")
	}
	return info
}
func (f *previewFixture) bootstrap(t *testing.T, info PreviewGrantInfo) *http.Cookie {
	t.Helper()
	response, err := f.browser.Get(info.BootstrapURL)
	if err != nil {
		t.Fatal("bootstrap TLS exchange failed", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 303 || response.Header.Get("Location") != "/" {
		t.Fatal("bootstrap did not redirect to clean root", response.StatusCode)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing authorization cookie")
	}
	cookie := cookies[0]
	if cookie.Name != previewCookie || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || !validSHA256Hex(cookie.Value) {
		t.Fatal("invalid authorization cookie attributes")
	}
	return cookie
}
func (f *previewFixture) request(t *testing.T, method, target string, cookie *http.Cookie, headers http.Header, body io.Reader) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header[k] = v
	}
	response, err := f.browser.Do(r)
	if err != nil {
		t.Fatal("preview exchange failed", err)
	}
	return response
}
func previewRead(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, previewRequestBytes+4096))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPreviewConfigAndTLSRequireIndependentValidWildcard(t *testing.T) {
	base := previewConfigForTest()
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PreviewConfig){func(c *PreviewConfig) { c.OriginBase = "http://preview.test" }, func(c *PreviewConfig) { c.OriginBase = "https://127.0.0.1" }, func(c *PreviewConfig) { c.OriginBase = "https://bad_.test" }, func(c *PreviewConfig) { c.APIOrigin = "https://sub.preview.test" }, func(c *PreviewConfig) { c.OriginBase = "https://preview.test/path" }, func(c *PreviewConfig) { c.Listen = "127.0.0.1:0" }, func(c *PreviewConfig) { c.KeyFile = "relative.key" }} {
		c := base
		change(&c)
		if c.validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	tlsConfig, _ := portTLSFixture(t, "*.preview.test")
	dir := t.TempDir()
	certificate := tlsConfig.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	base.CertFile = filepath.Join(dir, "preview.crt")
	base.KeyFile = filepath.Join(dir, "preview.key")
	if os.WriteFile(base.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600) != nil || os.WriteFile(base.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600) != nil {
		t.Fatal("cannot write disposable TLS credentials")
	}
	loaded, err := LoadPreviewTLS(&base)
	if err != nil || loaded.MinVersion != tls.VersionTLS13 || loaded.ClientAuth != tls.NoClientCert {
		t.Fatal("preview TLS", err)
	}
	base.OriginBase = "https://other.test"
	if _, err := LoadPreviewTLS(&base); err == nil {
		t.Fatal("wrong wildcard accepted")
	}
}

func TestPreviewBootstrapOwnerIsolationAndNoSecretsInInfo(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("root")) }))
	info := f.create(t, strings.Repeat("1", 24), 5000)
	if strings.Contains(info.Origin, info.ID) || info.Origin == f.api.server.URL {
		t.Fatal("caller chose browser origin")
	}
	response := f.request(t, "GET", info.Origin+"/", nil, nil, nil)
	if response.StatusCode != 401 {
		t.Fatal(response.StatusCode)
	}
	previewRead(t, response)
	cookie := f.bootstrap(t, info)
	response = f.request(t, "GET", info.BootstrapURL, nil, nil, nil)
	if response.StatusCode != 401 {
		t.Fatal("bootstrap replay accepted")
	}
	previewRead(t, response)
	response = f.request(t, "GET", info.Origin+"/", cookie, nil, nil)
	if response.StatusCode != 200 || string(previewRead(t, response)) != "root" {
		t.Fatal("root route failed")
	}
	path := "/v2/sessions/" + info.SessionID + "/previews/" + info.ID
	status, data := f.control(t, "GET", path, "token-a", nil)
	if status != 200 || bytes.Contains(data, []byte("bootstrap_url")) || bytes.Contains(data, []byte(cookie.Value)) {
		t.Fatal("grant info leaked authorization")
	}
	status, _ = f.control(t, "GET", path, "token-b", nil)
	if status != 404 {
		t.Fatal("cross owner grant exposed")
	}
	other := f.create(t, strings.Repeat("2", 24), 5000)
	response = f.request(t, "GET", other.Origin+"/", cookie, nil, nil)
	if response.StatusCode != 401 {
		t.Fatal("cross grant cookie accepted")
	}
	previewRead(t, response)
	response = f.request(t, "GET", info.Origin+"/", cookie, http.Header{"Origin": {other.Origin}}, nil)
	if response.StatusCode != 403 {
		t.Fatal("cross-origin accepted")
	}
	previewRead(t, response)
}

func TestPreviewHTTPBinaryCookiesCredentialsAndConnectionReuse(t *testing.T) {
	seen := make(chan http.Header, 8)
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Add("Set-Cookie", "app=ok; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", previewCookie+"=attacker; Path=/; Secure")
		w.Header().Add("Set-Cookie", "wide=bad; Domain=preview.test; Path=/")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Header().Set("Origin-Agent-Cluster", "?0")
		data, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte{0, 255}, data...))
	}))
	info := f.create(t, strings.Repeat("3", 24), 10000)
	cookie := f.bootstrap(t, info)
	for _, authorization := range []string{"Bearer token-a", "Bearer application-jwt"} {
		body := bytes.Repeat([]byte{0, 255, 1}, 10000)
		headers := http.Header{"Authorization": {authorization}, "Proxy-Authorization": {"secret"}, "Forwarded": {"for=spoof"}, "Cookie": {previewCookie + "=" + cookie.Value + "; app=ok"}}
		response := f.request(t, "POST", info.Origin+"/echo?key=value", nil, headers, bytes.NewReader(body))
		if response.StatusCode != 200 || !bytes.Equal(previewRead(t, response), append([]byte{0, 255}, body...)) {
			t.Fatal("binary HTTP exchange failed")
		}
		if response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("Origin-Agent-Cluster") != "?1" || len(response.Cookies()) != 1 || response.Cookies()[0].Name != "app" {
			t.Fatal("response isolation filter failed")
		}
		received := <-seen
		if strings.Contains(received.Get("Cookie"), previewCookie) || received.Get("Cookie") != "app=ok" || received.Get("Proxy-Authorization") != "" || received.Get("Forwarded") != "" || received.Get("X-Forwarded-Proto") != "https" {
			t.Fatal("control metadata reached application")
		}
		if authorization == "Bearer token-a" && received.Get("Authorization") != "" || authorization != "Bearer token-a" && received.Get("Authorization") != authorization {
			t.Fatal("application/control authentication filter failed")
		}
	}
	if f.guest.opens.Load() != 1 {
		t.Fatal("HTTP did not reuse its native connection", f.guest.opens.Load())
	}
}

func TestPreviewRevocationAndExpiryInvalidateIdleConnectionAndIDs(t *testing.T) {
	f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	info := f.create(t, strings.Repeat("4", 24), 5000)
	cookie := f.bootstrap(t, info)
	response := f.request(t, "GET", info.Origin, cookie, nil, nil)
	previewRead(t, response)
	path := "/v2/sessions/" + info.SessionID + "/previews/" + info.ID
	status, data := f.control(t, "DELETE", path, "token-a", nil)
	if status != 200 || !bytes.Contains(data, []byte(`"status":"revoked"`)) {
		t.Fatal("revoke failed")
	}
	response = f.request(t, "GET", info.Origin, cookie, nil, nil)
	if response.StatusCode != 404 {
		t.Fatal("revoked URL still active")
	}
	previewRead(t, response)
	status, _ = f.control(t, "POST", fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%s", info.SessionID, f.port, info.ID), "token-a", map[string]int{"ttl_ms": 5000})
	if status != 409 {
		t.Fatal("old grant ID replayed")
	}
	deadline := time.Now().Add(time.Second)
	for len(f.api.owner.portSem) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle connection not reclaimed")
		}
		time.Sleep(time.Millisecond)
	}
	short := f.create(t, strings.Repeat("5", 24), 1000)
	shortCookie := f.bootstrap(t, short)
	time.Sleep(time.Until(short.ExpiresAt) + 5*time.Millisecond)
	response = f.request(t, "GET", short.Origin, shortCookie, nil, nil)
	if response.StatusCode != 404 && response.StatusCode != 410 {
		t.Fatal("expired URL still active")
	}
	previewRead(t, response)
}
