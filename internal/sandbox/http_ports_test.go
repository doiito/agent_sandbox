package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func portTLSFixture(t *testing.T, dnsNames ...string) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "port-test-CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	certificate := func(number int64, client bool) tls.Certificate {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u := x509.ExtKeyUsageServerAuth
		if client {
			u = x509.ExtKeyUsageClientAuth
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(number), Subject: pkix.Name{CommonName: "port-test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{u}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: append([]string{"localhost"}, dnsNames...)}
		b, err := x509.CreateCertificate(rand.Reader, leaf, parsed, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: k}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate(2, false)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate(3, true)}, NextProtos: []string{"http/1.1"}}
}

type portHTTPFixture struct {
	handler   *apiHTTPHandler
	root      *Session
	owner     *tenantRuntime
	apiTenant *tenantRuntime
	session   *apiSession
	server    *httptest.Server
	tls       *tls.Config
	client    *http.Client
}

// Actual mTLS HTTP -> production API/launcher -> actual UDS guest wire. The
// guest endpoint is scripted; real guest PID1/TCP and KVM have separate gates.
func newPortHTTPFixture(t *testing.T, serve func(net.Conn, *bufio.Reader, linuxPortRequest)) *portHTTPFixture {
	t.Helper()
	s, owner := portTestSession(t, 1, serve)
	// Owner capabilities refresh the local lease from root Info. Keep that
	// authoritative fixture lease valid instead of a zero timestamp.
	s.info.ExpiresAt = time.Now().Add(time.Minute)
	s.info.MaxExpiresAt = s.info.ExpiresAt
	h := portLauncherFixture(t, s, owner, nil, os.Geteuid())
	client, server := net.Pipe()
	h.conn = client
	h.reader = bufio.NewReader(client)
	go func() {
		defer server.Close()
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var request launcherSessionRequest
			if json.Unmarshal(line, &request) != nil {
				return
			}
			response := launcherSessionResponse{Protocol: launcherSessionProtocol}
			if request.Operation == "close" {
				_ = s.Close()
				_ = json.NewEncoder(server).Encode(response)
				return
			}
			info := s.Info()
			response.Info = &info
			_ = json.NewEncoder(server).Encode(response)
		}
	}()
	auth := sessionAuthForTest()
	tenant, _ := auth.Authenticate("Bearer token-a")
	policy, _ := owner.policy.Ports.validatedCopy()
	tenant.policy.Ports = policy
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, auth, slog.Default()).(*apiHTTPHandler)
	info := s.info
	info.ExpiresAt = time.Now().Add(time.Minute)
	info.MaxExpiresAt = info.ExpiresAt
	session := &apiSession{info: info, tenant: tenant, handle: h, done: make(chan struct{}), release: func() {}, deadline: info.ExpiresAt,
		capability: CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: info.Backend, ArtifactAuthenticated: true, ArtifactManifestProtocol: "osv-sandbox-artifacts/v6", ArtifactManifestSHA256: info.ArtifactManifestSHA256, Features: CapabilityFeatures{Sessions: true, PortForward: true}}}
	handler.api.sessions[info.ID] = session
	t.Cleanup(func() { session.close(handler.api) })
	serverTLS, clientTLS := portTLSFixture(t)
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = serverTLS
	ts.Config.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	ts.StartTLS()
	transport := &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: false}
	f := &portHTTPFixture{handler: handler, root: s, owner: owner, apiTenant: tenant, session: session, server: ts, tls: clientTLS, client: &http.Client{Transport: transport, Timeout: 3 * time.Second}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := handler.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		transport.CloseIdleConnections()
		ts.Close()
	})
	return f
}

func (f *portHTTPFixture) path(r SessionPortRequest) string {
	return fmt.Sprintf("/v2/sessions/%s/ports/%d/connections/%s", f.session.info.ID, r.Port, r.ID)
}

func (f *portHTTPFixture) open(r SessionPortRequest, extra []byte) (net.Conn, *bufio.Reader, *http.Response, error) {
	return f.openRaw(f.path(r), "token-a", f.tls, "keep-alive, Upgrade", portTunnelUpgrade, r.Limits, extra)
}
func (f *portHTTPFixture) openRaw(path, token string, config *tls.Config, connection, upgrade string, body any, extra []byte) (net.Conn, *bufio.Reader, *http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, nil, nil, err
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.server.Listener.Addr().String(), config)
	if err != nil {
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\nConnection: %s\r\nUpgrade: %s\r\n\r\n", path, token, len(data), connection, upgrade)
	packet := append([]byte(request), data...)
	packet = append(packet, extra...)
	if err = writePortBytes(conn, packet); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	return conn, reader, response, nil
}

func (f *portHTTPFixture) control(t *testing.T, method, token string, r SessionPortRequest) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, f.server.URL+f.path(r), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

func TestPortHTTPMTLSBinaryDuplexAndEitherHalfCloseOrder(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			f := newPortHTTPFixture(t, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
				if r.Operation != "open" {
					sendPortControlInfo(c, r, "cancelled")
					return
				}
				if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
					return
				}
				if first {
					_ = writePortBytes(c, testPortFrame(portEOFFrame, nil))
				}
				var count uint64
				for {
					kind, data, err := readTestPortFrame(reader)
					if err != nil {
						return
					}
					if kind == portEOFFrame {
						break
					}
					if kind != portDataFrame {
						t.Error(kind)
						return
					}
					count += uint64(len(data))
					if !first {
						if writePortBytes(c, testPortFrame(portDataFrame, data)) != nil {
							return
						}
					}
				}
				received := count
				if first {
					received = 0
				} else {
					_ = writePortBytes(c, testPortFrame(portEOFFrame, nil))
				}
				body, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed", SentBytes: count, ReceivedBytes: received})
				_ = writePortBytes(c, testPortFrame(portFinishedFrame, body))
			})
			r := portOpenRequest(1)
			conn, reader, response, err := f.open(r, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if response.StatusCode != 101 || response.Header.Get("Upgrade") != portTunnelUpgrade || response.Header.Get("X-OSV-Session-ID") != f.session.info.ID || response.Header.Get("X-OSV-Connection-ID") != r.ID || response.Header.Get("X-OSV-Port") != "8080" {
				t.Fatal(response.Status, response.Header)
			}
			data := bytes.Repeat([]byte{0, 0xff, 10, 13, 4}, 40000)
			if first {
				kind, _, err := readTestPortFrame(reader)
				if err != nil || kind != portEOFFrame {
					t.Fatal(kind, err)
				}
			}
			done := make(chan error, 1)
			go func() {
				for start := 0; start < len(data); start += portDataLimit {
					if err := writePortBytes(conn, testPortFrame(portDataFrame, data[start:min(len(data), start+portDataLimit)])); err != nil {
						done <- err
						return
					}
				}
				done <- writePortBytes(conn, testPortFrame(portEOFFrame, nil))
			}()
			var output []byte
			var info SessionPortInfo
			for {
				kind, body, err := readTestPortFrame(reader)
				if err != nil {
					t.Fatal(err)
				}
				if kind == portDataFrame {
					output = append(output, body...)
				}
				if kind == portFinishedFrame {
					if err := json.Unmarshal(body, &info); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if info.Status != "completed" || info.SentBytes != uint64(len(data)) {
				t.Fatal(info)
			}
			if first {
				if len(output) != 0 || info.ReceivedBytes != 0 {
					t.Fatal(info)
				}
			} else if !bytes.Equal(output, data) || info.ReceivedBytes != uint64(len(data)) {
				t.Fatal("binary output lost", len(output), info)
			}
			status, body := f.control(t, "GET", "token-a", r)
			if status != 200 || !bytes.Contains(body, []byte(`"status":"completed"`)) {
				t.Fatal(status, string(body))
			}
		})
	}
}

func TestPortHTTPPreservesFramedDataCoalescedAfterJSONBody(t *testing.T) {
	for _, protocol := range []string{"osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8"} {
		t.Run(protocol, func(t *testing.T) {
			f := newPortHTTPFixture(t, func(c net.Conn, r *bufio.Reader, w linuxPortRequest) { portEchoGuest(t, c, r, w) })
			f.session.capability.ArtifactManifestProtocol = protocol
			r := portOpenRequest(1)
			packet := append(testPortFrame(portDataFrame, []byte("pipelined\x00\xff")), testPortFrame(portEOFFrame, nil)...)
			conn, reader, response, err := f.open(r, packet)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if response.StatusCode != 101 {
				t.Fatal(response.Status)
			}
			kind, data, err := readTestPortFrame(reader)
			if err != nil || kind != portDataFrame || string(data) != "pipelined\x00\xff" {
				t.Fatal(kind, string(data), err)
			}
			if kind, _, err = readTestPortFrame(reader); err != nil || kind != portEOFFrame {
				t.Fatal(kind, err)
			}
			if kind, _, err = readTestPortFrame(reader); err != nil || kind != portFinishedFrame {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestPortHTTPRejectsWrongIdentityCapabilityPolicyAndMalformedRequestBeforeDial(t *testing.T) {
	for _, mode := range []string{"bearer", "owner", "capability", "digest", "port", "id", "upgrade", "connection", "zero", "unknown_field", "policy", "proxy", "rate"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			f := newPortHTTPFixture(t, func(net.Conn, *bufio.Reader, linuxPortRequest) { calls.Add(1) })
			r := portOpenRequest(1)
			path, token, connection, upgrade, body, want := f.path(r), "token-a", "upgrade", portTunnelUpgrade, any(r.Limits), 400
			switch mode {
			case "bearer":
				token = "wrong"
				want = 401
			case "owner":
				token = "token-b"
				want = 404
			case "capability":
				f.session.capability.Features.PortForward = false
				want = 501
			case "digest":
				f.session.capability.ArtifactManifestSHA256 = strings.Repeat("e", 64)
				want = 501
			case "port":
				path = strings.Replace(path, "/8080/", "/08080/", 1)
			case "id":
				path = strings.TrimSuffix(path, r.ID) + "BAD"
			case "upgrade":
				upgrade = "websocket"
			case "connection":
				connection = "keep-alive"
			case "zero":
				body = SessionPortLimits{}
			case "unknown_field":
				body = map[string]any{"max_bytes": 1, "timeout_ms": 1000, "idle_timeout_ms": 1000, "address": "host.invalid"}
			case "policy":
				f.apiTenant.policy.Ports = nil
				want = 403
			case "proxy":
				r.Port = 3128
				path = f.path(r)
				want = 403
			case "rate":
				f.apiTenant.mu.Lock()
				f.apiTenant.tokens = 0
				f.apiTenant.policy.RequestsPerSecond = 0.0001
				f.apiTenant.mu.Unlock()
				want = 429
			}
			conn, _, response, err := f.openRaw(path, token, f.tls, connection, upgrade, body, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			defer response.Body.Close()
			if response.StatusCode != want || calls.Load() != 0 || len(f.owner.portSem) != 0 {
				t.Fatal(response.Status, "want", want, "guest", calls.Load())
			}
		})
	}
}

func TestPortHTTPRequiresMutualTLSAndNeverReturnsSuccessForLostFinishedFrame(t *testing.T) {
	f := newPortHTTPFixture(t, func(c net.Conn, _ *bufio.Reader, r linuxPortRequest) {
		if r.Operation != "open" {
			sendPortControlInfo(c, r, "cancelled")
			return
		}
		_ = writePortBytes(c, testPortJSON(testPortReply(r)))
		_ = writePortBytes(c, testPortFrame(portEOFFrame, nil))
	})
	r := portOpenRequest(1)
	noCert := f.tls.Clone()
	noCert.Certificates = nil
	conn, _, response, err := f.openRaw(f.path(r), "token-a", noCert, "upgrade", portTunnelUpgrade, r.Limits, nil)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("mTLS accepted no client certificate")
	}
	conn, reader, response, err := f.open(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if response.StatusCode != 101 {
		t.Fatal(response.Status)
	}
	kind, _, err := readTestPortFrame(reader)
	if err != nil || kind != portEOFFrame {
		t.Fatal(kind, err)
	}
	if _, _, err = readTestPortFrame(reader); err == nil {
		t.Fatal("transport loss invented terminal proof")
	}
	waitWarm(t, func() bool { return len(f.owner.portSem) == 0 })
	status, body := f.control(t, "GET", "token-a", r)
	if status != 200 || !bytes.Contains(body, []byte(`"status":"cancelled"`)) {
		t.Fatal(status, string(body))
	}
}

func TestPortHTTPPendingAndLiveShutdownJoinHandlersAndRejectNewOpen(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			arrived, closed := make(chan struct{}), make(chan struct{})
			f := newPortHTTPFixture(t, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
				if r.Operation != "open" {
					<-closed
					sendPortControlInfo(c, r, "cancelled")
					return
				}
				defer close(closed)
				if !pending {
					if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
						return
					}
				}
				close(arrived)
				_, _ = io.Copy(io.Discard, reader)
			})
			r := portOpenRequest(1)
			opened := make(chan int, 1)
			go func() {
				c, reader, response, err := f.open(r, nil)
				if err != nil {
					opened <- 0
					return
				}
				defer c.Close()
				opened <- response.StatusCode
				if response.StatusCode == 101 {
					_, _, _ = readTestPortFrame(reader)
				}
			}()
			<-arrived
			if !pending {
				if status := <-opened; status != 101 {
					t.Fatal(status)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.handler.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			f.handler.api.portMu.Lock()
			active := len(f.handler.api.portTunnels)
			f.handler.api.portMu.Unlock()
			if active != 0 {
				t.Fatal("shutdown retained pending/live handler", active)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("root open ignored peer loss")
			}
			if pending {
				select {
				case status := <-opened:
					if status == 101 {
						t.Fatal("cancelled pending open upgraded")
					}
				case <-time.After(time.Second):
					t.Fatal("pending HTTP request hung")
				}
			}
			waitWarm(t, func() bool { return len(f.owner.portSem) == 0 })
			r = portOpenRequest(2)
			c, _, response, err := f.open(r, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if response.StatusCode != 503 {
				t.Fatal(response.Status)
			}
		})
	}
}

func TestPortHTTPAbsentChildCancelBeforeOpenAndCleanupBypassesRateAndPolicy(t *testing.T) {
	f := newPortHTTPFixture(t, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("local tombstone dialed guest") })
	r := portOpenRequest(1)
	status, body := f.control(t, "GET", "token-a", r)
	if status != 404 || !bytes.Contains(body, []byte(`"code":"port_not_found"`)) {
		t.Fatal(status, string(body))
	}
	f.apiTenant.policy.Ports = nil
	f.apiTenant.mu.Lock()
	f.apiTenant.tokens = 0
	f.apiTenant.mu.Unlock()
	status, body = f.control(t, "DELETE", "token-a", r)
	if status != 202 || !bytes.Contains(body, []byte(`"status":"cancelled"`)) {
		t.Fatal(status, string(body))
	}
	status, body = f.control(t, "GET", "token-a", r)
	if status != 200 || !bytes.Contains(body, []byte(`"session_id":"`+f.session.info.ID+`"`)) {
		t.Fatal(status, string(body))
	}
}

func TestPortHTTPRejectsNonUpgradeTransportsBeforeGuestAdmission(t *testing.T) {
	for _, mode := range []string{"http2", "chunked", "no_length", "oversized", "duplicate_upgrade", "no_hijacker"} {
		t.Run(mode, func(t *testing.T) {
			f := newPortHTTPFixture(t, func(net.Conn, *bufio.Reader, linuxPortRequest) { t.Error("invalid transport dialed guest") })
			r := portOpenRequest(1)
			body, _ := json.Marshal(r.Limits)
			request := httptest.NewRequest("POST", f.path(r), bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer token-a")
			request.Header.Set("Connection", "upgrade")
			request.Header.Set("Upgrade", portTunnelUpgrade)
			want := 400
			switch mode {
			case "http2":
				request.ProtoMajor = 2
				request.ProtoMinor = 0
				want = 426
			case "chunked":
				request.TransferEncoding = []string{"chunked"}
			case "no_length":
				request.ContentLength = -1
			case "oversized":
				request.ContentLength = portHandshakeLimit + 1
			case "duplicate_upgrade":
				request.Header.Add("Upgrade", "websocket")
			case "no_hijacker":
				want = 503
			}
			response := httptest.NewRecorder()
			f.handler.ServeHTTP(response, request)
			if response.Code != want || len(f.owner.portSem) != 0 {
				t.Fatal(response.Code, response.Body.String())
			}
		})
	}
}

func TestPortHTTPSlowReaderAndFullTenantQuotaStillAllowIndependentCancel(t *testing.T) {
	opened, closed := make(chan struct{}), make(chan struct{})
	var delivered atomic.Uint64
	f := newPortHTTPFixture(t, func(c net.Conn, _ *bufio.Reader, r linuxPortRequest) {
		if r.Operation != "open" {
			<-closed
			reply := testPortReply(r)
			reply.Response.Status = "cancelled"
			code := "cancelled"
			reply.Response.Error = &code
			reply.Response.ReceivedBytes = delivered.Load()
			_ = writePortBytes(c, testPortJSON(reply))
			return
		}
		defer close(closed)
		if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
			return
		}
		close(opened)
		body := bytes.Repeat([]byte{0x42}, portDataLimit)
		for i := 0; i < 1024; i++ {
			frame := testPortFrame(portDataFrame, body)
			if writePortBytes(c, frame[:5]) != nil {
				return
			}
			remaining := body
			for len(remaining) != 0 {
				n, err := c.Write(remaining)
				delivered.Add(uint64(n))
				remaining = remaining[n:]
				if err != nil || n == 0 {
					return
				}
			}
		}
	})
	r := portOpenRequest(1)
	conn, _, response, err := f.open(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if response.StatusCode != 101 {
		t.Fatal(response.Status)
	}
	<-opened
	// The client deliberately never reads the tunnel. Sixteen MiB exceeds real
	// TLS/TCP/UDS buffers; cancellation uses another authenticated HTTP request.
	select {
	case <-closed:
		t.Fatal("output did not exercise backpressure")
	case <-time.After(100 * time.Millisecond):
	}
	other := portOpenRequest(2)
	c, _, rejected, err := f.open(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if rejected.StatusCode != 429 {
		t.Fatal(rejected.Status)
	}
	started := time.Now()
	status, body := f.control(t, "DELETE", "token-a", r)
	if status != 202 || !bytes.Contains(body, []byte(`"status":"cancelled"`)) {
		t.Fatal(status, string(body))
	}
	if time.Since(started) > time.Second {
		t.Fatal("backpressure blocked cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("guest transport retained")
	}
	waitWarm(t, func() bool { return len(f.owner.portSem) == 0 })
}
