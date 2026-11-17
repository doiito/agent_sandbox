package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type egressMemoryAudit struct {
	mu     sync.Mutex
	events []EgressAuditEvent
	failed error
	failAt int
}

func (a *egressMemoryAudit) Err() error { a.mu.Lock(); defer a.mu.Unlock(); return a.failed }
func (a *egressMemoryAudit) AppendNetwork(event EgressAuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failAt > 0 && len(a.events)+1 >= a.failAt {
		a.failed = errors.New("audit storage failed")
	}
	if a.failed != nil {
		return a.failed
	}
	a.events = append(a.events, event)
	return nil
}
func egressTestAuth(t *testing.T, policy EgressPolicy) (*Authenticator, *tenantRuntime) {
	t.Helper()
	digest := sha256.Sum256([]byte("egress-test-token"))
	disabled := sha256.Sum256([]byte("egress-disabled-token"))
	file := AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []TenantPolicy{{ID: "egress-a", TokenSHA256: hex.EncodeToString(digest[:]), AllowedEntrypoints: []string{"/agent"}, RequestsPerSecond: 100, Burst: 100, MaxConcurrent: 1, Egress: &policy}, {ID: "egress-b", TokenSHA256: hex.EncodeToString(disabled[:]), AllowedEntrypoints: []string{"/agent"}, RequestsPerSecond: 100, Burst: 100, MaxConcurrent: 1}}}
	data, _ := json.Marshal(file)
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := auth.Authenticate("Bearer egress-test-token")
	return auth, tenant
}
func egressTestSocketAccepting(path string) bool {
	connection, err := net.DialTimeout("unix", path, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func startEgressTestSocket(t *testing.T, server *EgressServer) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "e.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeEgress(ctx, path, server) }()
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if egressTestSocketAccepting(path) {
			break
		}
		select {
		case err := <-done:
			t.Fatal("egress service did not start", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not appear")
		}
		time.Sleep(time.Millisecond)
	}
	return path, cancel, done
}
func testNetworkRequest(handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestEgressServiceAPIUnixPolicyAndIndependentSlots(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "actual")
		w.Write([]byte{0, 255, 10})
	}))
	defer upstream.Close()
	policy := EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.1/32"}, MaxConcurrent: 1, TimeoutMS: 1000}
	auth, tenant := egressTestAuth(t, policy)
	audit := &egressMemoryAudit{}
	server, err := NewEgressServer(auth, audit, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	socket, cancel, done := startEgressTestSocket(t, server)
	api := NewAPIWithEgress(&fakeSessionRunner{}, auth, slog.New(slog.NewTextHandler(io.Discard, nil)), socket)
	response := testNetworkRequest(api, "GET", "/v1/capabilities", "egress-test-token", nil)
	var caps CapabilityReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &caps) != nil || !caps.Features.NetworkFetch || caps.Features.NetworkEgress || caps.NetworkFetchPolicy == nil {
		t.Fatal(response.Code, response.Body.String())
	}
	disabled := testNetworkRequest(api, "GET", "/v1/capabilities", "egress-disabled-token", nil)
	var hidden CapabilityReport
	_ = json.Unmarshal(disabled.Body.Bytes(), &hidden)
	if hidden.Features.NetworkFetch || hidden.NetworkFetchPolicy != nil {
		t.Fatal("disabled tenant learned enabled network policy", disabled.Body.String())
	}
	// A held VM quota must not prevent a separately budgeted egress operation.
	tenant.sem <- struct{}{}
	response = testNetworkRequest(api, "POST", "/v2/net/fetch", "egress-test-token", NetworkFetchRequest{URL: upstream.URL + "/data?secret-query"})
	<-tenant.sem
	var result NetworkFetchResult
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.BodyBase64 != base64.StdEncoding.EncodeToString([]byte{0, 255, 10}) || len(result.RequestID) != 24 {
		t.Fatal(response.Code, response.Body.String())
	}
	for token, expected := range map[string]int{"wrong": 401, "egress-disabled-token": 403} {
		if got := testNetworkRequest(api, "POST", "/v2/net/fetch", token, NetworkFetchRequest{URL: upstream.URL}); got.Code != expected {
			t.Fatal(got.Code, got.Body.String())
		}
	}
	if denied := testNetworkRequest(api, "POST", "/v2/net/fetch", "egress-test-token", NetworkFetchRequest{URL: "http://169.254.169.254/credentials"}); denied.Code != 403 {
		t.Fatal(denied.Code, denied.Body.String())
	}
	audit.mu.Lock()
	data, _ := json.Marshal(audit.events)
	audit.mu.Unlock()
	if strings.Contains(string(data), "secret-query") || strings.Contains(string(data), "egress-test-token") || strings.Contains(string(data), "credentials") {
		t.Fatal("audit leaked path/query/credential", string(data))
	}
	if !strings.Contains(string(data), "net.allow") || !strings.Contains(string(data), "net.complete") || !strings.Contains(string(data), "net.deny") {
		t.Fatal("incomplete audit", string(data))
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := testNetworkRequest(api, "POST", "/v2/net/fetch", "egress-test-token", NetworkFetchRequest{URL: upstream.URL}); got.Code != 503 {
		t.Fatal("stopped service fell back to direct network", got.Code)
	}
	response = testNetworkRequest(api, "GET", "/v1/capabilities", "egress-test-token", nil)
	caps = CapabilityReport{}
	_ = json.Unmarshal(response.Body.Bytes(), &caps)
	if caps.Features.NetworkFetch || caps.NetworkFetchPolicy != nil {
		t.Fatal("stopped daemon advertised network fetch", response.Body.String())
	}
}

func TestEgressServiceConcurrencyCancellationAndAuditFailure(t *testing.T) {
	entered, released := make(chan struct{}, 2), make(chan struct{}, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			entered <- struct{}{}
			<-r.Context().Done()
			released <- struct{}{}
			return
		}
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	auth, _ := egressTestAuth(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.1/32"}, MaxConcurrent: 1, TimeoutMS: 1000})
	audit := &egressMemoryAudit{}
	server, _ := NewEgressServer(auth, audit, "", 1)
	socket, cancel, done := startEgressTestSocket(t, server)
	client := NewEgressClient(socket)
	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		data, _ := json.Marshal(NetworkFetchRequest{URL: upstream.URL + "/slow"})
		_, _, err := client.exchange(ctx, "POST", "/v1/fetch", "Bearer egress-test-token", data)
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not reached")
	}
	body, _ := json.Marshal(NetworkFetchRequest{URL: upstream.URL})
	status, _, err := client.exchange(context.Background(), "POST", "/v1/fetch", "Bearer egress-test-token", body)
	if err != nil || status != 429 {
		t.Fatal("network concurrency escaped", status, err)
	}
	stop()
	if err := <-finished; err == nil {
		t.Fatal("cancelled caller succeeded")
	}
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream survived API disconnect")
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(server.slots) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("network slot leaked")
		}
		time.Sleep(time.Millisecond)
	}
	status, _, err = client.exchange(context.Background(), "POST", "/v1/fetch", "Bearer egress-test-token", body)
	if err != nil || status != 200 {
		t.Fatal("slot not reusable", status, err)
	}
	audit.mu.Lock()
	audit.failAt = len(audit.events) + 2
	audit.mu.Unlock() // admit succeeds, pre-dial audit fails
	status, _, err = client.exchange(context.Background(), "POST", "/v1/fetch", "Bearer egress-test-token", body)
	if err != nil || status != 503 {
		t.Fatal("audit loss did not stop outbound operation", status, err)
	}
	status, _, err = client.exchange(context.Background(), "POST", "/v1/fetch", "Bearer egress-test-token", body)
	if err != nil || status != 503 {
		t.Fatal("audit failure was not sticky", status, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEgressUnixPeerAndSocketOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	guard := &egressListener{UnixListener: listener, uid: uint32(os.Geteuid() + 1), connections: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { _, err := guard.Accept(); done <- err }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = conn.Read(b[:]); err != io.EOF {
		t.Fatal("wrong peer UID was not rejected", err)
	}
	listener.Close()
	<-done
	for _, target := range []string{filepath.Join(t.TempDir(), "not-private.sock"), "relative.sock"} {
		if filepath.IsAbs(target) {
			if err = os.Chmod(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if ServeEgress(context.Background(), target, nil) == nil {
			t.Fatal("unmanaged socket accepted")
		}
	}
}

func TestEgressAuditFilePersistenceAndIncompleteTail(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "audit.jsonl")
	audit, err := OpenEgressAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = audit.AppendNetwork(EgressAuditEvent{Event: "net.allow", Tenant: "a", RequestID: strings.Repeat("1", 24), Origin: "https://example.com:443", IP: "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	audit.Close()
	data, _ := os.ReadFile(path)
	var event EgressAuditEvent
	if json.Unmarshal(data, &event) != nil || event.Protocol != "osv-sandbox-egress-audit/v1" || event.At.IsZero() {
		t.Fatal(string(data))
	}
	if err = os.WriteFile(path, []byte("{incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenEgressAudit(path); err == nil {
		t.Fatal("incomplete audit was silently overwritten")
	}
}
