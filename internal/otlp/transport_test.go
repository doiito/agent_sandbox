package otlp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportRetryableAndPermanentResponses(t *testing.T) {
	for _, status := range []int{429, 502, 503, 504, 400, 401, 403, 404, 413, 500, 501} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Uint64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := calls.Add(1)
				if count == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, "do-not-echo-collector-private-body")
					return
				}
				ack(w)
			}))
			defer server.Close()
			e, err := New(testConfig(server.URL), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closeExporter(t, e)
			ok := e.send(context.Background(), 1, []byte(`{}`), 3)
			retry := status == 429 || status == 502 || status == 503 || status == 504
			state := e.Stats().Signals["logs"]
			if retry && (!ok || calls.Load() != 2 || state.Retries != 1 || state.ExportedRecords != 3) ||
				!retry && (ok || calls.Load() != 1 || state.DroppedRecords != 3) {
				t.Fatal("HTTP retry classification or accounting invalid")
			}
			encoded, _ := json.Marshal(e.Stats())
			if strings.Contains(string(encoded), "collector-private-body") {
				t.Fatal("collector error body escaped")
			}
		})
	}
}

func TestTransportRetryAfterAndAttemptBounds(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
	}))
	defer server.Close()
	e, err := New(testConfig(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if e.send(context.Background(), 1, []byte(`{}`), 3) || calls.Load() != 3 || e.Stats().Signals["logs"].Retries != 2 {
		t.Fatal("retry attempt limit was not enforced")
	}
	for _, after := range []string{"3600", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)} {
		var observed atomic.Uint64
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observed.Add(1)
			w.Header().Set("Retry-After", after)
			w.WriteHeader(429)
		}))
		c := testConfig(peer.URL)
		c.TimeoutMS = 100
		client, err := New(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if client.send(context.Background(), 1, []byte(`{}`), 3) || observed.Load() != 1 || time.Since(start) > time.Second {
			t.Error("long throttle was retried early or blocked")
		}
		closeExporter(t, client)
		peer.Close()
	}
	for attempt := 0; attempt < 2; attempt++ {
		value := retryDelay("not-a-date", attempt, time.Now())
		base := time.Duration(100*(1<<attempt)) * time.Millisecond
		if value < base*75/100 || value > base*125/100 {
			t.Fatal("fallback exponential jitter outside bounds")
		}
	}
}

func TestTransportPartialSuccessNeverRetries(t *testing.T) {
	for index, field := range []string{"rejectedDataPoints", "rejectedLogRecords", "rejectedSpans"} {
		var calls atomic.Uint64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"partialSuccess":{"`+field+`":"2","errorMessage":"do-not-echo-peer-secret"}}`)
		}))
		e, err := New(testConfig(server.URL), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !e.send(context.Background(), index, []byte(`{}`), 3) || calls.Load() != 1 {
			t.Error("partial success was not consumed exactly once")
		}
		state := e.Stats().Signals[signals[index]]
		if state.PartialBatches != 1 || state.FullBatches != 0 || state.ExportedRecords != 1 || state.RejectedRecords != 2 || state.DroppedRecords != 2 {
			t.Error("partial response misreported as full success")
		}
		if e.Close(context.Background()) == nil {
			t.Error("shutdown concealed known rejection")
		}
		closeExporter(t, e)
		server.Close()
	}
}

func TestTransportRedirectDoesNotLeakBearer(t *testing.T) {
	var forwarded atomic.Uint64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); ack(w) }))
	defer other.Close()
	for _, status := range []int{301, 302, 307, 308} {
		var origin atomic.Uint64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin.Add(1)
			if r.Header.Get("Authorization") != "Bearer OUTBOUND_PRIVATE_SENTINEL" {
				t.Error("origin did not receive the configured credential")
			}
			w.Header().Set("Location", other.URL+"/capture")
			w.WriteHeader(status)
		}))
		path := filepath.Join(t.TempDir(), "credential")
		if err := os.WriteFile(path, []byte("OUTBOUND_PRIVATE_SENTINEL"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := testConfig(server.URL)
		c.BearerTokenFile = path
		e, err := New(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if e.send(context.Background(), 1, []byte(`{}`), 1) || forwarded.Load() != 0 || origin.Load() != 1 {
			t.Error("redirect followed or falsely acknowledged")
		}
		transport := e.client.Transport.(*http.Transport)
		if transport.Proxy != nil {
			t.Error("environment proxy policy active")
		}
		encoded, _ := json.Marshal(e.Stats())
		if strings.Contains(string(encoded), "PRIVATE_SENTINEL") {
			t.Error("credential appeared in counters")
		}
		closeExporter(t, e)
		server.Close()
	}
}

func TestTransportResponseLimitsAndFalseAcknowledgements(t *testing.T) {
	cases := []struct{ contentType, encoding, body string }{
		{"application/json", "", strings.Repeat("x", (64<<10)+1)},
		{"application/json", "gzip", `{}`}, {"text/plain", "", `{}`},
		{"application/json", "", ""}, {"application/json", "", `{"partialSuccess":{},"partialSuccess":null}`},
	}
	for _, item := range cases {
		var calls atomic.Uint64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", item.contentType)
			if item.encoding != "" {
				w.Header().Set("Content-Encoding", item.encoding)
			}
			_, _ = io.WriteString(w, item.body)
		}))
		e, err := New(testConfig(server.URL), nil)
		if err != nil {
			t.Fatal(err)
		}
		if e.send(context.Background(), 1, []byte(`{}`), 1) || calls.Load() != 1 {
			t.Error("invalid or oversized success response accepted/retried")
		}
		closeExporter(t, e)
		server.Close()
	}
}

func TestTransportConnectionResetUsesBoundedRetries(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
	}))
	defer server.Close()
	e, err := New(testConfig(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	if e.send(context.Background(), 1, []byte(`{}`), 1) || calls.Load() != 3 {
		t.Fatal("connection reset did not stop at the retry bound")
	}
}

func makeTLSMaterials(t *testing.T) (Config, *tls.Config) {
	t.Helper()
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OTLP test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
		certPath, keyPath := filepath.Join(directory, name+".pem"), filepath.Join(directory, name+".key")
		if os.WriteFile(certPath, certPEM, 0o644) != nil || os.WriteFile(keyPath, keyPEM, 0o600) != nil {
			t.Fatal("cannot write TLS fixture identities")
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPath, keyPath
	}
	server, _, _ := issue("server", 2, x509.ExtKeyUsageServerAuth)
	_, certPath, keyPath := issue("client", 3, x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	// Add the parsed certificate (including its actual DER) for client checks.
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(parsed)
	return Config{CAFile: caPath, ClientCertFile: certPath, ClientKeyFile: keyPath, Signals: []string{"logs"}, IntervalMS: 60000},
		&tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
}

func TestTransportVerifiedTLSAndRequiredClientIdentity(t *testing.T) {
	config, serverTLS := makeTLSMaterials(t)
	var accepted atomic.Uint64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accepted.Add(1); ack(w) }))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	config.Endpoint = server.URL
	e, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !e.send(context.Background(), 1, []byte(`{}`), 1) || accepted.Load() != 1 {
		t.Fatal("valid mTLS export rejected")
	}
	closeExporter(t, e)
	config.ClientCertFile, config.ClientKeyFile = "", ""
	missing, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if missing.send(context.Background(), 1, []byte(`{}`), 1) || accepted.Load() != 1 {
		t.Fatal("server accepted missing client identity")
	}
	closeExporter(t, missing)
	config.CAFile = ""
	unknown, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.send(context.Background(), 1, []byte(`{}`), 1) || unknown.Stats().Signals["logs"].Retries != 0 || accepted.Load() != 1 {
		t.Fatal("untrusted TLS accepted or retried")
	}
	closeExporter(t, unknown)
}
