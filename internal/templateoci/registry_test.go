package templateoci

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
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

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

const testRepository = "tenant/templates"
const uploadQuery = "state=a%2Bb%2Fc&opaque=z%2Bx"

type registryFixture struct {
	mu            sync.Mutex
	blobs         map[string][]byte
	manifest      []byte
	counts        map[string]int
	authorization string
	hook          func(http.ResponseWriter, *http.Request) bool
}

func newRegistryFixture(auth string) *registryFixture {
	return &registryFixture{blobs: map[string][]byte{}, counts: map[string]int{}, authorization: auth}
}
func (s *registryFixture) setHook(hook func(http.ResponseWriter, *http.Request) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = hook
}
func (s *registryFixture) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[key]
}
func (s *registryFixture) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.counts[r.Method+" "+r.URL.Path]++
	hook, auth := s.hook, s.authorization
	s.mu.Unlock()
	if auth != "" && r.Header.Get("Authorization") != auth {
		w.WriteHeader(401)
		io.WriteString(w, "private remote error body must not be exposed")
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	prefix := "/v2/" + testRepository + "/"
	if strings.HasPrefix(r.URL.Path, prefix+"manifests/") {
		if r.Method == http.MethodPut {
			data, err := io.ReadAll(io.LimitReader(r.Body, metadataLimit+1))
			if err != nil || len(data) > int(metadataLimit) || r.Header.Get("Content-Type") != ManifestMediaType {
				w.WriteHeader(400)
				return
			}
			s.mu.Lock()
			s.manifest = append([]byte(nil), data...)
			s.mu.Unlock()
			w.Header().Set("Docker-Content-Digest", digest(data))
			w.WriteHeader(201)
			return
		}
		s.mu.Lock()
		data := append([]byte(nil), s.manifest...)
		s.mu.Unlock()
		if len(data) == 0 {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", ManifestMediaType+"; charset=utf-8")
		w.Header().Set("Docker-Content-Digest", digest(data))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			w.Write(data)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, prefix+"blobs/uploads/") {
		if r.Method == http.MethodPost {
			w.Header().Set("Location", prefix+"blobs/uploads/session?"+uploadQuery)
			w.WriteHeader(202)
			return
		}
		if r.Method == http.MethodPut {
			if !strings.HasPrefix(r.URL.RawQuery, uploadQuery+"&digest=") {
				w.WriteHeader(400)
				return
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
			if err != nil || digest(data) != r.URL.Query().Get("digest") || r.ContentLength != int64(len(data)) {
				w.WriteHeader(400)
				return
			}
			s.mu.Lock()
			s.blobs[digest(data)] = append([]byte(nil), data...)
			s.mu.Unlock()
			w.Header().Set("Docker-Content-Digest", digest(data))
			w.WriteHeader(201)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, prefix+"blobs/") {
		key := strings.TrimPrefix(r.URL.Path, prefix+"blobs/")
		s.mu.Lock()
		data, exists := s.blobs[key]
		data = append([]byte(nil), data...)
		s.mu.Unlock()
		if !exists {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Docker-Content-Digest", key)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			w.Write(data)
		}
		return
	}
	w.WriteHeader(404)
}
func startRegistryFixture(t *testing.T, state *registryFixture) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(state.serve))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)
	return server
}
func clientFor(t *testing.T, server string, authFile string) *Registry {
	t.Helper()
	r, err := NewRegistry(RegistryOptions{URL: server, PlainHTTP: true, AuthFile: authFile, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}
func populateRegistry(t *testing.T, state *registryFixture, layout string, d Descriptor) {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	state.manifest = mustRead(t, filepath.Join(layout, blobName(d)))
	entries, err := os.ReadDir(filepath.Join(layout, "blobs/sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		state.blobs["sha256:"+entry.Name()] = mustRead(t, filepath.Join(layout, "blobs/sha256", entry.Name()))
	}
}

func TestRegistryPushPullRoundTripAndBlobDeduplication(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	state := newRegistryFixture("")
	server := startRegistryFixture(t, state)
	r := clientFor(t, server.URL, "")
	for i := 0; i < 2; i++ {
		got, err := r.Push(context.Background(), layout, d.Digest, testRepository, "release-1", f.options)
		if err != nil || got.Digest != d.Digest {
			t.Fatalf("push %+v %v", got, err)
		}
	}
	if got := state.count("POST /v2/" + testRepository + "/blobs/uploads/"); got != 6 {
		t.Fatalf("second push uploaded existing blobs, POST=%d", got)
	}
	if got := state.count("PUT /v2/" + testRepository + "/manifests/release-1"); got != 2 {
		t.Fatalf("manifest commits=%d", got)
	}
	parent := t.TempDir()
	pulled := filepath.Join(parent, "pulled")
	got, err := r.Pull(context.Background(), d.Digest, testRepository, pulled, f.options)
	if err != nil || got.Digest != d.Digest {
		t.Fatalf("pull %+v %v", got, err)
	}
	imported := filepath.Join(parent, "imported")
	if _, err := Import(context.Background(), pulled, d.Digest, imported, f.options); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(imported, f.metadata.Image.Path)), mustRead(t, filepath.Join(f.root, f.metadata.Image.Path))) {
		t.Fatal("registry roundtrip changed signed image")
	}
}

func TestRegistryBasicAndBearerAuthentication(t *testing.T) {
	for _, kind := range []string{"basic", "bearer"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			layout, d := exportFixture(t, f)
			authFile := filepath.Join(t.TempDir(), "auth.json")
			expected := "Bearer fixture-token"
			if kind == "basic" {
				mustWrite(t, authFile, []byte(`{"username":"fixture-user","password":"fixture-password"}`))
				expected = "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password"))
			} else {
				mustWrite(t, authFile, []byte(`{"token":"fixture-token"}`))
			}
			state := newRegistryFixture(expected)
			server := startRegistryFixture(t, state)
			anonymous := clientFor(t, server.URL, "")
			if _, err := anonymous.Push(context.Background(), layout, d.Digest, testRepository, "", f.options); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "private remote") {
				t.Fatalf("unauthorized error leaked or succeeded: %v", err)
			}
			r := clientFor(t, server.URL, authFile)
			if _, err := r.Push(context.Background(), layout, d.Digest, testRepository, "", f.options); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Pull(context.Background(), d.Digest, testRepository, filepath.Join(t.TempDir(), "pulled"), f.options); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegistryPreflightRejectsChangedLocalBlobBeforeNetworking(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	path := filepath.Join(layout, "blobs/sha256", f.metadata.Image.SHA256)
	data := mustRead(t, path)
	data[0] ^= 1
	mustWrite(t, path, data)
	state := newRegistryFixture("")
	server := startRegistryFixture(t, state)
	r := clientFor(t, server.URL, "")
	if _, err := r.Push(context.Background(), layout, d.Digest, testRepository, "", f.options); err == nil {
		t.Fatal("pushed changed local blob")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.counts) != 0 {
		t.Fatal("contacted registry before validating local artifacts")
	}
}

func TestRegistryPullAuthenticatesBeforeLargeDownloads(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	d = mutateSigned(t, layout, d, f, func(m *sandbox.SignedArtifactManifest) { m.ExpiresAt = m.ExpiresAt.Add(time.Hour) }, false)
	state := newRegistryFixture("")
	populateRegistry(t, state, layout, d)
	server := startRegistryFixture(t, state)
	r := clientFor(t, server.URL, "")
	target := filepath.Join(t.TempDir(), "pulled")
	_, err := r.Pull(context.Background(), d.Digest, testRepository, target, f.options)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature accepted: %v", err)
	}
	assertNotPublished(t, target)
	if state.count("GET /v2/"+testRepository+"/blobs/sha256:"+f.metadata.Image.SHA256) != 0 {
		t.Fatal("downloaded image before authenticating metadata")
	}
}

func TestRegistryPullRefusesCorruptResponsesAndCleansStage(t *testing.T) {
	for _, kind := range []string{"manifest-media", "manifest-digest", "blob-header", "blob-bytes", "blob-length", "encoding", "remote-secret"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			layout, d := exportFixture(t, f)
			state := newRegistryFixture("")
			populateRegistry(t, state, layout, d)
			state.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				isManifest := strings.Contains(r.URL.Path, "/manifests/")
				isImage := strings.HasSuffix(r.URL.Path, f.metadata.Image.SHA256)
				if kind == "remote-secret" {
					w.WriteHeader(503)
					io.WriteString(w, "REMOTE_PRIVATE_BODY")
					return true
				}
				if isManifest && (kind == "manifest-media" || kind == "manifest-digest") {
					media := ManifestMediaType
					data := mustRead(t, filepath.Join(layout, blobName(d)))
					if kind == "manifest-media" {
						media = "application/json"
					} else {
						data = append(data, ' ')
					}
					w.Header().Set("Content-Type", media)
					w.Write(data)
					return true
				}
				if isImage {
					data := mustRead(t, filepath.Join(f.root, f.metadata.Image.Path))
					switch kind {
					case "blob-header":
						w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
					case "blob-bytes":
						data[0] ^= 1
					case "blob-length":
						w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
					case "encoding":
						w.Header().Set("Content-Encoding", "gzip")
					default:
						return false
					}
					w.Write(data)
					return true
				}
				return false
			})
			server := startRegistryFixture(t, state)
			r := clientFor(t, server.URL, "")
			target := filepath.Join(t.TempDir(), "pulled")
			if _, err := r.Pull(context.Background(), d.Digest, testRepository, target, f.options); err == nil || strings.Contains(err.Error(), "REMOTE_PRIVATE_BODY") {
				t.Fatalf("corrupt response accepted or exposed: %v", err)
			}
			assertNotPublished(t, target)
		})
	}
}

func TestRegistryCrossOriginRequestsNeverReceiveCredentials(t *testing.T) {
	for _, kind := range []string{"upload-location", "get-redirect", "write-redirect"} {
		t.Run(kind, func(t *testing.T) {
			var leaked atomic.Int32
			attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
			defer attacker.Close()
			f := newFixture(t)
			layout, d := exportFixture(t, f)
			authFile := filepath.Join(t.TempDir(), "auth.json")
			mustWrite(t, authFile, []byte(`{"token":"NEVER_FORWARD_THIS_TOKEN"}`))
			state := newRegistryFixture("Bearer NEVER_FORWARD_THIS_TOKEN")
			populateRegistry(t, state, layout, d)
			state.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				if kind == "get-redirect" && r.Method == http.MethodGet {
					http.Redirect(w, r, attacker.URL+"/redirect?private=SECRET_STATE", 307)
					return true
				}
				if kind != "get-redirect" && r.Method == http.MethodPost {
					if kind == "upload-location" {
						w.Header().Set("Location", attacker.URL+"/upload?private=SECRET_STATE")
						w.WriteHeader(202)
					} else {
						http.Redirect(w, r, attacker.URL+"/upload?private=SECRET_STATE", 307)
					}
					return true
				}
				return false
			})
			if kind != "get-redirect" {
				state.mu.Lock()
				state.blobs = map[string][]byte{}
				state.mu.Unlock()
			}
			server := startRegistryFixture(t, state)
			r := clientFor(t, server.URL, authFile)
			var err error
			if kind == "get-redirect" {
				_, err = r.Pull(context.Background(), d.Digest, testRepository, filepath.Join(t.TempDir(), "pulled"), f.options)
			} else {
				_, err = r.Push(context.Background(), layout, d.Digest, testRepository, "", f.options)
			}
			if err == nil || strings.Contains(err.Error(), "SECRET_STATE") || strings.Contains(err.Error(), "NEVER_FORWARD") {
				t.Fatalf("unsafe redirect succeeded or error leaked details: %v", err)
			}
			if leaked.Load() != 0 {
				t.Fatal("cross-origin request was sent")
			}
		})
	}
}

func TestRegistryPublicationDisconnectRetainsKnownDigestWithoutReplay(t *testing.T) {
	for _, kind := range []string{"commit-disconnect", "readback-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			layout, d := exportFixture(t, f)
			state := newRegistryFixture("")
			state.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.Contains(r.URL.Path, "/manifests/") {
					return false
				}
				if kind == "readback-failure" && r.Method == http.MethodGet {
					w.WriteHeader(503)
					return true
				}
				if kind == "commit-disconnect" && r.Method == http.MethodPut {
					data, _ := io.ReadAll(r.Body)
					state.mu.Lock()
					state.manifest = data
					state.mu.Unlock()
					connection, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						connection.Close()
					}
					return true
				}
				return false
			})
			server := startRegistryFixture(t, state)
			r := clientFor(t, server.URL, "")
			got, err := r.Push(context.Background(), layout, d.Digest, testRepository, "release-1", f.options)
			var uncertain *PublicationUnconfirmed
			if !errors.As(err, &uncertain) || uncertain.Digest != d.Digest || got.Digest != d.Digest {
				t.Fatalf("lost operation identity: %+v %v", got, err)
			}
			if state.count("PUT /v2/"+testRepository+"/manifests/release-1") != 1 {
				t.Fatal("replayed an unconfirmed manifest publication")
			}
		})
	}
}

func TestRegistryPullCancellationDuringNetworkImageRead(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	state := newRegistryFixture("")
	populateRegistry(t, state, layout, d)
	started := make(chan struct{})
	state.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, f.metadata.Image.SHA256) {
			w.Header().Set("Content-Length", strconv.FormatInt(f.metadata.ImageSize, 10))
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
			return true
		}
		return false
	})
	server := startRegistryFixture(t, state)
	r := clientFor(t, server.URL, "")
	target := filepath.Join(t.TempDir(), "pulled")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Pull(ctx, d.Digest, testRepository, target, f.options); done <- err }()
	select {
	case <-started:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("image request did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled network transfer did not return")
	}
	assertNotPublished(t, target)
}

func TestRegistryRejectsUnsafeConfiguration(t *testing.T) {
	for _, raw := range []string{"http://registry.example", "https://user:secret@registry.example", "https://registry.example/path", "https://registry.example?secret=1", "https://registry.example#fragment", "file:///tmp/registry"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewRegistry(RegistryOptions{URL: raw, PlainHTTP: true}); err == nil {
				t.Fatal("accepted unsafe origin")
			}
		})
	}
	for _, text := range []string{`{"token":"a","username":"u","password":"p"}`, `{"token":"bad\ntoken"}`, `{"username":"u:x","password":"p"}`, `{"username":"u"}`, `{"token":"x","extra":"y"}`} {
		t.Run("credentials-"+fmt.Sprint(len(text)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth.json")
			mustWrite(t, path, []byte(text))
			if _, err := NewRegistry(RegistryOptions{URL: "https://registry.example", AuthFile: path}); err == nil {
				t.Fatal("accepted invalid credentials")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "public-auth.json")
	mustWrite(t, path, []byte(`{"token":"x"}`))
	os.Chmod(path, 0o644)
	if _, err := NewRegistry(RegistryOptions{URL: "https://registry.example", AuthFile: path}); err == nil {
		t.Fatal("accepted public-readable credentials")
	}
}

func registryTLSFiles(t *testing.T) (*tls.Config, string, string, string) {
	t.Helper()
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OCI test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	caPath := filepath.Join(root, "ca.crt")
	mustWrite(t, caPath, caPEM)
	issue := func(serial int64, server bool) (tls.Certificate, []byte, []byte) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		}
		data, err := x509.CreateCertificate(rand.Reader, certificate, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
		keyDER, err := x509.MarshalECPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(encoded, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, encoded, keyPEM
	}
	server, _, _ := issue(2, true)
	_, cert, keyPEM := issue(3, false)
	certPath, keyPath := filepath.Join(root, "client.crt"), filepath.Join(root, "client.key")
	mustWrite(t, certPath, cert)
	mustWrite(t, keyPath, keyPEM)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, caPath, certPath, keyPath
}

func TestRegistryVerifiedTLSAndMutualTLS(t *testing.T) {
	f := newFixture(t)
	layout, d := exportFixture(t, f)
	state := newRegistryFixture("")
	security, ca, cert, key := registryTLSFiles(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(state.serve))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = security
	server.StartTLS()
	defer server.Close()
	for _, options := range []RegistryOptions{{URL: server.URL}, {URL: server.URL, CAFile: ca}} {
		r, err := NewRegistry(options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Push(context.Background(), layout, d.Digest, testRepository, "", f.options)
		r.Close()
		if err == nil {
			t.Fatal("accepted untrusted TLS or missing client identity")
		}
	}
	r, err := NewRegistry(RegistryOptions{URL: server.URL, CAFile: ca, ClientCertFile: cert, ClientKeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Push(context.Background(), layout, d.Digest, testRepository, "", f.options); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Pull(context.Background(), d.Digest, testRepository, filepath.Join(t.TempDir(), "pulled"), f.options); err != nil {
		t.Fatal(err)
	}
}
