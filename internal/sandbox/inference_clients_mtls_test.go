package sandbox

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The processes, mTLS, Unix RPC, TLS model and billing are real. VM ownership is
// explicitly constructed by inferenceHTTPFixture; this is not guest/KVM proof.
func TestRemoteInferenceClientsMTLS(t *testing.T) {
	requireGuestProxyRoot(t)
	for _, runtime := range []string{"python", "node", "mcp"} {
		t.Run(runtime, func(t *testing.T) {
			directory := t.TempDir()
			marker := filepath.Join(directory, "pending-provider")
			secretFile := filepath.Join(directory, "provider.token")
			if err := os.WriteFile(secretFile, []byte("private-inference-fixture-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			var calls, cancellations, wrongCredentials atomic.Int32
			provider, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer private-inference-fixture-secret" || r.TLS.ServerName != "allowed.test" {
					wrongCredentials.Add(1)
				}
				var payload struct {
					Mode string `json:"mode"`
				}
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &payload)
				w.Header().Set("Content-Type", "application/json")
				if payload.Mode == "pending" {
					_, _ = w.Write([]byte(`{"pending":`))
					w.(http.Flusher).Flush()
					if err := os.WriteFile(marker, []byte("ready"), 0600); err != nil {
						t.Error(err)
					}
					<-r.Context().Done()
					cancellations.Add(1)
					return
				}
				if payload.Mode == "unicode" {
					// Raw UTF-8 is within the provider body budget; transport JSON
					// escaping expands it beyond the previous launcher frame limit.
					_, _ = w.Write([]byte(`{"text":"` + strings.Repeat("\u2028", 140000) + `"}`))
					return
				}
				_, _ = w.Write([]byte(`{"answer":"ok"}`))
			}))
			_, port, _ := net.SplitHostPort(provider.Listener.Addr().String())
			service, _, main, _, _ := inferenceServiceFixture(t, "https://allowed.test:"+port+"/invoke", func(network *EgressPolicy, policy *InferencePolicy) {
				network.MaxRequestBytes, network.MaxResponseBytes, network.TimeoutMS = 4096, 512<<10, 10000
				budget := InferenceUnits(math.MaxUint64)
				policy.BudgetUnits = &budget
				policy.Endpoints[0].Price.RequestUnits = InferenceUnits(9007199254740993)
				policy.Endpoints[0].Credential = &InferenceCredential{File: secretFile, Header: "Authorization", Prefix: "Bearer "}
			})
			service.engine.roots = roots
			service.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			handler, _, session, _ := inferenceHTTPFixture(t, service, main)
			serverTLS, clientTLS := portTLSFixture(t)
			var rejectedDiscovery atomic.Int32
			tlsAPI := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if session.ctx.Err() != nil && (r.URL.Path == "/v1/capabilities" || r.URL.Path == "/v2/templates") {
					rejectedDiscovery.Add(1)
					writeJobError(w, 503, "unavailable", "new admission unavailable", true)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			tlsAPI.TLS = serverTLS
			tlsAPI.Config.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
			tlsAPI.StartTLS()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = handler.(*apiHTTPHandler).Shutdown(ctx)
				tlsAPI.Close()
			})
			write := func(name string, data []byte) string {
				path := filepath.Join(directory, name)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			cert := clientTLS.Certificates[0]
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"url": tlsAPI.URL, "session": session.Info(), "pending_marker": marker,
				"cert": write("client.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
				"key":  write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
				"ca":   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]}))}
			if runtime == "mcp" {
				binary := filepath.Join(directory, "osv-sandbox-mcp")
				build, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				command := exec.CommandContext(build, "go", "build", "-buildvcs=false", "-trimpath", "-o", binary, "../../cmd/osv-sandbox-mcp")
				command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off")
				output, err := command.CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("MCP compile: %v %s", err, output)
				}
				program, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("MCP_ELF_SHA256 %x", sha256.Sum256(program))
				config["binary"] = binary
				for _, suffix := range []string{"", "-other"} {
					token := "inference-test-token"
					if suffix != "" {
						token = "inference-other-token"
					}
					value := map[string]any{"api_url": tlsAPI.URL, "ca_file": config["ca"], "cert_file": config["cert"], "key_file": config["key"],
						"token_file": write("token"+suffix, []byte(token)), "max_in_flight": 1}
					data, _ := json.Marshal(value)
					config["mcp_config"+suffix] = write("mcp"+suffix+".json", data)
				}
			}
			data, _ := json.Marshal(config)
			path := write("client-config.json", data)
			interpreter, script := "python3", "test-inference-clients.py"
			if runtime == "node" {
				interpreter, script = "node", "test-inference-node.mjs"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, interpreter, filepath.Join("..", "..", "scripts", script), path, runtime)
			command.Env = append(os.Environ(), "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("actual inference client chain: %v", err)
			}
			expected := 8
			if runtime == "mcp" {
				expected = 9
			}
			if strings.Count(string(output), "PASS ") != expected {
				t.Fatal("not all declared client cases ran")
			}
			if calls.Load() != 3 || cancellations.Load() != 1 || wrongCredentials.Load() != 0 || rejectedDiscovery.Load() < 1 {
				t.Fatal("provider replay, credential, cancellation or history independence regression", calls.Load(), cancellations.Load(), wrongCredentials.Load(), rejectedDiscovery.Load())
			}
			bill, err := service.inference.ledger.bill("tenant-a", session.info.ID)
			if err != nil || !bill.Closed || len(bill.Invocations) != 3 || bill.HeldUnits == 0 || bill.ValidateForTask(session.info.ID) != nil {
				t.Fatal("durable metering or task cleanup failed", bill, err)
			}
			if err := handler.(*apiHTTPHandler).Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
