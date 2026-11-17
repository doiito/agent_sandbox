package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type inferenceCountedConn struct {
	net.Conn
	written atomic.Int64
}

func (c *inferenceCountedConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.written.Add(int64(n))
	return n, err
}

// Real Python/Node processes, fixed TCP route, production root relay, egress,
// TLS credential injection and persistent ledger. The bridge replaces the VM
// vsock device. The optional C shim checks ctypes ABI only, not OSv boot/KVM.
func TestRemoteInferenceGuestSDKs(t *testing.T) {
	requireGuestProxyRoot(t)
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for index, mode := range []string{"python", "node", "python-osv-abi"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			marker, secret := filepath.Join(directory, "pending"), filepath.Join(directory, "secret")
			if err := os.WriteFile(secret, []byte("fixture-guest-model-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			const unicodeCount = (egressResponseLimit - 32) / 3
			var calls, cancellations, wrongCredentials atomic.Int32
			provider, roots := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer fixture-guest-model-secret" || r.TLS.ServerName != "allowed.test" {
					wrongCredentials.Add(1)
				}
				var input struct {
					Mode string `json:"mode"`
				}
				data, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(data, &input)
				w.Header().Set("Content-Type", "application/json")
				if input.Mode == "pending" {
					_, _ = w.Write([]byte(`{"pending":`))
					w.(http.Flusher).Flush()
					if err := os.WriteFile(marker, []byte("ready"), 0600); err != nil {
						t.Error(err)
					}
					<-r.Context().Done()
					cancellations.Add(1)
					return
				}
				if input.Mode == "unicode" {
					_, _ = w.Write([]byte(`{"text":"` + strings.Repeat("\u2028", unicodeCount) + `"}`))
					return
				}
				_, _ = w.Write([]byte(`{"answer":"ok"}`))
			}))
			_, port, _ := net.SplitHostPort(provider.Listener.Addr().String())
			service, root, main, _, _ := inferenceServiceFixture(t, "https://allowed.test:"+port+"/invoke", func(n *EgressPolicy, p *InferencePolicy) {
				n.MaxRequestBytes, n.MaxResponseBytes, n.TimeoutMS = 4096, egressResponseLimit, 10000
				budget := InferenceUnits(math.MaxUint64)
				p.BudgetUnits = &budget
				p.Endpoints[0].Price.RequestUnits = InferenceUnits(9007199254740993)
				p.Endpoints[0].Credential = &InferenceCredential{File: secret, Header: "Authorization", Prefix: "Bearer "}
			})
			service.engine.roots = roots
			service.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			binding := inferenceTestBinding()
			binding.TaskID = fmt.Sprintf("%024x", index+100)
			if _, err := root.task(context.Background(), "bind", binding); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			proxy := &vmGuestProxy{ctx: ctx, egressSocket: main, tenant: binding.Tenant, vmID: binding.VMID,
				leaseID: binding.LeaseID, inference: &binding,
				inferencePolicySHA256: (&Manager{inferenceAuth: service.auth}).inferencePolicyDigest(binding.Tenant)}
			listener, err := net.Listen("tcp4", "127.0.0.1:3128")
			if err != nil {
				cancel()
				t.Fatal("fixed guest proxy fixture port unavailable", err)
			}
			var workers sync.WaitGroup
			var largest atomic.Int64
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer connection.Close()
						counted := &inferenceCountedConn{Conn: connection}
						proxy.relay(counted)
						value := counted.written.Load()
						for previous := largest.Load(); value > previous; previous = largest.Load() {
							if largest.CompareAndSwap(previous, value) {
								break
							}
						}
					}()
				}
			}()
			t.Cleanup(func() {
				cancel()
				listener.Close()
				<-done
				workers.Wait()
				_, _ = root.task(context.Background(), "close", binding)
			})
			config, _ := json.Marshal(map[string]any{"task_id": binding.TaskID, "pending_marker": marker, "unicode_count": unicodeCount})
			configPath := filepath.Join(directory, "config.json")
			if err := os.WriteFile(configPath, config, 0600); err != nil {
				t.Fatal(err)
			}
			interpreter, script := "python3", "test-guest-inference.py"
			if mode == "node" {
				interpreter, script = "node", "test-guest-inference.cjs"
			}
			process, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			command := exec.CommandContext(process, interpreter, filepath.Join(project, "scripts", script), configPath, mode)
			command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
			if mode == "python-osv-abi" {
				library := filepath.Join(directory, "vsock-test-only.so")
				compiler := exec.CommandContext(process, "cc", "-shared", "-fPIC", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
					"-o", library, filepath.Join(project, "tests/guest_inference_vsock_shim.c"))
				if output, err := compiler.CombinedOutput(); err != nil {
					t.Fatalf("test-only ABI shim compile: %v %s", err, output)
				}
				command.Env = append(command.Env, "LD_PRELOAD="+library)
			}
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("guest SDK component chain: %v", err)
			}
			expectedCases, expectedCalls, expectedCancel := 11, int32(4), int32(1)
			if mode == "node" {
				expectedCases, expectedCalls, expectedCancel = 12, 5, 2
			}
			if mode == "python-osv-abi" {
				expectedCases = 12
			}
			if strings.Count(string(output), "PASS ") != expectedCases || calls.Load() != expectedCalls || cancellations.Load() != expectedCancel || wrongCredentials.Load() != 0 {
				t.Fatal("missing cases, model replay, lost cancellation or credentials", calls.Load(), cancellations.Load(), wrongCredentials.Load())
			}
			if _, err := root.task(context.Background(), "close", binding); err != nil {
				t.Fatal(err)
			}
			bill, err := service.inference.ledger.bill(binding.Tenant, binding.TaskID)
			if err != nil || !bill.Closed || len(bill.Invocations) != int(expectedCalls) || bill.HeldUnits == 0 || bill.ValidateForTask(binding.TaskID) != nil {
				t.Fatal("guest task bill was not durably closed", err)
			}
			// Wait for the root relay's final byte accounting before asserting.
			deadline := time.Now().Add(time.Second)
			for largest.Load() < 500<<10 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if largest.Load() < 500<<10 || largest.Load() > 1<<20 {
				t.Fatal("maximum UTF-8 body and receipt did not fit the actual bounded root relay", largest.Load())
			}
			t.Logf("GUEST_CHAIN model_POSTs=%d cancellations=%d maximum_HTTP_response_bytes=%d guest_VM=false OSv_boot=false", calls.Load(), cancellations.Load(), largest.Load())
		})
	}
}
