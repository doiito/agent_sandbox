package sandbox

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortSDKMTLSAPIAndLauncher(t *testing.T) {
	for _, runtime := range []string{"python3", "node", "mcp"} {
		t.Run(runtime, func(t *testing.T) {
			dir := t.TempDir()
			pendingMarker := filepath.Join(dir, "pending-open")
			interpreter := runtime
			if runtime == "mcp" {
				interpreter = "python3"
			}
			if _, err := exec.LookPath(interpreter); err != nil {
				t.Fatal(err)
			}
			var slowStarted, slowComplete atomic.Bool
			f := newPortHTTPFixture(t, func(c net.Conn, reader *bufio.Reader, r linuxPortRequest) {
				if r.Operation != "open" {
					if r.Operation == "cancel" && r.ID[len(r.ID)-1] == 'a' && (!slowStarted.Load() || slowComplete.Load()) {
						t.Error("slow reader did not create reverse backpressure")
					}
					sendPortControlInfo(c, r, "cancelled")
					return
				}
				if r.ID[len(r.ID)-1] == 'b' {
					if err := os.WriteFile(pendingMarker, []byte(r.ID), 0600); err != nil {
						t.Error(err)
					}
					_, _ = io.Copy(io.Discard, reader)
					return
				}
				if writePortBytes(c, testPortJSON(testPortReply(r))) != nil {
					return
				}
				mode := r.ID[len(r.ID)-1]
				if mode == 'a' {
					slowStarted.Store(true)
					slowComplete.Store(false)
					data := testPortFrame(portDataFrame, make([]byte, 16384))
					for i := 0; i < 1024; i++ {
						if writePortBytes(c, data) != nil {
							return
						}
					}
					slowComplete.Store(true)
					return
				}
				if mode >= '4' {
					_, _ = io.Copy(io.Discard, reader)
					return
				}
				if mode == '2' {
					if writePortBytes(c, testPortFrame(portEOFFrame, nil)) != nil {
						return
					}
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
						t.Error("unexpected client frame")
						return
					}
					count += uint64(len(data))
					if mode == '1' {
						if writePortBytes(c, testPortFrame(portDataFrame, data)) != nil {
							return
						}
					}
				}
				if mode == '3' {
					return
				}
				var received uint64
				if mode == '1' {
					received = count
					if writePortBytes(c, testPortFrame(portEOFFrame, nil)) != nil {
						return
					}
				}
				body, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed", SentBytes: count, ReceivedBytes: received})
				_ = writePortBytes(c, testPortFrame(portFinishedFrame, body))
			})
			f.session.capability.AllowedEntrypoints = []string{"/bin/bash"}
			f.session.capability.Methods = []string{}
			f.session.capability.Limits = CapabilityLimits{PortConnections: 8, PortConnectionIDs: 256, PortFrameBytes: 16384, PortMaxBytes: 64 << 20, PortTimeoutMS: 300000}
			cert := f.tls.Certificates[0]
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			write := func(name string, data []byte) string {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			config := map[string]any{"url": f.server.URL, "session": f.session.info, "pending_marker": pendingMarker,
				"cert": write("client.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
				"key":  write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
				"ca":   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]}))}
			if runtime == "mcp" {
				binary := filepath.Join(dir, "osv-sandbox-mcp")
				buildCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				output, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "../../cmd/osv-sandbox-mcp").CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("build MCP: %v %s", err, output)
				}
				mcpConfig := map[string]any{"api_url": f.server.URL, "ca_file": config["ca"], "cert_file": config["cert"], "key_file": config["key"], "token_file": write("token", []byte("token-a")), "max_in_flight": 1}
				data, _ := json.Marshal(mcpConfig)
				config["mcp_config"] = write("mcp.json", data)
				config["binary"] = binary
			}
			data, _ := json.Marshal(config)
			path := write("config.json", data)
			script := "e2e-python-ports.py"
			if runtime == "node" {
				script = "e2e-node-ports.mjs"
			}
			if runtime == "mcp" {
				script = "e2e-mcp-ports.py"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, interpreter, filepath.Join("..", "..", "scripts", script), path)
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("SDK actual TLS fixture: %v", err)
			}
			expected := 8
			if runtime == "mcp" {
				expected = 20
			}
			if strings.Count(string(output), "PASS ") != expected {
				t.Fatal("not all SDK fixture cases ran")
			}
			if f.owner.portSem != nil && len(f.owner.portSem) != 0 {
				t.Fatal("tenant port slot leaked")
			}
		})
	}
}
