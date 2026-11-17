package sandbox

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreviewSDKMTLSAPIAndLauncher(t *testing.T) {
	// mTLS/API, UDS launcher, native codec and guest application TCP are real.
	// The guest's protocol service is scripted; this is not KVM/vsock evidence.
	buildDir := t.TempDir()
	binary := filepath.Join(buildDir, "osv-sandbox-mcp")
	buildCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	output, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "../../cmd/osv-sandbox-mcp").CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build MCP: %v %s", err, output)
	}
	for _, runtime := range []string{"python", "node", "mcp-modern", "mcp-legacy"} {
		t.Run(runtime, func(t *testing.T) {
			f := newPreviewFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("preview upstream credentials/body invalid")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(append([]byte{0, 255}, body...))
			}))
			_, frontPort, _ := net.SplitHostPort(f.front.Listener.Addr().String())
			f.service.base.Host = "preview.test:" + frontPort
			f.service.config.OriginBase = f.service.base.String()
			f.api.session.capability.AllowedEntrypoints = []string{"/bin/bash"}
			dir := t.TempDir()
			write := func(name string, data []byte) string {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			cert := f.api.tls.Certificates[0]
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"url": f.api.server.URL, "session": f.api.session.info, "port": f.port,
				"result": filepath.Join(dir, "grant.json"), "binary": binary, "legacy": runtime == "mcp-legacy",
				"cert": write("client.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
				"key":  write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
				"ca":   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]}))}
			mcpConfig := map[string]any{"api_url": f.api.server.URL, "ca_file": config["ca"], "cert_file": config["cert"], "key_file": config["key"], "token_file": write("token", []byte("token-a")), "max_in_flight": 1}
			data, _ := json.Marshal(mcpConfig)
			config["mcp_config"] = write("mcp.json", data)
			data, _ = json.Marshal(config)
			configPath := write("config.json", data)
			interpreter, script := "python3", "e2e-python-preview.py"
			if runtime == "node" {
				interpreter, script = "node", "e2e-node-preview.mjs"
			} else if strings.HasPrefix(runtime, "mcp-") {
				script = "e2e-mcp-preview.py"
			}
			run := func(phase string) {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, interpreter, filepath.Join("..", "..", "scripts", script), configPath, phase).CombinedOutput()
				if err != nil {
					t.Fatalf("%s %s: %v %s", runtime, phase, err, output)
				}
				if bytes.Count(output, []byte("PASS ")) != 1 {
					t.Fatalf("client assertion missing: %s", output)
				}
				t.Log(strings.TrimSpace(string(output)))
			}
			run("create")
			data, err = os.ReadFile(config["result"].(string))
			var info PreviewGrantInfo
			if err != nil || json.Unmarshal(data, &info) != nil || info.ValidateFor(f.api.session.info.ID, strings.Repeat("b", 24), f.port, true) != nil {
				t.Fatal("client did not retain valid grant metadata")
			}
			if f.guest.opens.Load() != 0 {
				t.Fatal("creating a grant unexpectedly dialed guest TCP")
			}
			cookie := f.bootstrap(t, info)
			body := bytes.Repeat([]byte{0, 255, 42}, 10000)
			response := f.request(t, "POST", info.Origin+"/echo?source=sdk", cookie, nil, bytes.NewReader(body))
			if response.StatusCode != 200 || !bytes.Equal(previewRead(t, response), append([]byte{0, 255}, body...)) || f.guest.opens.Load() != 1 {
				t.Fatal("grant did not survive client exit or proxy binary app data")
			}
			t.Log("PASS post-exit bootstrap and 30000-byte application relay")
			f.api.apiTenant.policy.Ports.Preview = false
			run("control")
			response = f.request(t, "GET", info.Origin+"/", cookie, nil, nil)
			if response.StatusCode != 404 {
				t.Fatal("revoked grant still usable")
			}
			previewRead(t, response)
			t.Log("PASS revoked browser origin unavailable")
		})
	}
}
