package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func egressProbe(root string) bool {
	binary := filepath.Join(root, "bin/osv-sandbox-egress")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return true
	}
	if !run("egress-guest-loopback", "/bin/busybox", "ip", "link", "set", "dev", "lo", "up") {
		return false
	}
	work, err := os.MkdirTemp("/tmp", "arm-egress-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(work)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("FAIL bundled-egress-fetch:", err)
		return false
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{0, 255, 65}) })}
	go server.Serve(listener)
	defer server.Close()
	token := "arm-qemu-disposable-egress-token"
	digest := sha256.Sum256([]byte(token))
	target := "http://" + listener.Addr().String()
	secureTarget := ""
	if fileExists("/bin/guest-http") {
		pair, e := tls.LoadX509KeyPair("/mcp/server.crt", "/mcp/server.key")
		if e != nil {
			return false
		}
		secure, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return false
		}
		secureTarget = "https://" + secure.Addr().String()
		secured := &http.Server{Handler: server.Handler}
		go secured.Serve(tls.NewListener(secure, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}))
		defer secured.Close()
	}
	auth := sandbox.AuthPolicyFile{Protocol: "osv-sandbox-auth/v1", Tenants: []sandbox.TenantPolicy{{ID: "qemu-egress", TokenSHA256: hex.EncodeToString(digest[:]), AllowedEntrypoints: []string{"/bin/sh"}, RequestsPerSecond: 20, Burst: 20, MaxConcurrent: 1, Egress: &sandbox.EgressPolicy{AllowedOrigins: []string{target}, AllowedCIDRs: []string{"127.0.0.1/32"}, MaxConcurrent: 1, MaxRequestBytes: 1024, MaxResponseBytes: 1024, TimeoutMS: 1000}}}}
	if secureTarget != "" {
		p := auth.Tenants[0].Egress
		p.AllowedOrigins = append(p.AllowedOrigins, secureTarget)
		p.MaxRequestBytes, p.MaxResponseBytes, p.TimeoutMS = 65536, 65536, 5000
	}
	data, _ := json.Marshal(auth)
	authPath := filepath.Join(work, "auth.json")
	if os.WriteFile(authPath, data, 0o600) != nil {
		return false
	}
	socket := filepath.Join(work, "e.sock")
	configuration := sandbox.EgressServiceConfig{Production: false, SocketPath: socket, AuthPolicyPath: authPath, AuditLogPath: filepath.Join(work, "audit.jsonl"), MaxConcurrent: 1}
	configuration.GuestProxy = secureTarget != ""
	if ca := filepath.Join(root, "examples/egress-public-roots.crt"); fileExists(ca) {
		configuration.CAFile = ca
	}
	data, _ = json.Marshal(configuration)
	configPath := filepath.Join(work, "config.json")
	if os.WriteFile(configPath, data, 0o600) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, binary, "-require-production=false", "-config", configPath)
	child.Stderr = os.Stderr
	if err = child.Start(); err != nil {
		fmt.Println("FAIL bundled-egress-fetch:", err)
		return false
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err = os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Println("FAIL bundled-egress-fetch: socket absent")
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 3 * time.Second}
	body, _ := json.Marshal(sandbox.NetworkFetchRequest{URL: target + "/binary"})
	request, _ := http.NewRequestWithContext(ctx, "POST", "http://egress.invalid/v1/fetch", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		fmt.Println("FAIL bundled-egress-fetch:", err)
		return false
	}
	payload, err := io.ReadAll(response.Body)
	response.Body.Close()
	var result sandbox.NetworkFetchResult
	if json.Unmarshal(payload, &result) != nil {
		fmt.Println("FAIL bundled-egress-fetch: invalid JSON")
		return false
	}
	decoded, e := base64.StdEncoding.DecodeString(result.BodyBase64)
	if err != nil || e != nil || response.StatusCode != 200 || result.Protocol != "osv-sandbox-network-fetch/v1" || !bytes.Equal(decoded, []byte{0, 255, 65}) {
		fmt.Println("FAIL bundled-egress-fetch:", string(payload))
		return false
	}
	client.CloseIdleConnections()
	if secureTarget != "" && !guestHTTPProbe(ctx, root, socket, target, secureTarget) {
		return false
	}
	if child.Process.Signal(syscall.SIGTERM) != nil {
		return false
	}
	if err = child.Wait(); err != nil {
		fmt.Println("FAIL bundled-egress-fetch: shutdown", err)
		return false
	}
	audit, err := os.ReadFile(filepath.Join(work, "audit.jsonl"))
	if err != nil || !bytes.Contains(audit, []byte("net.complete")) {
		fmt.Println("FAIL bundled-egress-fetch: audit absent")
		return false
	}
	fmt.Println("PASS bundled-egress-fetch")
	return true
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func guestHTTPProbe(ctx context.Context, root, socket, target, secureTarget string) bool {
	binary, err := os.ReadFile("/bin/guest-http")
	if err != nil {
		return false
	}
	var document struct {
		Components []struct {
			Name   string `json:"name"`
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
	}
	sbom, err := os.ReadFile(filepath.Join(root, "artifacts/sbom.cdx.json"))
	if err != nil || json.Unmarshal(sbom, &document) != nil {
		return false
	}
	bound := false
	digest := sha256.Sum256(binary)
	for _, component := range document.Components {
		if component.Name == "osv-http-guest-client" {
			for _, hash := range component.Hashes {
				bound = bound || (hash.Alg == "SHA-256" && hash.Content == hex.EncodeToString(digest[:]))
			}
		}
	}
	if !bound {
		fmt.Println("FAIL bundled-guest-http-source-binding")
		return false
	}
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			client, err := proxy.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				stop := context.AfterFunc(proxyCtx, func() { _ = client.Close() })
				defer stop()
				upstream, err := (&net.Dialer{}).DialContext(proxyCtx, "unix", socket)
				if err != nil {
					return
				}
				defer upstream.Close()
				stopUpstream := context.AfterFunc(proxyCtx, func() { _ = upstream.Close() })
				defer stopUpstream()
				_, err = io.WriteString(upstream, "POST /v1/guest-proxy HTTP/1.1\r\nHost: egress.invalid\r\nConnection: Upgrade\r\nUpgrade: osv-guest-proxy/1\r\nX-OSV-Tenant: qemu-egress\r\nX-OSV-VM: 0123456789abcdef01234567\r\nX-OSV-Lease: abcdef0123456789abcdef01\r\nContent-Length: 0\r\n\r\n")
				if err != nil {
					return
				}
				reader := bufio.NewReader(upstream)
				response, err := http.ReadResponse(reader, nil)
				if err != nil || response.StatusCode != 101 {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close(); _ = client.Close(); close(copied) }()
				_, _ = io.Copy(client, reader)
				_ = client.Close()
				_ = upstream.Close()
				<-copied
			}()
		}
	}()
	defer func() { cancel(); _ = proxy.Close(); <-accepted; workers.Wait() }()
	for _, test := range []struct {
		name, target, ca string
		success          bool
	}{
		{"bundled-guest-http-proxy", target, "", true},
		{"bundled-guest-https-verified-proxy", secureTarget, "/mcp/ca.crt", true},
		{"bundled-guest-https-untrusted-rejected", secureTarget, "", false},
	} {
		args := []string{"-timeout", "5s"}
		if test.ca != "" {
			args = append(args, "-cacert", test.ca)
		}
		args = append(args, test.target)
		command := exec.CommandContext(proxyCtx, "/bin/guest-http", args...)
		command.Env = append(os.Environ(), "HTTP_PROXY=http://"+proxy.Addr().String(), "HTTPS_PROXY=http://"+proxy.Addr().String(), "NO_PROXY=", "no_proxy=")
		output, err := command.CombinedOutput()
		if test.success {
			if err != nil || !bytes.Equal(output, []byte{0, 255, 65}) {
				fmt.Println("FAIL", test.name, err, string(output))
				return false
			}
		} else if err == nil || !strings.Contains(string(output), "certificate") {
			fmt.Println("FAIL", test.name, err, string(output))
			return false
		}
		fmt.Println("PASS", test.name)
	}
	return true
}
