package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVMProxyPeerHelper(t *testing.T) {
	mode := os.Getenv("OSV_VM_PROXY_HELPER")
	if mode == "" {
		return
	}
	conn, err := net.DialTimeout("unix", "agent.vsock_5001", 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if mode == "denied" {
		_, _ = io.WriteString(conn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
		var one [1]byte
		if n, err := conn.Read(one[:]); n != 0 || err == nil {
			os.Exit(3)
		}
		return
	}
	if mode == "hold" {
		_, _ = io.WriteString(conn, "GET ")
		fmt.Println("READY")
		var one [1]byte
		if n, err := conn.Read(one[:]); n != 0 || err == nil {
			os.Exit(4)
		}
		return
	}
	_, _ = fmt.Fprintf(conn, "GET %s/private HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n", os.Getenv("OSV_VM_PROXY_TARGET"))
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(data) != "\x00\xffactual-vm-uid" {
		fmt.Fprintln(os.Stderr, response.StatusCode, data, err)
		os.Exit(6)
	}
}

func vmProxyHelper(t *testing.T, parent, binary, mode, target string, uid uint32) *exec.Cmd {
	t.Helper()
	command := exec.Command(binary, "-test.run=^TestVMProxyPeerHelper$", "-test.count=1")
	command.Dir = parent
	command.Env = append(os.Environ(), "OSV_VM_PROXY_HELPER="+mode, "OSV_VM_PROXY_TARGET="+target)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	return command
}

func vmProxyTestPaths(t *testing.T) (string, string) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "vm-proxy-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	binary := filepath.Join(base, "proxy-tests")
	file, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(file, source)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(base, strings.Repeat("long-jail-", 14))
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	return parent, binary
}

func TestVMProxyUnixIdentityBindingAndCleanup(t *testing.T) {
	requireGuestProxyRoot(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("\x00\xffactual-vm-uid")) }))
	defer upstream.Close()
	server, _, audit := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{upstream.URL}, AllowedCIDRs: []string{"127.0.0.0/8"}})
	egress, cancel, done := startEgressTestSocket(t, server)
	parent, binary := vmProxyTestPaths(t)
	proxy, err := newVMGuestProxy(context.Background(), filepath.Join(parent, "agent.vsock"), egress, "egress-a", proxyTestVM, proxyTestLease, 65530, 65530)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if output, err := vmProxyHelper(t, parent, binary, "http", upstream.URL, 65530).CombinedOutput(); err != nil {
		t.Fatal("actual VMM UID proxy", err, string(output))
	}
	// We deliberately loosen filesystem permissions in this test: the kernel
	// peer check must reject another UID even if it can open the socket.
	if err := os.Chmod(filepath.Join(parent, "agent.vsock_5001"), 0o666); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []uint32{65531, 0} {
		if output, err := vmProxyHelper(t, parent, binary, "denied", upstream.URL, uid).CombinedOutput(); err != nil {
			t.Fatal("foreign VM UID accepted", uid, err, string(output))
		}
	}
	proxy.Close()
	if len(proxy.slots) != 0 {
		t.Fatal("VM relay slots retained")
	}
	if _, err := os.Lstat(filepath.Join(parent, "agent.vsock_5001")); !os.IsNotExist(err) {
		t.Fatal("VM listener path retained", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, event := range audit.events {
		if event.Tenant != "egress-a" || event.VMID != proxyTestVM || event.LeaseID != proxyTestLease {
			t.Fatal("guest spoofed immutable identity", event)
		}
	}
}

func TestVMProxyOwnerCancellationJoinsRelays(t *testing.T) {
	requireGuestProxyRoot(t)
	server, tenant, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{"http://example.com"}, TimeoutMS: 30000})
	egress, cancel, done := startEgressTestSocket(t, server)
	parent, binary := vmProxyTestPaths(t)
	ctx, stop := context.WithCancel(context.Background())
	proxy, err := newVMGuestProxy(ctx, filepath.Join(parent, "agent.vsock"), egress, "egress-a", proxyTestVM, proxyTestLease, 65530, 65530)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	child := vmProxyHelper(t, parent, binary, "hold", "", 65530)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatal(line, err)
	}
	stop()
	proxy.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(tenant.netSem) != 0 || len(server.slots) != 0 || len(proxy.slots) != 0 {
		t.Fatal("owner cancellation retained proxy slots")
	}
}

func TestSignedLinuxProxyProfileAndLiveCapability(t *testing.T) {
	profile := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v3", Backend: "firecracker-linux", AgentFeatures: []string{"vsock-proxy-v1"}}
	if err := profile.ValidateProfile("firecracker-linux", []string{"/bin/sh"}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SignedArtifactManifest){
		func(m *SignedArtifactManifest) { m.Backend = "firecracker-osv" },
		func(m *SignedArtifactManifest) { m.AgentFeatures = []string{"unknown"} },
		func(m *SignedArtifactManifest) { m.AgentFeatures = nil },
		func(m *SignedArtifactManifest) { m.Entrypoints = []string{"/agent.so"} },
		func(m *SignedArtifactManifest) { m.OSvUpstreamCommit = strings.Repeat("a", 40) },
	} {
		copy := profile
		mutate(&copy)
		if copy.ValidateProfile("firecracker-linux", nil) == nil {
			t.Fatal("invalid Linux signed feature accepted", copy)
		}
	}
	server, _, _ := newGuestProxyTestServer(t, EgressPolicy{AllowedOrigins: []string{"https://example.com"}})
	egress, cancel, done := startEgressTestSocket(t, server)
	manager := &Manager{config: Config{Backend: "firecracker-linux", EgressSocket: egress, AllowedEntrypoints: []string{"/agent"}}, backend: FirecrackerLinuxBackend{}, manifest: &profile}
	profile.digestSHA256 = strings.Repeat("a", 64)
	api := NewAPIWithEgress(manager, server.auth, slog.New(slog.NewTextHandler(io.Discard, nil)), egress)
	for token, expected := range map[string]bool{"egress-test-token": true, "egress-disabled-token": false} {
		response := testNetworkRequest(api, "GET", "/v1/capabilities", token, nil)
		var report CapabilityReport
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.Features.NetworkEgress != expected {
			t.Fatal("live guest proxy capability", response.Code, response.Body.String())
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	response := testNetworkRequest(api, "GET", "/v1/capabilities", "egress-test-token", nil)
	var report CapabilityReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.Features.NetworkEgress {
		t.Fatal("stopped egress remained advertised")
	}
	profile.Protocol = "osv-sandbox-artifacts/v1"
	if manager.hasLinuxProxyFeature() {
		t.Fatal("legacy signed template gained proxy")
	}
}
