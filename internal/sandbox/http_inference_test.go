package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This constructs the future profile contract without a VM. It verifies the
// public HTTP/root RPC/service path, not signed-v7 guest or KVM acceptance.
func inferenceHTTPFixture(t *testing.T, service *EgressServer, main string) (http.Handler, *API, *Session, *LauncherSessionClient) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	config := capacityConfig()
	config.Backend, config.EgressSocket = "firecracker-linux", main
	manager := &Manager{config: config, inferenceAuth: service.auth, manifest: &SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v7", Backend: "firecracker-linux", digestSHA256: digest, GuestInference: inferenceTestGuestProfile("firecracker-linux"),
		AgentFeatures: []string{"remote-infer-v1", "vsock-proxy-v1"}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	binding := inferenceTestBinding()
	binding.LeaseID = binding.TaskID
	instance := &vmInstance{id: binding.VMID, manager: manager, ctx: ctx, cancel: cancel,
		proxy: &vmGuestProxy{inference: &binding, inferencePolicySHA256: manager.inferencePolicyDigest(binding.Tenant)}}
	session := &Session{manager: manager, instance: instance, ctx: ctx, cancel: cancel,
		info: SessionInfo{ID: binding.TaskID, State: "running", Network: "proxy", Backend: config.Backend, ArtifactManifestSHA256: digest,
			CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute), MaxExpiresAt: time.Now().Add(time.Minute)},
		hardDeadline: time.Now().Add(time.Minute)}
	if err := manager.registerOwnedSession(session, binding.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := newInferenceRootClient(main).task(ctx, "bind", binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = newInferenceRootClient(main).task(context.Background(), "close", binding)
		session.unregisterOwnedSession()
	})
	socket := filepath.Join(t.TempDir(), "launcher.sock")
	listener, err := ListenLauncher(socket, LauncherOptions{AllowedUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go handleLauncherConnection(ctx, conn, manager, LauncherOptions{AllowedUID: os.Geteuid()}, slog.Default())
		}
	}()
	handle := &LauncherSessionClient{id: binding.TaskID, tenant: binding.Tenant, socketPath: socket}
	client, owner := net.Pipe()
	handle.conn, handle.reader = client, bufio.NewReader(client)
	t.Cleanup(func() { _ = client.Close(); _ = owner.Close() })
	go func() {
		defer owner.Close()
		decoder := json.NewDecoder(owner)
		for {
			var request launcherSessionRequest
			if decoder.Decode(&request) != nil {
				return
			}
			reply := launcherSessionResponse{Protocol: launcherSessionProtocol}
			if request.Operation == "close" {
				_, _ = newInferenceRootClient(main).task(context.Background(), "close", binding)
				session.unregisterOwnedSession()
				cancel()
				_ = json.NewEncoder(owner).Encode(reply)
				return
			}
			info := session.Info()
			reply.Info = &info
			if json.NewEncoder(owner).Encode(reply) != nil {
				return
			}
		}
	}()
	capability := CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: config.Backend, ArtifactAuthenticated: true,
		ArtifactManifestProtocol: manager.manifest.Protocol, ArtifactManifestSHA256: digest,
		AllowedEntrypoints: []string{"/agent"}, Features: CapabilityFeatures{Sessions: true, RemoteInference: true, NetworkEgress: true},
		Limits: CapabilityLimits{MinMemoryMiB: 64, MaxMemoryMiB: 512, MaxVCPUs: 2, MaxTimeoutMS: 300000, MaxConcurrent: 4, MaxOutputBytes: 65536, SessionMaxTTLMS: 300000, SessionMaxLifetimeMS: 600000}}
	runner := &sessionCapabilityRunner{report: capability}
	handler := newAPIWithEgress(runner, service.auth, slog.Default(), main)
	tenant, _ := service.auth.Authenticate("Bearer inference-test-token")
	handler.api.sessions[binding.TaskID] = &apiSession{info: session.info, tenant: tenant, handle: handle,
		capability: capability, deadline: time.Now().Add(time.Minute), done: make(chan struct{}), release: func() {}}
	return handler, handler.api, session, handle
}

func TestInferenceHTTPRootRPCAndHistoryIndependentOfShellAndSession(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"ok"}`))
	}))
	t.Cleanup(provider.Close)
	service, _, main, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	handler, api, session, handle := inferenceHTTPFixture(t, service, main)
	base := "/v2/sessions/" + session.info.ID + "/ml/invocations"
	request := inferenceRequest(1)
	body, _ := marshalInferenceJSON(request)
	// A synchronous shell can own both existing control locks. Inference uses
	// its own authenticated root connection.
	session.opMu.Lock()
	handle.mu.Lock()
	response := sessionHTTPCall(handler, "inference-test-token", "POST", base, string(body))
	handle.mu.Unlock()
	session.opMu.Unlock()
	var result InferenceInvokeResult
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.TaskID != session.info.ID || result.Invocation.ID != request.ID || result.Invocation.SettledUnits == 0 || calls.Load() != 1 {
		t.Fatal("independent public inference path failed", response.Code, response.Body.String())
	}
	duplicate := sessionHTTPCall(handler, "inference-test-token", "POST", base, string(body))
	if duplicate.Code != 409 || !strings.Contains(duplicate.Body.String(), request.ID) || calls.Load() != 1 {
		t.Fatal("replay or error identity regression", duplicate.Code, duplicate.Body.String())
	}
	for _, name := range []string{"foreign-owner", "caller-url", "caller-task", "old-profile", "no-network"} {
		t.Run(name, func(t *testing.T) {
			token, payload, want := "inference-test-token", string(body), 403
			owned := api.sessions[session.info.ID]
			previous := owned.capability
			previousNetwork := owned.info.Network
			defer func() { owned.capability, owned.info.Network = previous, previousNetwork }()
			switch name {
			case "foreign-owner":
				token, want = "inference-other-token", 404
			case "caller-url":
				payload, want = strings.TrimSpace(payload), 400
				payload = `{"url":"http://127.0.0.1/",` + payload[1:]
			case "caller-task":
				payload, want = strings.TrimSpace(payload), 400
				payload = `{"task_id":"` + strings.Repeat("f", 24) + `",` + payload[1:]
			case "old-profile":
				owned.capability.ArtifactManifestProtocol = "osv-sandbox-artifacts/v6"
			case "no-network":
				owned.info.Network = "none"
			}
			denied := sessionHTTPCall(handler, token, "POST", base, payload)
			if denied.Code != want || calls.Load() != 1 {
				t.Fatal("denied request reached provider", denied.Code, denied.Body.String())
			}
		})
	}
	binding := *session.instance.proxy.inference
	if _, err := newInferenceRootClient(main).task(context.Background(), "close", binding); err != nil {
		t.Fatal(err)
	}
	session.unregisterOwnedSession()
	session.cancel()
	api.sessionsMu.Lock()
	delete(api.sessions, session.info.ID)
	api.sessionsMu.Unlock()
	billPath := "/v2/ml/bills/" + session.info.ID
	response = sessionHTTPCall(handler, "inference-test-token", "GET", billPath, "")
	var bill InferenceBill
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &bill) != nil || !bill.Closed || len(bill.Invocations) != 1 || bill.SettledUnits != result.Invocation.SettledUnits {
		t.Fatal("closed session lost independently persisted history", response.Code, response.Body.String())
	}
	if other := sessionHTTPCall(handler, "inference-other-token", "GET", billPath, ""); other.Code != 404 || strings.Contains(other.Body.String(), session.info.ID) {
		t.Fatal("foreign tenant observed historical task", other.Code, other.Body.String())
	}
}

func TestInferenceCapabilitiesPolicyAgreementAndRootRejectsChangedPolicy(t *testing.T) {
	service, root, main, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	tenant, _ := service.auth.Authenticate("Bearer inference-test-token")
	state, err := NewEgressClient(main).inferenceState(context.Background(), "Bearer inference-test-token")
	if err != nil || !state.Billing || state.Policy == nil || state.PolicySHA256 != inferenceTenantPolicyDigest(tenant) {
		t.Fatal("private policy agreement unavailable", state, err)
	}
	base := CapabilityReport{Backend: "firecracker-linux", ArtifactAuthenticated: true, ArtifactManifestProtocol: "osv-sandbox-artifacts/v7",
		ArtifactManifestSHA256: strings.Repeat("a", 64), Features: CapabilityFeatures{Sessions: true, RemoteInference: true, NetworkEgress: true}}
	for _, name := range []string{"enabled", "enabled-v8", "osv-v8-rejected", "stale-private-digest", "proxy-disabled", "unsigned", "no-network", "old-profile"} {
		t.Run(name, func(t *testing.T) {
			report, local, proxy := base, state, true
			switch name {
			case "enabled-v8":
				report.ArtifactManifestProtocol = "osv-sandbox-artifacts/v8"
			case "osv-v8-rejected":
				report.Backend, report.ArtifactManifestProtocol = "firecracker-osv", "osv-sandbox-artifacts/v8"
			case "stale-private-digest":
				local.PolicySHA256 = strings.Repeat("0", 64)
			case "proxy-disabled":
				proxy = false
			case "unsigned":
				report.ArtifactAuthenticated = false
			case "no-network":
				report.Features.NetworkEgress = false
			case "old-profile":
				report.ArtifactManifestProtocol = "osv-sandbox-artifacts/v6"
			}
			applyInferenceCapability(&report, tenant, local, proxy)
			enabled := name == "enabled" || name == "enabled-v8"
			if report.Features.RemoteInference != enabled || !report.Features.InferenceBilling || (report.RemoteInferencePolicy != nil) != enabled {
				t.Fatal("capability policy disagreement", report)
			}
			data, _ := json.Marshal(report)
			if strings.Contains(string(data), state.PolicySHA256) || strings.Contains(string(data), "127.0.0.1") {
				t.Fatal("private policy digest or provider address escaped public discovery")
			}
			if enabled {
				applyInferenceCapability(&report, tenant, local, proxy)
				if len(report.Methods) != 2 {
					t.Fatal("repeated discovery duplicated inference methods", report.Methods)
				}
				applyInferenceCapability(&report, tenant, inferenceServiceState{}, proxy)
				if report.Features.InferenceBilling || report.Features.RemoteInference || len(report.Methods) != 0 {
					t.Fatal("unavailable service retained stale inference methods", report)
				}
			}
		})
	}
	binding := inferenceTestBinding()
	if _, err := root.task(context.Background(), "bind", binding); err != nil {
		t.Fatal(err)
	}
	_, err = root.invoke(context.Background(), binding, inferenceRequest(1), strings.Repeat("0", 64))
	expectInferenceFailure(t, err, "inference_policy_unavailable")
	bill, err := service.inference.ledger.bill(binding.Tenant, binding.TaskID)
	if err != nil || len(bill.Invocations) != 0 || bill.SettledUnits != 0 || bill.HeldUnits != 0 {
		t.Fatal("changed root policy consumed budget", bill, err)
	}
}
