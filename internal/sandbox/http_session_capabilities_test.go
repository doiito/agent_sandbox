package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type sessionCapabilityRunner struct {
	fakeSessionRunner
	report      CapabilityReport
	unavailable atomic.Bool
	selected    atomic.Int32
}

func (f *sessionCapabilityRunner) Capabilities() (CapabilityReport, error) { return f.report, nil }
func (f *sessionCapabilityRunner) CapabilitiesFor(backend, digest string) (CapabilityReport, error) {
	f.selected.Add(1)
	if f.unavailable.Load() {
		return CapabilityReport{}, ErrUnavailable
	}
	if backend != f.report.Backend || digest != f.report.ArtifactManifestSHA256 {
		return CapabilityReport{}, ErrTemplateMismatch
	}
	return f.report, nil
}
func boundCodeCapabilityForTest() CapabilityReport {
	return CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", Backend: "firecracker-linux", ArtifactAuthenticated: true,
		ArtifactManifestProtocol: "osv-sandbox-artifacts/v5", ArtifactManifestSHA256: strings.Repeat("a", 64),
		AllowedEntrypoints: []string{"/bin/sh", codeEntrypoint("python"), codeEntrypoint("javascript")},
		Methods:            []string{"GET /v2/sessions/{id}/capabilities"}, Features: CapabilityFeatures{Sessions: true, CodeContexts: true},
		CodeRuntime: testCodeProfile(), CodeLanguages: []string{"python", "javascript", "typescript"}}
}

func TestSessionCapabilitiesRemainBoundAfterAdmissionExpiresAndDoNotAliasPolicy(t *testing.T) {
	f := &sessionCapabilityRunner{report: boundCodeCapabilityForTest()}
	f.handles = make(chan *LauncherSessionClient, 1)
	auth := sessionAuthForTest()
	tenant, _ := auth.Authenticate("Bearer token-a")
	tenant.policy.AllowedEntrypoints = []string{"/bin/sh", codeEntrypoint("python")}
	handler := NewAPIWithAuthenticator(f, auth, slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+f.report.ArtifactManifestSHA256+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	h := <-f.handles
	defer h.Close()
	base := "/v2/sessions/" + h.id
	defer sessionHTTPCall(handler, "token-a", "DELETE", base, "")
	f.unavailable.Store(true)
	before := f.selected.Load()
	// The original cached contract must not alias the manager's maps/slices.
	f.report.CodeRuntime.KernelScriptsSHA256["python.py"] = "mutated"
	f.report.CodeRuntime.MinimumCPUFeatures[0] = "mutated"
	f.report.CodeLanguages[0] = "mutated"
	f.report.AllowedEntrypoints[1] = "/mutated"
	for _, policy := range [][]string{{"/bin/sh", codeEntrypoint("python")}, {"/bin/sh", codeEntrypoint("javascript")}, {"/bin/sh"}} {
		tenant.policy.AllowedEntrypoints = policy
		response := sessionHTTPCall(handler, "token-a", "GET", base+"/capabilities", "")
		var report SessionCapabilityReport
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.SessionID != h.id || report.CodeRuntime.validate() != nil {
			t.Fatal("active lease lost its bound runtime", response.Code, response.Body.String())
		}
		want := 0
		if len(policy) > 1 {
			if policy[1] == codeEntrypoint("python") {
				want = 1
			} else {
				want = 2
			}
		}
		if len(report.CodeLanguages) != want {
			t.Fatal("current tenant language policy ignored", report.CodeLanguages, policy)
		}
		if !report.Features.CodeContexts || f.selected.Load() != before {
			t.Fatal("bound query re-entered new admission")
		}
	}
	denied := sessionHTTPCall(handler, "token-b", "GET", base+"/capabilities", "")
	if denied.Code != 404 {
		t.Fatal("foreign owner received capabilities", denied.Code)
	}
	again := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if again.Code != 503 || f.created.Load() != 1 {
		t.Fatal("expired admission created a new VM", again.Code)
	}
}

func TestSessionCapabilitiesRejectChangedOwnerIdentityAndDeadLauncher(t *testing.T) {
	for _, kind := range []string{"backend", "digest", "id", "dead"} {
		t.Run(kind, func(t *testing.T) {
			f := &sessionCapabilityRunner{report: boundCodeCapabilityForTest()}
			f.handles = make(chan *LauncherSessionClient, 1)
			f.infoTransform = func(info SessionInfo) SessionInfo {
				switch kind {
				case "backend":
					info.Backend = "firecracker-osv"
				case "digest":
					info.ArtifactManifestSHA256 = strings.Repeat("b", 64)
				case "id":
					info.ID = strings.Repeat("b", 24)
				}
				return info
			}
			handler := NewAPIWithAuthenticator(f, sessionAuthForTest(), slog.Default())
			created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
			if created.Code != 201 {
				t.Fatal(created.Body.String())
			}
			h := <-f.handles
			defer h.Close()
			if kind == "dead" {
				_ = h.conn.Close()
			}
			path := "/v2/sessions/" + h.id
			response := sessionHTTPCall(handler, "token-a", "GET", path+"/capabilities", "")
			if response.Code != 404 && response.Code != 503 {
				t.Fatal("forged or dead owner was accepted", kind, response.Code, response.Body.String())
			}
			if after := sessionHTTPCall(handler, "token-a", "GET", path, ""); after.Code != 404 {
				t.Fatal("invalid identity retained API owner", after.Code)
			}
		})
	}
}

func TestSessionCapabilitiesUseIndependentRealUnixOwnerInfo(t *testing.T) {
	s := codeTestSession(t, func(net.Conn, *bufio.Reader, linuxCodeRequest) { t.Error("capabilities invoked a guest code command") })
	f := &codeHTTPFixture{watchHTTPFixture{socket: codeLauncherSocket(t, s, LauncherOptions{}), session: s}}
	f.handles = make(chan *LauncherSessionClient, 1)
	handler := NewAPIWithAuthenticator(f, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	h := <-f.handles
	defer h.Close()
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+h.id, "")
	h.mu.Lock()
	defer h.mu.Unlock()
	// s.opMu is also held by codeTestSession, as if a shell were still running.
	response := sessionHTTPCall(handler, "token-a", "GET", "/v2/sessions/"+h.id+"/capabilities", "")
	var report SessionCapabilityReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.SessionID != h.id || !report.Features.CodeContexts {
		t.Fatal("synchronous control blocked independent capability lookup", response.Code, response.Body.String())
	}
	if _, err := s.manager.ownedSession(h.id, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	request := httptest.NewRequest("GET", "/v2/sessions/"+h.id+"/capabilities", nil).WithContext(cancelled)
	request.Header.Set("Authorization", "Bearer token-a")
	interrupted := httptest.NewRecorder()
	handler.ServeHTTP(interrupted, request)
	if interrupted.Code == 200 || h.closed.Load() || s.closed.Load() {
		t.Fatal("cancelled metadata observation destroyed owner", interrupted.Code)
	}
}

func TestSessionCapabilitiesBusyLegacyControlDoesNotCloseOwner(t *testing.T) {
	f := &sessionCapabilityRunner{report: boundCodeCapabilityForTest()}
	f.handles = make(chan *LauncherSessionClient, 1)
	handler := NewAPIWithAuthenticator(f, sessionAuthForTest(), slog.Default())
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", `{"backend":"firecracker-linux","artifact_manifest_sha256":"`+strings.Repeat("a", 64)+`"}`)
	if created.Code != 201 {
		t.Fatal(created.Body.String())
	}
	h := <-f.handles
	defer h.Close()
	path := "/v2/sessions/" + h.id
	defer sessionHTTPCall(handler, "token-a", "DELETE", path, "")
	h.mu.Lock()
	response := sessionHTTPCall(handler, "token-a", "GET", path+"/capabilities", "")
	h.mu.Unlock()
	if response.Code != 429 || h.closed.Load() {
		t.Fatal("busy fallback owner was closed", response.Code)
	}
	if retry := sessionHTTPCall(handler, "token-a", "GET", path+"/capabilities", ""); retry.Code != 200 {
		t.Fatal(retry.Code, retry.Body.String())
	}
}

func TestSessionCapabilitiesUnavailableCatalogRetainsOnlyExistingCodeContract(t *testing.T) {
	s := codeTestSession(t, func(net.Conn, *bufio.Reader, linuxCodeRequest) { t.Error("catalog contacted guest") })
	s.manager.manifest.ExpiresAt = s.info.CreatedAt.Add(-1)
	before, err := s.manager.Capabilities()
	if err != nil || !before.Features.CodeContexts {
		t.Fatal(before, err)
	}
	report, err := s.manager.TemplateCatalog()
	if err != nil || len(report.Templates) != 1 || report.Templates[0].Available {
		t.Fatal(report, err)
	}
	cap := report.Templates[0].Capabilities
	if !cap.Features.CodeContexts || !cap.Features.Sessions || cap.CodeRuntime.validate() != nil || cap.Features.OneShotJob {
		t.Fatal("unavailable new admission lost the existing-session contract", cap)
	}
}
