package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPICapabilitiesAreAuthenticatedAndTenantScoped(t *testing.T) {
	auth := NewSingleTokenAuthenticator("secret")
	for _, tenant := range auth.tenants {
		tenant.policy.AllowedEntrypoints = []string{"/a.so"}
	}
	manager := &Manager{
		config: Config{Backend: "firecracker-osv", AllowedEntrypoints: []string{"/a.so", "/b.so"},
			Limits: Limits{MaxConcurrent: 4, MaxOutputByte: 16384, MaxTimeoutMS: 30000,
				MinMemoryMiB: 32, MaxMemoryMiB: 2048, MaxVCPUs: 4}},
		backend:  FirecrackerOSvBackend{},
		manifest: &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v2", digestSHA256: strings.Repeat("a", 64)},
	}
	handler := NewAPIWithAuthenticator(manager, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous capability query returned %d", response.Code)
	}
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var report CapabilityReport
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &report) != nil {
		t.Fatalf("authenticated capability query failed: %d %s", response.Code, response.Body.String())
	}
	if report.Protocol != "osv-sandbox-capabilities/v1" || report.Backend != "firecracker-osv" ||
		report.Workload != "osv-native-module" || report.Stage != "diagnostic" ||
		report.GuestResultProtocol != "osv-agent/v1" || !report.ArtifactAuthenticated ||
		report.ArtifactManifestSHA256 != strings.Repeat("a", 64) ||
		!strings.Contains(strings.Join(report.Methods, ","), "POST /v2/jobs") ||
		len(report.AllowedEntrypoints) != 1 || report.AllowedEntrypoints[0] != "/a.so" ||
		report.Features.InputFiles || report.Features.NetworkEgress || report.Features.Snapshots ||
		report.Features.Sessions || report.Features.SessionFiles || report.Features.PersistentWorkspace ||
		report.Limits.MaxConcurrent != 4 || report.Limits.MaxInputFiles != 0 {
		t.Fatalf("OSv capabilities overclaim or leak a tenant entrypoint: %+v", report)
	}
	manager.config.Backend = "firecracker-linux"
	manager.config.Production = true
	manager.backend = FirecrackerLinuxBackend{}
	manager.manifest.Protocol = "osv-sandbox-artifacts/v1"
	linux, err := manager.Capabilities()
	if err != nil || linux.Workload != "linux-process" || linux.Stage != "production" ||
		!linux.Features.InputFiles || linux.Limits.MaxInputFiles != 64 ||
		linux.GuestResultProtocol != "fc-agent/v1" || linux.Features.NetworkEgress ||
		!linux.Features.Sessions || !linux.Features.SessionFiles || !linux.Features.PersistentWorkspace ||
		linux.Limits.SessionMaxTTLMS != sessionMaxTTLMS || linux.Limits.SessionFileMaxBytes != sessionFileLimit ||
		!strings.Contains(strings.Join(linux.Methods, ","), "POST /v2/sessions/{id}/files") {
		t.Fatalf("Linux capabilities did not match implemented backend: %+v %v", linux, err)
	}
}

func TestV2JobsRequireExplicitMatchingTemplate(t *testing.T) {
	manager := testManager(t, "output")
	now := time.Now()
	digest := strings.Repeat("a", 64)
	manager.manifest = &SignedArtifactManifest{CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), digestSHA256: digest}
	handler := NewAPI(manager, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	post := func(body string) (int, map[string]any) {
		request := httptest.NewRequest(http.MethodPost, "/v2/jobs", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return response.Code, payload
	}
	if status, payload := post(`{"entrypoint":"/agent"}`); status != http.StatusBadRequest || payload["code"] != "invalid_request" {
		t.Fatalf("missing v2 selection returned %d %+v", status, payload)
	}
	if status, payload := post(`{"entrypoint":"/agent","backend":"` + manager.config.Backend + `","artifact_manifest_sha256":"` + strings.Repeat("b", 64) + `"}`); status != http.StatusConflict || payload["code"] != "template_mismatch" {
		t.Fatalf("stale v2 template returned %d %+v", status, payload)
	}
	if status, payload := post(`{"entrypoint":"/agent","backend":"` + manager.config.Backend + `","artifact_manifest_sha256":"` + digest + `"}`); status != http.StatusOK || payload["state"] != "succeeded" {
		t.Fatalf("matching v2 selection returned %d %+v", status, payload)
	}
}

func TestAPIRequiresAuthentication(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/v1/doctor", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d", w.Code)
	}
}

func TestAPIRejectsMissingTokenConfiguration(t *testing.T) {
	h := NewAPI(testManager(t, "output"), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", strings.NewReader(`{"entrypoint":"/agent"}`))
	r.Header.Set("Authorization", "Bearer guessed")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured authenticator returned %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIRejectsUnknownJSONFields(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", strings.NewReader(`{"unknown":true}`))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIEndToEndWithHelperBackend(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := bytes.NewBufferString(`{"entrypoint":"/agent","args":["echo","hello"]}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", body)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"protocol_ok":true`) {
		t.Fatalf("unexpected response %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIExportsAuthenticatedPrometheusMetrics(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "osv_sandbox_jobs_total") {
		t.Fatalf("unexpected metrics response %d: %s", w.Code, w.Body.String())
	}
}
