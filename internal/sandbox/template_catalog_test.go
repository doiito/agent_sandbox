package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func catalogConfigForTest() Config {
	c := warmConfigForTest()
	c.Production = true
	c.HypervisorPath = "/opt/osv/bin/firecracker"
	c.Jailer.Path, c.Jailer.ParentCgroup = "/opt/osv/bin/jailer", "osv-test"
	c.LinuxGuest.MkfsPath = "/opt/osv/bin/mkfs.ext4"
	c.LauncherSocket, c.AuthPolicyPath, c.AuditLogPath = "/run/osv/launcher.sock", "/etc/osv/auth.json", "/var/log/osv/audit.jsonl"
	c.TLS = &TLSConfig{CertFile: "/etc/osv/server.crt", KeyFile: "/etc/osv/server.key", ClientCAFile: "/etc/osv/ca.crt"}
	c.ArtifactManifest = &ArtifactManifestConfig{Path: "manifest.json", SignaturePath: "manifest.sig", PublicKeyPath: "/etc/osv/artifact.public", SBOMPath: "sbom.json"}
	c.Templates = []TemplateConfig{{ID: "python", Backend: "firecracker-osv", ArtifactRoot: "/opt/osv/python/artifacts", Image: Artifact{Format: "raw"}, ArtifactManifest: c.ArtifactManifest,
		AllowedEntrypoints: []string{"/python.so"}, WarmProfiles: []WarmPoolProfile{{Name: "small", MemoryMiB: 128, VCPUs: 1, MinReady: 1, MaxReady: 1}}}}
	return c
}

func TestTemplateCatalogConfigurationChecksCollectiveBudgetAndCopies(t *testing.T) {
	c := catalogConfigForTest()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	child := c.forTemplate(c.Templates[0])
	if child.LinuxGuest != nil || !child.Production || child.Jailer.UID != c.Jailer.UID || child.WarmPool.RefillBurst != c.WarmPool.RefillBurst {
		t.Fatal("template changed host policy or backend shape")
	}
	frozen := c.snapshot()
	c.Templates[0].AllowedEntrypoints[0] = "/mutated.so"
	c.Templates[0].ArtifactManifest.Path = "changed"
	c.Templates[0].WarmProfiles[0].MinReady = 4
	if frozen.Templates[0].AllowedEntrypoints[0] != "/python.so" || frozen.Templates[0].ArtifactManifest.Path != "manifest.json" || frozen.Templates[0].WarmProfiles[0].MinReady != 1 {
		t.Fatal("catalog snapshot retained writable aliases")
	}
	for _, name := range []string{"duplicate", "unsigned", "aggregate-minimum", "diagnostic", "unsafe-id"} {
		t.Run(name, func(t *testing.T) {
			value := catalogConfigForTest()
			switch name {
			case "duplicate":
				value.Templates[0].ID = "default"
			case "unsigned":
				value.Templates[0].ArtifactManifest = nil
			case "aggregate-minimum":
				value.Templates[0].WarmProfiles[0].MinReady = 4
				value.Templates[0].WarmProfiles[0].MaxReady = 4
			case "diagnostic":
				value.Production = false
			case "unsafe-id":
				value.Templates[0].ID = "../other"
			}
			if value.Validate() == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func routedManagersForTest(t *testing.T) (*Manager, *Manager, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	root, child := testManager(t, "output"), testManager(t, "output")
	a, b := &atomic.Int32{}, &atomic.Int32{}
	root.backend, child.backend = countedBackend{calls: a}, countedBackend{calls: b}
	root.config.Backend, child.config.Backend = "firecracker-linux", "firecracker-osv"
	root.config.AllowedEntrypoints, child.config.AllowedEntrypoints = []string{"/linux"}, []string{"/python.so"}
	child.config.TemplateID = "python"
	child.config.RunRoot = root.config.RunRoot
	child.owner, child.capacity = root, root.capacity
	now := time.Now()
	root.manifest = &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v3", AgentFeatures: []string{"vsock-proxy-v1"}, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), digestSHA256: strings.Repeat("a", 64)}
	child.manifest = &SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v2", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), digestSHA256: strings.Repeat("b", 64)}
	c := newTemplateCatalog(root, []*Manager{root, child})
	root.catalog, child.catalog = c, c
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := root.Shutdown(ctx); err != nil && !errors.Is(err, ErrUnavailable) {
			t.Error(err)
		}
	})
	return root, child, a, b
}

func TestTemplateCatalogRoutesExactSelectorAndKeepsLegacyDefault(t *testing.T) {
	root, child, a, b := routedManagersForTest(t)
	request := RunRequest{Entrypoint: "/python.so", Backend: child.config.Backend, ArtifactManifestSHA256: child.manifest.digestSHA256}
	result, err := root.Run(context.Background(), request)
	if err != nil || result.State != "succeeded" || a.Load() != 0 || b.Load() != 1 {
		t.Fatal("explicit OSv selector did not reach only its backend", result, err, a.Load(), b.Load())
	}
	legacy := RunRequest{Entrypoint: "/linux"}
	if _, err := root.Run(context.Background(), legacy); err != nil || a.Load() != 1 || b.Load() != 1 {
		t.Fatal("legacy default changed", err)
	}
	request.ArtifactManifestSHA256 = strings.Repeat("c", 64)
	if _, err := root.Run(context.Background(), request); !errors.Is(err, ErrTemplateMismatch) || a.Load() != 1 || b.Load() != 1 {
		t.Fatal("unknown selector fell back", err)
	}
	request.ArtifactManifestSHA256 = child.manifest.digestSHA256
	child.manifest.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := root.Run(context.Background(), request); !errors.Is(err, ErrUnavailable) || b.Load() != 1 {
		t.Fatal("expired template allocated a VM", err)
	}
	catalog, err := root.TemplateCatalog()
	if err != nil || len(catalog.Templates) != 2 || catalog.Templates[1].Available || !catalog.Templates[0].Available {
		t.Fatal("expiry hid healthy template or advertised expired availability", catalog, err)
	}
	root.manifest.ExpiresAt = time.Now().Add(-time.Second)
	child.manifest.ExpiresAt = time.Now().Add(time.Hour)
	if _, err := root.Run(context.Background(), request); err != nil || b.Load() != 2 {
		t.Fatal("expired default blocked a different valid template", err, b.Load())
	}
}

func TestTemplateCatalogAPIUsesSelectedCapabilitiesAndTenantPolicy(t *testing.T) {
	root, child, a, b := routedManagersForTest(t)
	auth := NewSingleTokenAuthenticator("secret")
	var tenant *tenantRuntime
	for _, value := range auth.tenants {
		tenant = value
	}
	handler := NewAPIWithAuthenticator(root, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	selected := "/v1/capabilities?backend=firecracker-osv&artifact_manifest_sha256=" + child.manifest.digestSHA256
	w := call("GET", selected, "")
	var cap CapabilityReport
	if json.Unmarshal(w.Body.Bytes(), &cap) != nil || w.Code != 200 || cap.Backend != "firecracker-osv" || cap.Features.Sessions || cap.Features.NetworkEgress || len(cap.AllowedEntrypoints) != 1 || cap.AllowedEntrypoints[0] != "/python.so" {
		t.Fatal("default capability leaked to selected OSv template", w.Code, w.Body.String())
	}
	w = call("POST", "/v2/jobs", `{"entrypoint":"/python.so","backend":"firecracker-osv","artifact_manifest_sha256":"`+child.manifest.digestSHA256+`","network":"proxy"}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported_network") || a.Load() != 0 || b.Load() != 0 {
		t.Fatal("selected OSv borrowed Linux proxy", w.Code, w.Body.String())
	}
	allowed := []TemplateSelector{{Backend: child.config.Backend, ArtifactManifestSHA256: child.manifest.digestSHA256}}
	tenant.policy.AllowedTemplates = &allowed
	w = call("GET", "/v2/templates", "")
	var catalog TemplateCatalogReport
	if json.Unmarshal(w.Body.Bytes(), &catalog) != nil || w.Code != 200 || len(catalog.Templates) != 1 || catalog.Templates[0].ID != "python" || catalog.DefaultTemplateID != "" {
		t.Fatal("catalog exposed a hidden template", w.Body.String())
	}
	cap = CapabilityReport{}
	if w = call("GET", "/v1/capabilities", ""); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cap) != nil || cap.ArtifactAuthenticated || cap.Backend != "" || cap.ArtifactManifestSHA256 != "" || len(cap.AllowedEntrypoints) != 0 {
		t.Fatal("denied default capability was not redacted", w.Code, w.Body.String())
	}
	if w = call("POST", "/v1/jobs", `{"entrypoint":"/linux"}`); w.Code != 403 {
		t.Fatal("legacy request bypassed template restriction", w.Code, w.Body.String())
	}
	w = call("POST", "/v2/jobs", `{"entrypoint":"/python.so","backend":"firecracker-osv","artifact_manifest_sha256":"`+child.manifest.digestSHA256+`"}`)
	if w.Code != 200 || b.Load() != 1 || a.Load() != 0 {
		t.Fatal("allowed template did not execute", w.Code, w.Body.String())
	}
	empty := []TemplateSelector{}
	tenant.policy.AllowedTemplates = &empty
	w = call("GET", "/v2/templates", "")
	if json.Unmarshal(w.Body.Bytes(), &catalog) != nil || len(catalog.Templates) != 0 {
		t.Fatal("empty allowed_templates did not deny all")
	}
}

func TestTemplateCatalogCleanupFailureBlocksSharedLedger(t *testing.T) {
	root, child, _, _ := routedManagersForTest(t)
	child.markCleanupFailed()
	if !root.cleanupFailed.Load() || !root.Capacity().Blocked || !child.Capacity().Blocked {
		t.Fatal("cleanup failure was isolated to one template")
	}
}

func TestTemplateCatalogLauncherWireRoutesAndReturnsActualBinding(t *testing.T) {
	root, child, a, b := routedManagersForTest(t)
	options := LauncherOptions{AllowedUID: os.Getuid(), SocketUID: os.Getuid(), SocketGID: os.Getgid(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	socket := filepath.Join(t.TempDir(), "l.sock")
	listener, err := ListenLauncher(socket, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeLauncher(ctx, listener, root, options) }()
	defer func() {
		cancel()
		listener.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := LauncherClient{SocketPath: socket, Timeout: 5 * time.Second}
	catalog, err := client.TemplateCatalog()
	if err != nil || len(catalog.Templates) != 2 {
		t.Fatal("launcher omitted real catalog", catalog, err)
	}
	cap, err := client.CapabilitiesFor(child.config.Backend, child.manifest.digestSHA256)
	if err != nil || cap.Backend != child.config.Backend || cap.TemplateID != "python" {
		t.Fatal("selected capabilities did not cross launcher", cap, err)
	}
	value, err := client.Run(context.Background(), RunRequest{Entrypoint: "/python.so", Backend: child.config.Backend, ArtifactManifestSHA256: child.manifest.digestSHA256})
	if err != nil || value.State != "succeeded" || value.TemplateID != "python" || value.ArtifactManifestSHA256 != child.manifest.digestSHA256 || a.Load() != 0 || b.Load() != 1 {
		t.Fatal("wire routed to wrong manager or reported default binding", value, err)
	}
	if _, err := client.CapabilitiesFor(child.config.Backend, strings.Repeat("c", 64)); !errors.Is(err, ErrTemplateMismatch) {
		t.Fatal("launcher lost typed stale selector", err)
	}
}
