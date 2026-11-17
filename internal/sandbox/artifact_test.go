package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveArtifactsVerifiesHashAndConfinement(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) Artifact {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		return Artifact{Path: name, SHA256: hex.EncodeToString(sum[:]), Format: "raw"}
	}
	kernel, image := write("kernel", "kernel"), write("image", "image")
	if _, err := ResolveArtifacts(root, kernel, image); err != nil {
		t.Fatal(err)
	}
	image.SHA256 = kernel.SHA256
	if _, err := ResolveArtifacts(root, kernel, image); err == nil {
		t.Fatal("expected hash mismatch")
	}
}

func TestVerifySignedArtifactManifest(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) Artifact {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(body))
		return Artifact{Path: name, SHA256: hex.EncodeToString(digest[:]), Format: "raw"}
	}
	kernel, image := write("kernel", "kernel"), write("image", "image")
	resolved, err := ResolveArtifacts(root, kernel, image)
	if err != nil {
		t.Fatal(err)
	}
	executable := write("firecracker", "executable")
	sbom := write("sbom.cdx.json", "sbom")
	if err := os.Chmod(filepath.Join(root, "firecracker"), 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(root, "manifest.public")
	if err := os.WriteFile(publicKeyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v1", CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		Kernel: kernel, Image: image, KernelSize: 6, ImageSize: 5,
		FirecrackerSHA256: executable.SHA256, JailerSHA256: executable.SHA256,
		SBOMSHA256: sbom.SHA256, SBOMSize: 4,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, data)
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ArtifactRoot: root, Kernel: kernel, Image: image, Backend: "firecracker-linux",
		HypervisorPath: filepath.Join(root, "firecracker"), Jailer: &JailerConfig{Path: filepath.Join(root, "firecracker")},
		ArtifactManifest: &ArtifactManifestConfig{Path: "manifest.json", SignaturePath: "manifest.sig", PublicKeyPath: publicKeyPath, SBOMPath: "sbom.cdx.json"},
	}
	if err := VerifyArtifactManifest(config, resolved); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyArtifactManifest(config, resolved)
	digest := sha256.Sum256(data)
	if err != nil || verified.digestSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("capability digest must identify signed manifest bytes: %+v %v", verified, err)
	}
	config.Backend = "firecracker-osv"
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted v1 Linux manifest for OSv")
	}
	config.Backend = "firecracker-linux"
	trailing := append(append([]byte(nil), data...), []byte(` {}`)...)
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), trailing, 0o600); err != nil {
		t.Fatal(err)
	}
	trailingSignature := ed25519.Sign(privateKey, trailing)
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(trailingSignature)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("expected signed trailing JSON to be rejected")
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("expected tampered manifest to be rejected")
	}
	config.Backend = "firecracker-osv"
	config.AllowedEntrypoints = []string{"/task-probe.so"}
	manifest.Protocol = "osv-sandbox-artifacts/v2"
	manifest.Backend = "firecracker-osv"
	manifest.Entrypoints = []string{"/task-probe.so"}
	manifest.AgentFeatures = []string{"environment"}
	manifest.OSvUpstreamCommit = "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b"
	component := func(name, hash string) map[string]any {
		return map[string]any{"name": name, "hashes": []map[string]string{{"alg": "SHA-256", "content": hash}}}
	}
	components := []map[string]any{
		{"name": "OSv", "version": manifest.OSvUpstreamCommit},
		component("osv-kernel", kernel.SHA256), component("osv-rootfs", image.SHA256),
		component("firecracker", executable.SHA256), component("jailer", executable.SHA256),
		component("osv-job-agent", executable.SHA256), component("osv-sandboxd", executable.SHA256),
		component("osv-sandbox-launcher", executable.SHA256), component("osv-module/task-probe.so", executable.SHA256),
	}
	sbomDocument := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
	sbomBytes, err := json.Marshal(sbomDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sbom.cdx.json"), sbomBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sbomDigest := sha256.Sum256(sbomBytes)
	manifest.SBOMSHA256, manifest.SBOMSize = hex.EncodeToString(sbomDigest[:]), int64(len(sbomBytes))
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	signature = ed25519.Sign(privateKey, data)
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err != nil {
		t.Fatalf("valid signed OSv profile rejected: %v", err)
	}
	manifest.OSvROFSCache = "disabled"
	policyData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), policyData, 0o600); err != nil {
		t.Fatal(err)
	}
	policySignature := ed25519.Sign(privateKey, policyData)
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(policySignature)), 0o600); err != nil {
		t.Fatal(err)
	}
	policyManifest, err := verifyArtifactManifest(config, resolved)
	if err != nil || policyManifest.OSvROFSCache != "disabled" {
		t.Fatalf("signed ROFS policy was not authenticated: %v", err)
	}
	manifest.OSvROFSCache = ""
	tamperedPolicy, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), tamperedPolicy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted ROFS policy removal without a new signature")
	}
	manifest.OSvROFSCache = "disabled"
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), policyData, 0o600); err != nil {
		t.Fatal(err)
	}
	components[0]["version"] = "0000000000000000000000000000000000000000"
	wrongSBOM, err := json.Marshal(sbomDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOSvSBOM(wrongSBOM, manifest); err == nil {
		t.Fatal("accepted SBOM with a conflicting OSv upstream commit")
	}
	components[0]["version"] = manifest.OSvUpstreamCommit
	components[len(components)-1]["name"] = "osv-module/unsigned.so"
	wrongSBOM, err = json.Marshal(sbomDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOSvSBOM(wrongSBOM, manifest); err == nil {
		t.Fatal("accepted SBOM with an unsigned module entry")
	}
	config.AllowedEntrypoints = []string{"/unsigned.so"}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted unsigned OSv module in runtime policy")
	}
	config.AllowedEntrypoints = []string{"/task-probe.so"}
	config.Backend = "firecracker-linux"
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted signed OSv profile for Linux")
	}
	config.Backend = "firecracker-osv"
	if err := os.WriteFile(filepath.Join(root, "sbom.cdx.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted tampered OSv SBOM")
	}
	if err := os.WriteFile(filepath.Join(root, "sbom.cdx.json"), sbomBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest.ExpiresAt = time.Now().Add(-time.Minute)
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	signature = ed25519.Sign(privateKey, data)
	if err := os.WriteFile(filepath.Join(root, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted expired signed OSv profile")
	}
	manifest.ExpiresAt = time.Now().Add(time.Hour)
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactManifest(config, resolved); err == nil {
		t.Fatal("accepted invalid OSv signature")
	}
}

func TestOSvROFSCachePolicyProfileBoundaries(t *testing.T) {
	manifest := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v2", Backend: "firecracker-osv",
		OSvUpstreamCommit: "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b", Entrypoints: []string{"/task-probe.so"}}
	for _, policy := range []string{"", "disabled"} {
		manifest.OSvROFSCache = policy
		if err := manifest.ValidateProfile("firecracker-osv", manifest.Entrypoints); err != nil {
			t.Fatal(err)
		}
	}
	for _, policy := range []string{"enabled", "DISABLED", "disabled --nopci", "disabled\n"} {
		manifest.OSvROFSCache = policy
		if err := manifest.ValidateProfile("firecracker-osv", manifest.Entrypoints); err == nil {
			t.Fatalf("accepted unsupported policy %q", policy)
		}
	}
	linux := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v1"}
	if err := linux.ValidateProfile("firecracker-linux", nil); err != nil {
		t.Fatal(err)
	}
	linux.OSvROFSCache = "disabled"
	if err := linux.ValidateProfile("firecracker-linux", nil); err == nil {
		t.Fatal("Linux manifest accepted an OSv-only memory policy")
	}
}

func TestSignedOSvManifestRejectsBadModuleLists(t *testing.T) {
	base := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v2", Backend: "firecracker-osv",
		OSvUpstreamCommit: "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b",
		Entrypoints:       []string{"/task-probe.so"}}
	if err := base.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SignedArtifactManifest){
		"empty":            func(m *SignedArtifactManifest) { m.Entrypoints = nil },
		"duplicate":        func(m *SignedArtifactManifest) { m.Entrypoints = []string{"/task-probe.so", "/task-probe.so"} },
		"unsorted":         func(m *SignedArtifactManifest) { m.Entrypoints = []string{"/z.so", "/a.so"} },
		"traversal":        func(m *SignedArtifactManifest) { m.Entrypoints = []string{"/../task-probe.so"} },
		"uppercase-commit": func(m *SignedArtifactManifest) { m.OSvUpstreamCommit = "0E34e4dc2b278b7f64e4169abbf297b7de46fb6b" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err == nil {
				t.Fatal("accepted invalid signed OSv profile")
			}
		})
	}
	if err := base.ValidateProfile("firecracker-osv", nil); err == nil {
		t.Fatal("accepted empty runtime OSv module policy")
	}
}

func TestSignedOSvAgentFeatureMustBeExplicitAndKnown(t *testing.T) {
	manifest := SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v2", Backend: "firecracker-osv",
		Entrypoints:       []string{"/task-probe.so"},
		OSvUpstreamCommit: "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b",
	}
	if err := manifest.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err != nil {
		t.Fatal(err)
	}
	manifest.AgentFeatures = []string{"environment"}
	if err := manifest.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err != nil {
		t.Fatal(err)
	}
	manifest.AgentFeatures = []string{"environment", "stdin"}
	if err := manifest.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err != nil {
		t.Fatal(err)
	}
	manifest.AgentFeatures = []string{"environment", "pristine-v1", "stdin"}
	if err := manifest.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err != nil {
		t.Fatal(err)
	}
	for _, features := range [][]string{{"unknown"}, {"environment", "environment"},
		{"Environment"}, {"stdin", "environment"}, {"stdin", "stdin"}} {
		manifest.AgentFeatures = features
		if err := manifest.ValidateProfile("firecracker-osv", []string{"/task-probe.so"}); err == nil {
			t.Fatalf("accepted invalid agent features: %v", features)
		}
	}
	manifest.Protocol = "osv-sandbox-artifacts/v1"
	manifest.Backend = ""
	manifest.Entrypoints = nil
	manifest.OSvUpstreamCommit = ""
	manifest.AgentFeatures = []string{"environment"}
	if err := manifest.ValidateProfile("firecracker-linux", nil); err == nil {
		t.Fatal("accepted OSv agent feature in Linux v1 manifest")
	}
}

func TestResolveArtifactsRejectsEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	body := []byte("outside")
	if err := os.WriteFile(outside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	a := Artifact{Path: outside, SHA256: hex.EncodeToString(sum[:]), Format: "raw"}
	if _, err := ResolveArtifacts(root, a, a); err == nil {
		t.Fatal("expected artifact root escape to fail")
	}
}
