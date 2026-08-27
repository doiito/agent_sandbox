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
		ArtifactRoot: root, Kernel: kernel, Image: image,
		HypervisorPath: filepath.Join(root, "firecracker"), Jailer: &JailerConfig{Path: filepath.Join(root, "firecracker")},
		ArtifactManifest: &ArtifactManifestConfig{Path: "manifest.json", SignaturePath: "manifest.sig", PublicKeyPath: publicKeyPath, SBOMPath: "sbom.cdx.json"},
	}
	if err := VerifyArtifactManifest(config, resolved); err != nil {
		t.Fatal(err)
	}
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
