package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/offlinebundle"
)

// This fixture exercises archive authentication, not execution of ELF payloads.
func signedVerifyFixture(t *testing.T, expires time.Time) (string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(root, "release.public.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"bin/osv-sandboxd", "bin/osv-sandbox-launcher", "bin/firecracker", "bin/jailer", "bin/osv-offline-release", "bin/mkfs.ext4", "artifacts/kernel", "artifacts/rootfs.ext4", "systemd/osv-sandboxd.service", "systemd/osv-sandbox-launcher.service", "config/config.production.json.template", "artifacts/manifest.json", "artifacts/manifest.json.sig", "artifacts/sbom.cdx.json"}
	sort.Strings(names)
	m := offlinebundle.Manifest{Format: 1, Version: "verify-json-test", Arch: "amd64", Commit: strings.Repeat("a", 40), ValidUntil: expires.UTC().Format(time.RFC3339)}
	for _, name := range names {
		digest := sha256.Sum256([]byte(name))
		mode := int64(0o444)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o555
		}
		m.Files = append(m.Files, offlinebundle.File{Path: name, Size: int64(len(name)), Mode: mode, SHA256: hex.EncodeToString(digest[:])})
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(hex.EncodeToString(ed25519.Sign(private, body)))
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	write := func(name string, mode int64, data []byte) {
		t.Helper()
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", 0o444, body)
	write("manifest.sig", 0o444, signature)
	for _, item := range m.Files {
		write(item.Path, item.Mode, []byte(item.Path))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "candidate.tar")
	if err := os.WriteFile(archive, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return archive, pub, output.Bytes()
}

func capturedRun(t *testing.T, args []string) ([]byte, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	before := os.Stdout
	os.Stdout = writer
	runErr := run(args)
	os.Stdout = before
	writer.Close()
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return data, runErr
}

func TestVerifyJSONAuthenticatesAndHashesWholeArchive(t *testing.T) {
	archive, public, raw := signedVerifyFixture(t, time.Now().Add(time.Hour))
	args := []string{"verify", "-json", "-archive", archive, "-public-key", public, "-arch", "amd64"}
	data, err := capturedRun(t, args)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Manifest offlinebundle.Manifest `json:"manifest"`
		SHA      string                 `json:"archive_sha256"`
		Bytes    int64                  `json:"archive_bytes"`
	}
	want := sha256.Sum256(raw)
	if json.Unmarshal(data, &value) != nil || value.SHA != hex.EncodeToString(want[:]) || value.Bytes != int64(len(raw)) || value.Manifest.Version != "verify-json-test" {
		t.Fatal("JSON did not bind authenticated archive", string(data))
	}
	legacy, err := capturedRun(t, []string{"verify", "-archive", archive, "-public-key", public, "-arch", "amd64"})
	if err != nil || !strings.HasPrefix(string(legacy), "verified version=") {
		t.Fatal("legacy output changed", err, string(legacy))
	}
	raw[len(raw)-1] = 'x'
	if err := os.WriteFile(archive, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := capturedRun(t, args); err == nil || len(data) != 0 {
		t.Fatal("tampered archive emitted authenticated JSON", err, string(data))
	}
}

func TestVerifyJSONRejectsExpiredAndWrongArchitecture(t *testing.T) {
	for _, expired := range []bool{false, true} {
		expires := time.Now().Add(time.Hour)
		arch := "arm64"
		if expired {
			expires = time.Now().Add(-time.Hour)
			arch = "amd64"
		}
		archive, public, _ := signedVerifyFixture(t, expires)
		data, err := capturedRun(t, []string{"verify", "-json", "-archive", archive, "-public-key", public, "-arch", arch})
		if err == nil || len(data) != 0 {
			t.Fatal("invalid reference emitted authenticated JSON", expired, err)
		}
	}
	if err := run([]string{"pack", "-json"}); err == nil {
		t.Fatal("JSON accepted outside verify")
	}
}
