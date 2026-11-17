package sandbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSignedArtifactMetadataAuthenticationBoundary(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v1", CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	data, _ := json.Marshal(m)
	key := []byte(base64.StdEncoding.EncodeToString(public))
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, data)))
	if got, err := VerifySignedArtifactMetadata(data, signature, key, "firecracker-linux", nil); err != nil || got.digestSHA256 == "" {
		t.Fatalf("metadata-only authentication without artifact files: %+v %v", got, err)
	}
	for _, test := range []struct {
		name                 string
		data, signature, key []byte
		backend              string
	}{
		{"manifest-limit", bytes.Repeat([]byte("x"), (1<<20)+1), signature, key, "firecracker-linux"},
		{"signature-limit", data, bytes.Repeat([]byte("x"), 4097), key, "firecracker-linux"},
		{"key-limit", data, signature, bytes.Repeat([]byte("x"), 4097), "firecracker-linux"},
		{"wrong-backend", data, signature, key, "firecracker-osv"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifySignedArtifactMetadata(test.data, test.signature, test.key, test.backend, nil); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}
