package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthPolicyRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	policy := `{"protocol":"osv-sandbox-auth/v1","tenants":[]} {}`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticator(path); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestTenantAuthPolicyEnforcesEntrypointAndConcurrency(t *testing.T) {
	token := "correct horse battery staple"
	digest := sha256.Sum256([]byte(token))
	policy := `{"protocol":"osv-sandbox-auth/v1","tenants":[{"id":"tenant-a","token_sha256":"` + hex.EncodeToString(digest[:]) + `","allowed_entrypoints":["/bin/echo"],"requests_per_second":1,"burst":2,"max_concurrent":1}]}`
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	tenant, ok := auth.Authenticate("Bearer " + token)
	if !ok || tenant.policy.ID != "tenant-a" {
		t.Fatal("valid tenant token was rejected")
	}
	if _, ok := auth.Authenticate("Bearer wrong"); ok {
		t.Fatal("invalid tenant token was accepted")
	}
	if _, err := tenant.authorize(RunRequest{Entrypoint: "/bin/sh"}); err == nil {
		t.Fatal("tenant entrypoint policy was not enforced")
	}
	release, err := tenant.authorize(RunRequest{Entrypoint: "/bin/echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := tenant.authorize(RunRequest{Entrypoint: "/bin/echo"}); err == nil {
		t.Fatal("tenant concurrency limit was not enforced")
	}
}
