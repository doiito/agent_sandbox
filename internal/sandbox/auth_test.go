package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestTenantRateBucketIsIndependentOfOtherTenant(t *testing.T) {
	first := &tenantRuntime{
		policy: TenantPolicy{AllowedEntrypoints: []string{"/bin/sh"}, RequestsPerSecond: 0.001, Burst: 3},
		sem:    make(chan struct{}, 1), tokens: 3, last: time.Now(),
	}
	second := &tenantRuntime{
		policy: TenantPolicy{AllowedEntrypoints: []string{"/bin/sh"}, RequestsPerSecond: 100, Burst: 100},
		sem:    make(chan struct{}, 1), tokens: 100, last: time.Now(),
	}
	job := RunRequest{Entrypoint: "/bin/sh"}
	release, err := first.authorize(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.authorize(job); !errors.Is(err, ErrBusy) {
		t.Fatalf("active tenant did not enforce concurrency: %v", err)
	}
	release()
	release, err = first.authorize(job)
	if err != nil {
		t.Fatalf("remaining token was unavailable: %v", err)
	}
	release()
	if _, err := first.authorize(job); !errors.Is(err, ErrBusy) {
		t.Fatalf("exhausted tenant did not enforce rate limit: %v", err)
	}
	otherRelease, err := second.authorize(job)
	if err != nil {
		t.Fatalf("other tenant inherited rate limit: %v", err)
	}
	otherRelease()
	first.mu.Lock()
	first.last = first.last.Add(-time.Hour)
	first.mu.Unlock()
	release, err = first.authorize(job)
	if err != nil {
		t.Fatalf("rate bucket did not refill: %v", err)
	}
	release()
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

func TestTenantSessionHoldsConcurrencyWhileCommandsUseRateTokens(t *testing.T) {
	tenant := &tenantRuntime{
		policy: TenantPolicy{AllowedEntrypoints: []string{"/bin/sh"}, RequestsPerSecond: 0.001, Burst: 4},
		sem:    make(chan struct{}, 1), tokens: 4, last: time.Now(),
	}
	release, err := tenant.authorizeSessionCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := tenant.authorizeSessionCommand(SessionCommandRequest{Entrypoint: "/bin/sh"}); err != nil {
		t.Fatalf("command could not use the held session slot: %v", err)
	}
	if err := tenant.authorizeSessionCommand(SessionCommandRequest{Entrypoint: "/bin/id"}); err == nil {
		t.Fatal("session command bypassed entrypoint policy")
	}
	if _, err := tenant.authorizeSessionCreate(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second session bypassed the held concurrency slot: %v", err)
	}
	if err := tenant.authorizeSessionCommand(SessionCommandRequest{Entrypoint: "/bin/sh"}); err != nil {
		t.Fatalf("remaining command token was unavailable: %v", err)
	}
	if err := tenant.authorizeSessionCommand(SessionCommandRequest{Entrypoint: "/bin/sh"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("session command bypassed rate limit: %v", err)
	}
	release()
	tenant.mu.Lock()
	tenant.last = tenant.last.Add(-time.Hour)
	tenant.mu.Unlock()
	newRelease, err := tenant.authorizeSessionCreate()
	if err != nil {
		t.Fatalf("session slot was not released: %v", err)
	}
	newRelease()
}
