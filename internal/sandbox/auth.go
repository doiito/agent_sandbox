package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type AuthPolicyFile struct {
	Protocol string         `json:"protocol"`
	Tenants  []TenantPolicy `json:"tenants"`
}

type TenantPolicy struct {
	ID                 string   `json:"id"`
	TokenSHA256        string   `json:"token_sha256"`
	AllowedEntrypoints []string `json:"allowed_entrypoints"`
	RequestsPerSecond  float64  `json:"requests_per_second"`
	Burst              int      `json:"burst"`
	MaxConcurrent      int      `json:"max_concurrent"`
}

type tenantRuntime struct {
	policy TenantPolicy
	sem    chan struct{}
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

type Authenticator struct {
	tenants map[[sha256.Size]byte]*tenantRuntime
}

func LoadAuthenticator(path string) (*Authenticator, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("auth policy must be a regular file not writable by group or other")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var policyFile AuthPolicyFile
	if err := decoder.Decode(&policyFile); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("auth policy must contain exactly one JSON object")
	}
	if policyFile.Protocol != "osv-sandbox-auth/v1" || len(policyFile.Tenants) == 0 {
		return nil, errors.New("invalid or empty auth policy")
	}
	auth := &Authenticator{tenants: make(map[[sha256.Size]byte]*tenantRuntime, len(policyFile.Tenants))}
	ids := make(map[string]struct{}, len(policyFile.Tenants))
	for _, policy := range policyFile.Tenants {
		if !safeTenantID(policy.ID) || policy.RequestsPerSecond <= 0 || policy.RequestsPerSecond > 10_000 ||
			policy.Burst < 1 || policy.Burst > 10_000 || policy.MaxConcurrent < 1 || policy.MaxConcurrent > 1024 || len(policy.AllowedEntrypoints) == 0 {
			return nil, fmt.Errorf("invalid tenant policy %q", policy.ID)
		}
		if _, exists := ids[policy.ID]; exists {
			return nil, fmt.Errorf("duplicate tenant id %q", policy.ID)
		}
		ids[policy.ID] = struct{}{}
		digestBytes, err := hex.DecodeString(policy.TokenSHA256)
		if err != nil || len(digestBytes) != sha256.Size {
			return nil, fmt.Errorf("tenant %q has an invalid token hash", policy.ID)
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		if _, exists := auth.tenants[digest]; exists {
			return nil, errors.New("duplicate tenant token hash")
		}
		for _, entrypoint := range policy.AllowedEntrypoints {
			if entrypoint != "*" && (!strings.HasPrefix(entrypoint, "/") || strings.ContainsAny(entrypoint, " \t\r\n;!&$")) {
				return nil, fmt.Errorf("tenant %q has an unsafe entrypoint", policy.ID)
			}
		}
		auth.tenants[digest] = &tenantRuntime{
			policy: policy, sem: make(chan struct{}, policy.MaxConcurrent),
			tokens: float64(policy.Burst), last: time.Now(),
		}
	}
	return auth, nil
}

func NewSingleTokenAuthenticator(token string) *Authenticator {
	digest := sha256.Sum256([]byte(token))
	policy := TenantPolicy{ID: "legacy", AllowedEntrypoints: []string{"*"}, RequestsPerSecond: 10_000, Burst: 10_000, MaxConcurrent: 1024}
	return &Authenticator{tenants: map[[sha256.Size]byte]*tenantRuntime{
		digest: {policy: policy, sem: make(chan struct{}, policy.MaxConcurrent), tokens: float64(policy.Burst), last: time.Now()},
	}}
}

func (a *Authenticator) Authenticate(header string) (*tenantRuntime, bool) {
	if a == nil || !strings.HasPrefix(header, "Bearer ") {
		return nil, false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if token == "" || len(token) > 4096 {
		return nil, false
	}
	digest := sha256.Sum256([]byte(token))
	tenant, ok := a.tenants[digest]
	return tenant, ok
}

func (t *tenantRuntime) authorize(request RunRequest) (func(), error) {
	allowed := false
	for _, entrypoint := range t.policy.AllowedEntrypoints {
		allowed = allowed || entrypoint == "*" || entrypoint == request.Entrypoint
	}
	if !allowed {
		return nil, errors.New("entrypoint is not allowed for tenant")
	}
	now := time.Now()
	t.mu.Lock()
	elapsed := now.Sub(t.last).Seconds()
	t.tokens += elapsed * t.policy.RequestsPerSecond
	if t.tokens > float64(t.policy.Burst) {
		t.tokens = float64(t.policy.Burst)
	}
	t.last = now
	if t.tokens < 1 {
		t.mu.Unlock()
		return nil, ErrBusy
	}
	t.tokens--
	t.mu.Unlock()
	select {
	case t.sem <- struct{}{}:
		return func() { <-t.sem }, nil
	default:
		return nil, ErrBusy
	}
}

func safeTenantID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char == '-' || char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
