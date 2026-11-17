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
	AllowedTemplates   *[]TemplateSelector `json:"allowed_templates,omitempty"`
	ID                 string              `json:"id"`
	TokenSHA256        string              `json:"token_sha256"`
	AllowedEntrypoints []string            `json:"allowed_entrypoints"`
	RequestsPerSecond  float64             `json:"requests_per_second"`
	Burst              int                 `json:"burst"`
	MaxConcurrent      int                 `json:"max_concurrent"`
	Egress             *EgressPolicy       `json:"egress,omitempty"`
	Ports              *PortPolicy         `json:"ports,omitempty"`
	Inference          *InferencePolicy    `json:"inference,omitempty"`
}

type tenantRuntime struct {
	policy    TenantPolicy
	sem       chan struct{}
	mu        sync.Mutex
	tokens    float64
	last      time.Time
	egress    *egressRules
	netSem    chan struct{}
	portSem   chan struct{}
	inference *inferenceRules
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
		var egress *egressRules
		if policy.AllowedTemplates != nil {
			if len(*policy.AllowedTemplates) > 16 {
				return nil, errors.New("at most 16 allowed_templates per tenant")
			}
			items := append([]TemplateSelector{}, (*policy.AllowedTemplates)...)
			seen := map[TemplateSelector]bool{}
			for _, item := range items {
				if (item.Backend != "firecracker-linux" && item.Backend != "firecracker-osv") || !validSHA256Hex(item.ArtifactManifestSHA256) || seen[item] {
					return nil, errors.New("invalid or duplicate tenant template selector")
				}
				seen[item] = true
			}
			policy.AllowedTemplates = &items
		}
		if policy.Egress != nil {
			egress, err = compileEgressPolicy(*policy.Egress)
			if err != nil {
				return nil, fmt.Errorf("tenant %q: %w", policy.ID, err)
			}
			policy.Egress = &egress.policy
		}
		var inference *inferenceRules
		if policy.Inference != nil {
			inference, err = compileInferencePolicy(*policy.Inference, egress)
			if err != nil {
				return nil, fmt.Errorf("tenant %q: %w", policy.ID, err)
			}
			policy.Inference = &inference.policy
		}
		if policy.Ports != nil {
			policy.Ports, err = policy.Ports.validatedCopy()
			if err != nil {
				return nil, fmt.Errorf("tenant %q: %w", policy.ID, err)
			}
		}
		runtime := &tenantRuntime{
			policy: policy, sem: make(chan struct{}, policy.MaxConcurrent),
			tokens: float64(policy.Burst), last: time.Now(),
			inference: inference,
		}
		if egress != nil {
			runtime.egress = egress
			runtime.netSem = make(chan struct{}, egress.policy.MaxConcurrent)
		}
		if policy.Ports != nil {
			runtime.portSem = make(chan struct{}, policy.Ports.MaxConcurrent)
		}
		auth.tenants[digest] = runtime
	}
	return auth, nil
}

func NewSingleTokenAuthenticator(token string) *Authenticator {
	if token == "" {
		return nil
	}
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
	if !t.allowsTemplate(request.Backend, request.ArtifactManifestSHA256) {
		return nil, errors.New("template is not allowed for tenant")
	}
	if !t.allowsEntrypoint(request.Entrypoint) {
		return nil, errors.New("entrypoint is not allowed for tenant")
	}
	if err := t.consumeRequestToken(); err != nil {
		return nil, err
	}
	return t.acquireConcurrent()
}

func (t *tenantRuntime) allowsTemplate(backend, digest string) bool {
	if t == nil {
		return false
	}
	if t.policy.AllowedTemplates == nil {
		return true
	}
	for _, item := range *t.policy.AllowedTemplates {
		if item.Backend == backend && item.ArtifactManifestSHA256 == digest {
			return true
		}
	}
	return false
}

func (t *tenantRuntime) authorizeSessionCreate() (func(), error) {
	if err := t.consumeRequestToken(); err != nil {
		return nil, err
	}
	return t.acquireConcurrent()
}

func (t *tenantRuntime) authorizeSessionCommand(request SessionCommandRequest) error {
	if !t.allowsEntrypoint(request.Entrypoint) {
		return errors.New("entrypoint is not allowed for tenant")
	}
	return t.consumeRequestToken()
}

func (t *tenantRuntime) allowsEntrypoint(entrypoint string) bool {
	for _, allowed := range t.policy.AllowedEntrypoints {
		if allowed == "*" || allowed == entrypoint {
			return true
		}
	}
	return false
}

func (t *tenantRuntime) consumeRequestToken() error {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := now.Sub(t.last).Seconds()
	t.tokens += elapsed * t.policy.RequestsPerSecond
	if t.tokens > float64(t.policy.Burst) {
		t.tokens = float64(t.policy.Burst)
	}
	t.last = now
	if t.tokens < 1 {
		return ErrBusy
	}
	t.tokens--
	return nil
}

func (t *tenantRuntime) acquireConcurrent() (func(), error) {
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
