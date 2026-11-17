package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type EgressClient struct{ http *http.Client }

func NewEgressClient(socket string) *EgressClient {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: 32 * time.Second}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		unix, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, errors.New("expected Unix egress peer")
		}
		cred, err := unixPeerCredential(unix)
		if err != nil || cred.Uid != uint32(os.Geteuid()) {
			conn.Close()
			return nil, errors.New("egress service UID mismatch")
		}
		return conn, nil
	}
	return &EgressClient{http: &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *EgressClient) exchange(ctx context.Context, method, path, authorization string, body []byte) (int, json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://egress.invalid"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("egress service unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || !json.Valid(data) {
		return 0, nil, errors.New("invalid egress service response")
	}
	return response.StatusCode, data, nil
}
func (c *EgressClient) policy(ctx context.Context, authorization string) (*EgressPolicy, error) {
	policy, _, err := c.policyState(ctx, authorization)
	return policy, err
}
func (c *EgressClient) policyState(ctx context.Context, authorization string) (*EgressPolicy, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	status, data, err := c.exchange(ctx, "GET", "/v1/policy", authorization, nil)
	if err != nil || status != 200 {
		return nil, false, errors.New("egress policy unavailable")
	}
	var value struct {
		GuestProxy bool         `json:"guest_proxy"`
		Protocol   string       `json:"protocol"`
		Policy     EgressPolicy `json:"policy"`
	}
	if json.Unmarshal(data, &value) != nil || value.Protocol != "osv-sandbox-egress-policy/v1" {
		return nil, false, errors.New("invalid egress policy response")
	}
	rules, err := compileEgressPolicy(value.Policy)
	if err != nil {
		return nil, false, err
	}
	return &rules.policy, value.GuestProxy, nil
}

func (a *API) authorizeGuestProxy(w http.ResponseWriter, r *http.Request, network string, selector ...string) bool {
	if network != "proxy" {
		return true
	}
	backend, digest := "", ""
	if len(selector) == 2 {
		backend, digest = selector[0], selector[1]
	}
	report, err := capabilitiesFor(a.runner, backend, digest)
	if err != nil {
		writeTemplateLookupError(w, err)
		return false
	}
	if !report.Features.NetworkEgress {
		writeJobError(w, 400, "unsupported_network", "signed template does not support guest proxy", true)
		return false
	}
	tenant := tenantFromRequest(r)
	if tenant == nil || tenant.egress == nil {
		writeJobError(w, 403, "egress_disabled", "guest proxy disabled for tenant", true)
		return false
	}
	if a.egress == nil {
		writeJobError(w, 503, "egress_unavailable", "guest proxy service is not configured", true)
		return false
	}
	policy, enabled, err := a.egress.policyState(r.Context(), r.Header.Get("Authorization"))
	if err != nil || !enabled || !matchingEgressPolicy(policy, &tenant.egress.policy) {
		writeJobError(w, 503, "egress_policy_unavailable", "guest proxy policy unavailable or differs from API policy", true)
		return false
	}
	return true
}

func matchingEgressPolicy(left, right *EgressPolicy) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

func (a *API) networkFetch(w http.ResponseWriter, r *http.Request) {
	tenant, ok := r.Context().Value(tenantContextKey{}).(*tenantRuntime)
	if !ok || tenant.egress == nil {
		writeJobError(w, 403, "egress_disabled", "network fetch disabled for tenant", true)
		return
	}
	if a.egress == nil {
		writeJobError(w, 503, "egress_unavailable", "network fetch service is not configured", true)
		return
	}
	policy, err := a.egress.policy(r.Context(), r.Header.Get("Authorization"))
	if err != nil || !matchingEgressPolicy(policy, &tenant.egress.policy) {
		writeJobError(w, 503, "egress_policy_unavailable", "network service policy unavailable or differs from API policy", true)
		return
	}
	var request NetworkFetchRequest
	if decodeHTTPBody(w, r, &request) != nil {
		writeJobError(w, 400, "egress_request", "invalid bounded network request", true)
		return
	}
	if _, _, _, err := prepareEgressRequest(request, tenant.egress); err != nil {
		var e *EgressError
		errors.As(err, &e)
		writeJobError(w, e.Status, e.Code, e.Error(), true)
		return
	}
	if tenant.consumeRequestToken() != nil {
		writeJobError(w, 429, "egress_rate_limit", "tenant request rate limit", true)
		return
	}
	body, err := json.Marshal(request)
	if err != nil {
		writeJobError(w, 400, "egress_request", "invalid request", true)
		return
	}
	status, data, err := a.egress.exchange(r.Context(), "POST", "/v1/fetch", r.Header.Get("Authorization"), body)
	if err != nil {
		writeJobError(w, 503, "egress_unavailable", "network fetch service unavailable", true)
		return
	}
	if status < 200 || status >= 300 {
		var value struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(data, &value) != nil || !safeEgressCode(value.Code) {
			value.Code = "egress_upstream"
		}
		if status < 400 || status > 599 {
			status = 502
		}
		writeJobError(w, status, value.Code, "network fetch rejected", true)
		return
	}
	var result NetworkFetchResult
	if json.Unmarshal(data, &result) != nil || result.Protocol != "osv-sandbox-network-fetch/v1" || result.RequestID == "" {
		writeJobError(w, 502, "egress_protocol", "invalid network response", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
func safeEgressCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, c := range code {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
