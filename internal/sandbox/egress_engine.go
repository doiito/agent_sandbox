package sandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type NetworkFetchRequest struct {
	URL             string            `json:"url"`
	Method          string            `json:"method,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	BodyBase64      string            `json:"body_base64,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
	TimeoutMS       int               `json:"timeout_ms,omitempty"`
}
type NetworkFetchResult struct {
	Protocol      string              `json:"protocol"`
	RequestID     string              `json:"request_id"`
	URL           string              `json:"url"`
	Status        int                 `json:"status"`
	Headers       map[string][]string `json:"headers"`
	BodyBase64    string              `json:"body_base64"`
	BodyBytes     int                 `json:"body_bytes"`
	Redirects     int                 `json:"redirects"`
	DurationMS    int64               `json:"duration_ms"`
	RequestBytes  int                 `json:"request_bytes"`
	ResponseBytes int                 `json:"response_bytes"`
}
type EgressError struct {
	Status int
	Code   string
}

func (e *EgressError) Error() string            { return "egress " + e.Code }
func egressError(status int, code string) error { return &EgressError{status, code} }
func egressErrorFor(ctx context.Context, code string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return egressError(504, "egress_timeout")
	}
	if ctx.Err() != nil {
		return egressError(499, "egress_cancelled")
	}
	return egressError(502, code)
}

type egressEngine struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool
}

func newEgressEngine(roots *x509.CertPool) *egressEngine {
	return &egressEngine{lookup: net.DefaultResolver.LookupNetIP, dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, roots: roots}
}

// approvedAddresses is shared by fetch and transparent guest CONNECT. Every
// answer is checked before any dial; callers dial these literal IPs only.
func (engine *egressEngine) approvedAddresses(ctx context.Context, u *url.URL, origin string, rules *egressRules) ([]netip.Addr, error) {
	if !rules.origins[origin] {
		return nil, egressError(403, "egress_origin_denied")
	}
	var addresses []netip.Addr
	var err error
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		addresses = []netip.Addr{ip.Unmap()}
	} else {
		addresses, err = engine.lookup(ctx, "ip", u.Hostname())
		if err != nil || len(addresses) == 0 {
			return nil, egressErrorFor(ctx, "egress_dns")
		}
	}
	if len(addresses) > 64 {
		return nil, egressError(502, "egress_dns_limit")
	}
	for _, ip := range addresses {
		if !rules.allowsIP(ip) {
			return nil, egressError(403, "egress_ip_denied")
		}
	}
	return addresses, nil
}
func egressHeaderBlocked(name string) bool {
	switch strings.ToLower(name) {
	case "host", "connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "transfer-encoding", "content-length", "upgrade", "te", "trailer", "expect":
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "proxy-") || strings.HasPrefix(strings.ToLower(name), "sec-websocket-")
}
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
func prepareEgressRequest(req NetworkFetchRequest, rules *egressRules) (string, []byte, http.Header, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return "", nil, nil, egressError(400, "egress_method")
	}
	if len(req.BodyBase64) > base64.StdEncoding.EncodedLen(rules.policy.MaxRequestBytes) || req.TimeoutMS < 0 || req.TimeoutMS > rules.policy.TimeoutMS {
		return "", nil, nil, egressError(400, "egress_request_limit")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(req.BodyBase64)
	if err != nil || base64.StdEncoding.EncodeToString(body) != req.BodyBase64 || len(body) > rules.policy.MaxRequestBytes || (method == "GET" || method == "HEAD") && len(body) > 0 {
		return "", nil, nil, egressError(400, "egress_body")
	}
	if len(req.Headers) > 32 {
		return "", nil, nil, egressError(400, "egress_headers")
	}
	headers, total := make(http.Header), 0
	for name, value := range req.Headers {
		total += len(name) + len(value)
		_, duplicate := headers[http.CanonicalHeaderKey(name)]
		if total > 8192 || !validHeaderName(name) || egressHeaderBlocked(name) || duplicate || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return "", nil, nil, egressError(400, "egress_headers")
		}
		for _, c := range value {
			if c < 32 && c != '\t' || c == 127 {
				return "", nil, nil, egressError(400, "egress_headers")
			}
		}
		headers.Set(name, value)
	}
	return method, body, headers, nil
}

// Fetch never uses an environment proxy or an unchecked second DNS lookup.
// authorize is persisted before each actual outbound connection.
func (engine *egressEngine) fetch(parent context.Context, request NetworkFetchRequest, rules *egressRules, authorize func(origin, method, ip string, hop int) error) (NetworkFetchResult, error) {
	return engine.fetchObserved(parent, request, rules, authorize, nil)
}

// Once an HTTP connection (including its TLS handshake) is ready, an interrupted
// request can have reached the provider. Treat that boundary conservatively;
// do not infer a free failure from a late or absent WroteRequest callback.
type egressFetchObservation struct {
	requestPossible atomic.Bool
}

func (engine *egressEngine) fetchObserved(parent context.Context, request NetworkFetchRequest, rules *egressRules, authorize func(origin, method, ip string, hop int) error, observation *egressFetchObservation) (NetworkFetchResult, error) {
	var result NetworkFetchResult
	method, body, headers, err := prepareEgressRequest(request, rules)
	if err != nil {
		return result, err
	}
	timeout := request.TimeoutMS
	if timeout == 0 {
		timeout = rules.policy.TimeoutMS
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	started := time.Now()
	current := request.URL
	sent, totalReceived := 0, 0
	for hop := 0; ; hop++ {
		u, origin, err := egressURL(current)
		if err != nil {
			return result, egressError(400, "egress_url")
		}
		addresses, err := engine.approvedAddresses(ctx, u, origin, rules)
		if err != nil {
			return result, err
		}
		transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: time.Duration(timeout) * time.Millisecond, TLSHandshakeTimeout: 5 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: engine.roots, ServerName: u.Hostname()}}
		transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			for _, ip := range addresses {
				if err := authorize(origin, method, ip.Unmap().String(), hop); err != nil {
					return nil, err
				}
				conn, e := engine.dial(dialCtx, "tcp", net.JoinHostPort(ip.Unmap().String(), u.Port()))
				if e == nil {
					return conn, nil
				}
				if dialCtx.Err() != nil {
					return nil, dialCtx.Err()
				}
			}
			return nil, errors.New("approved destination unreachable")
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return result, egressError(400, "egress_request")
		}
		req.Header = headers.Clone()
		if observation != nil {
			// Inference requests must never be automatically replayed, including
			// when an administrator uses an idempotency-related credential header.
			req.GetBody = nil
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
				GotConn: func(httptrace.GotConnInfo) { observation.requestPossible.Store(true) },
			}))
		}
		response, err := client.Do(req)
		if err != nil {
			transport.CloseIdleConnections()
			var policyErr *EgressError
			if errors.As(err, &policyErr) {
				return result, policyErr
			}
			if ctx.Err() == nil {
				var certificateError *tls.CertificateVerificationError
				var recordError tls.RecordHeaderError
				if errors.As(err, &certificateError) || errors.As(err, &recordError) {
					return result, egressError(502, "egress_tls")
				}
				var networkError net.Error
				if errors.As(err, &networkError) && networkError.Timeout() {
					return result, egressError(504, "egress_timeout")
				}
			}
			return result, egressErrorFor(ctx, "egress_upstream")
		}
		sent += len(body)
		result.RequestBytes = sent
		result.Status = response.StatusCode
		data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(rules.policy.MaxResponseBytes-totalReceived)+1))
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		totalReceived += len(data)
		result.ResponseBytes = totalReceived
		if totalReceived > rules.policy.MaxResponseBytes {
			return result, egressError(502, "egress_response_limit")
		}
		if readErr != nil {
			return result, egressErrorFor(ctx, "egress_response")
		}
		location := response.Header.Get("Location")
		redirect := response.StatusCode == 301 || response.StatusCode == 302 || response.StatusCode == 303 || response.StatusCode == 307 || response.StatusCode == 308
		if !redirect || !request.FollowRedirects || location == "" {
			clean := make(map[string][]string)
			hopHeaders := map[string]bool{}
			for _, v := range response.Header.Values("Connection") {
				for _, name := range strings.Split(v, ",") {
					hopHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
				}
			}
			for name, values := range response.Header {
				if !egressHeaderBlocked(name) && !hopHeaders[name] {
					clean[name] = values
				}
			}
			return NetworkFetchResult{Protocol: "osv-sandbox-network-fetch/v1", URL: u.String(), Status: response.StatusCode, Headers: clean, BodyBase64: base64.StdEncoding.EncodeToString(data), BodyBytes: len(data), Redirects: hop, DurationMS: time.Since(started).Milliseconds(), RequestBytes: sent, ResponseBytes: totalReceived}, nil
		}
		if hop >= rules.policy.MaxRedirects {
			return result, egressError(403, "egress_redirect_limit")
		}
		next, err := u.Parse(location)
		if err != nil {
			return result, egressError(502, "egress_redirect")
		}
		_, nextOrigin, err := egressURL(next.String())
		if err != nil {
			return result, egressError(403, "egress_redirect")
		}
		if u.Scheme == "https" && next.Scheme != "https" {
			return result, egressError(403, "egress_tls_downgrade")
		}
		if nextOrigin != origin {
			headers = make(http.Header)
		}
		if response.StatusCode == 303 && method != "HEAD" || (response.StatusCode == 301 || response.StatusCode == 302) && method == "POST" {
			method, body = "GET", nil
			headers.Del("Content-Type")
			headers.Del("Content-Encoding")
		}
		current = next.String()
	}
}
