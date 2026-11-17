// Package mcp exposes the authenticated sandbox API over bounded MCP stdio.
package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

const maxAPIResponse = 8 << 20

type Config struct {
	APIURL           string `json:"api_url"`
	CAFile           string `json:"ca_file"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	TokenFile        string `json:"token_file"`
	MaxInFlight      int    `json:"max_in_flight,omitempty"`
	RequestTimeoutMS int    `json:"request_timeout_ms,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open MCP configuration")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return c, errors.New("cannot read bounded MCP configuration")
	}
	if err = decodeStrict(data, &c); err != nil {
		return c, errors.New("invalid MCP configuration")
	}
	return c, nil
}

type apiClient struct {
	origin string
	token  string
	http   *http.Client
}
type apiFailure struct {
	Status int
	Code   string
}

func (e *apiFailure) Error() string {
	return fmt.Sprintf("sandbox API rejected operation (%d %s)", e.Status, e.Code)
}

func NewServer(c Config) (*Server, error) {
	if c.MaxInFlight == 0 {
		c.MaxInFlight = 4
	}
	if c.RequestTimeoutMS == 0 {
		c.RequestTimeoutMS = 320000
	}
	if c.MaxInFlight < 1 || c.MaxInFlight > 16 || c.RequestTimeoutMS < 1000 || c.RequestTimeoutMS > 330000 {
		return nil, errors.New("invalid MCP concurrency or timeout")
	}
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("MCP api_url must be an HTTPS origin")
	}
	if c.CAFile == "" || c.CertFile == "" || c.KeyFile == "" || c.TokenFile == "" {
		return nil, errors.New("MCP requires CA, client certificate, key and token files")
	}
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("cannot read MCP API CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid MCP API CA")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, errors.New("invalid MCP API client certificate/key")
	}
	file, err := os.Open(c.TokenFile)
	if err != nil {
		return nil, errors.New("cannot read MCP API token")
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 4097))
	_ = file.Close()
	if readErr != nil || len(token) > 4096 {
		return nil, errors.New("invalid MCP API token")
	}
	secret := strings.TrimSpace(string(token))
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, errors.New("invalid MCP API token")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}}, MaxConnsPerHost: c.MaxInFlight + 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: time.Duration(c.RequestTimeoutMS) * time.Millisecond}
	client := &apiClient{origin: strings.TrimSuffix(c.APIURL, "/"), token: secret, http: &http.Client{Transport: transport, Timeout: time.Duration(c.RequestTimeoutMS) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return newServer(client, c.MaxInFlight), nil
}

func (a *apiClient) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(body); err != nil {
			return nil, errors.New("cannot encode sandbox request")
		}
		data := encoded.Bytes()
		if len(data) > 1<<20 {
			return nil, errors.New("sandbox request exceeds 1 MiB")
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.origin+path, reader)
	if err != nil {
		return nil, errors.New("cannot create sandbox request")
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.GetBody = nil // Body-bearing tools must not be replayed by the transport.
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("sandbox API transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponse+1))
	if err != nil {
		return nil, errors.New("sandbox API response failed")
	}
	if len(data) > maxAPIResponse {
		return nil, errors.New("sandbox API response exceeds 8 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code := "api_error"
		var value struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(data, &value) == nil && safeCode(value.Code) {
			code = value.Code
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			code = "redirect_rejected"
		}
		return nil, &apiFailure{response.StatusCode, code}
	}
	if response.StatusCode == http.StatusNoContent && len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{"status":204}`), nil
	}
	if trimmed := bytes.TrimSpace(data); !json.Valid(data) || len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("sandbox API returned invalid JSON")
	}
	return data, nil
}
func safeCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func (a *apiClient) capabilities(ctx context.Context) (sandbox.CapabilityReport, error) {
	return a.capabilitiesFor(ctx, "", "")
}

func (a *apiClient) capabilitiesFor(ctx context.Context, backend, digest string) (sandbox.CapabilityReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var cap sandbox.CapabilityReport
	path := "/v1/capabilities"
	if backend != "" || digest != "" {
		path += "?" + url.Values{"backend": {backend}, "artifact_manifest_sha256": {digest}}.Encode()
	}
	raw, err := a.call(ctx, "GET", path, nil)
	if err != nil {
		return cap, err
	}
	if json.Unmarshal(raw, &cap) != nil || cap.Protocol != "osv-sandbox-capabilities/v1" || (cap.Backend == "" && cap.ArtifactAuthenticated) || cap.AllowedEntrypoints == nil {
		return cap, errors.New("sandbox API capabilities are invalid")
	}
	if backend != "" && (cap.Backend != backend || cap.ArtifactManifestSHA256 != digest) {
		return cap, errors.New("sandbox API returned different template capabilities")
	}
	return cap, nil
}
func decodeStrict(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}
