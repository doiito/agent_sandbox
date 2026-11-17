package templateoci

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RegistryOptions never disables certificate validation. Plain HTTP is an
// explicit loopback-only facility for local verification registries.
type RegistryOptions struct {
	URL            string
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
	AuthFile       string
	PlainHTTP      bool
	Timeout        time.Duration
	WorkDir        string
}

type Registry struct {
	base          *url.URL
	client        *http.Client
	authorization string
	workDir       string
}

var repositoryPattern = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)
var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
var errUnsafeLocation = errors.New("registry redirected outside its trusted origin or used an unsafe URL")

func repositoryOK(value string) bool {
	return len(value) <= 255 && repositoryPattern.MatchString(value)
}
func referenceOK(value, expected string) bool {
	return value == expected || tagPattern.MatchString(value)
}
func endpointPort(u *url.URL) string {
	if value := u.Port(); value != "" {
		return value
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && endpointPort(a) == endpointPort(b)
}
func safeURL(u *url.URL) bool {
	return u.User == nil && u.Opaque == "" && u.Fragment == "" && u.RawFragment == ""
}
func privateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("registry credential/key file must be a private regular file")
	}
	return readBounded(filepath.Dir(path), filepath.Base(path), limit)
}
func readAuthorization(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := privateFile(path, 16<<10)
	if err != nil {
		return "", err
	}
	var auth struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if decode(data, &auth) != nil {
		return "", errors.New("invalid registry credential JSON")
	}
	if auth.Token != "" {
		if auth.Username != "" || auth.Password != "" {
			return "", errors.New("registry credentials must use either Basic or Bearer")
		}
		for _, ch := range auth.Token {
			if ch < 0x21 || ch > 0x7e {
				return "", errors.New("invalid registry Bearer token")
			}
		}
		return "Bearer " + auth.Token, nil
	}
	if auth.Username == "" || auth.Password == "" || strings.Contains(auth.Username, ":") || strings.ContainsAny(auth.Username+auth.Password, "\r\n\x00") {
		return "", errors.New("invalid registry Basic credentials")
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Password)), nil
}

func NewRegistry(options RegistryOptions) (*Registry, error) {
	base, err := url.Parse(options.URL)
	if err != nil || base == nil || base.Hostname() == "" || !safeURL(base) || base.RawQuery != "" || base.ForceQuery || (base.Path != "" && base.Path != "/") || base.RawPath != "" {
		return nil, errors.New("registry URL must contain only an HTTPS origin")
	}
	base.Scheme = strings.ToLower(base.Scheme)
	if base.Scheme != "https" {
		address, parseErr := netip.ParseAddr(base.Hostname())
		if base.Scheme != "http" || !options.PlainHTTP || parseErr != nil || !address.IsLoopback() {
			return nil, errors.New("registry requires HTTPS; explicit HTTP is limited to loopback IPs")
		}
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Minute
	}
	if options.Timeout < time.Second || options.Timeout > 24*time.Hour {
		return nil, errors.New("registry timeout must be between one second and 24 hours")
	}
	if (options.ClientCertFile == "") != (options.ClientKeyFile == "") {
		return nil, errors.New("registry mTLS requires both certificate and private key")
	}
	authorization, err := readAuthorization(options.AuthFile)
	if err != nil {
		return nil, err
	}
	security := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.CAFile != "" {
		data, err := readBounded(filepath.Dir(options.CAFile), filepath.Base(options.CAFile), 4<<20)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid registry CA certificates")
		}
		security.RootCAs = pool
	}
	if options.ClientCertFile != "" {
		certificate, err := readBounded(filepath.Dir(options.ClientCertFile), filepath.Base(options.ClientCertFile), 256<<10)
		if err != nil {
			return nil, err
		}
		key, err := privateFile(options.ClientKeyFile, 256<<10)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			return nil, errors.New("invalid registry mTLS certificate/key")
		}
		security.Certificates = []tls.Certificate{pair}
	}
	transport := &http.Transport{TLSClientConfig: security, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, ExpectContinueTimeout: time.Second,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10, DisableCompression: true}
	registry := &Registry{base: base, authorization: authorization, workDir: options.WorkDir}
	registry.client = &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 4 || !safeURL(request.URL) || !sameOrigin(base, request.URL) {
			return errUnsafeLocation
		}
		if len(via) > 0 && via[0].Method != http.MethodGet && via[0].Method != http.MethodHead {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return registry, nil
}

func (r *Registry) Close() { r.client.CloseIdleConnections() }
func (r *Registry) endpoint(repository, kind, reference string) *url.URL {
	result := *r.base
	result.Path = "/v2/" + repository + "/" + kind + "/" + reference
	result.RawPath = ""
	return &result
}
func (r *Registry) request(ctx context.Context, method string, target *url.URL, body io.Reader, size int64, contentType string) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !safeURL(target) || !sameOrigin(r.base, target) {
		return nil, errUnsafeLocation
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, errors.New("invalid registry request")
	}
	request.ContentLength = size
	request.GetBody = nil // Never replay a write after a redirect or connection loss.
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "osv-template-oci/1")
	request.Header.Set("Accept", ManifestMediaType)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if r.authorization != "" {
		request.Header.Set("Authorization", r.authorization)
	}
	response, err := r.client.Do(request)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, errUnsafeLocation) {
			return nil, errUnsafeLocation
		}
		// url.Error may include an upload Location with a sensitive query.
		return nil, errors.New("registry transport failed; remote URL and response details omitted")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		response.Body.Close()
		return nil, errors.New("registry response used unsupported content encoding")
	}
	return response, nil
}
func responseStatus(response *http.Response, expected int) error {
	if response.StatusCode != expected {
		return fmt.Errorf("registry returned HTTP %d; expected %d", response.StatusCode, expected)
	}
	return nil
}
func responseDescriptor(response *http.Response, d Descriptor) error {
	if value := response.Header.Get("Docker-Content-Digest"); value != "" && value != d.Digest {
		return errors.New("registry content digest header mismatch")
	}
	if response.ContentLength >= 0 && response.ContentLength != d.Size {
		return errors.New("registry content length mismatch")
	}
	return nil
}
func (r *Registry) manifest(ctx context.Context, repository, expected string) ([]byte, Descriptor, error) {
	response, err := r.request(ctx, http.MethodGet, r.endpoint(repository, "manifests", expected), nil, 0, "")
	if err != nil {
		return nil, Descriptor{}, err
	}
	defer response.Body.Close()
	if err := responseStatus(response, http.StatusOK); err != nil {
		return nil, Descriptor{}, err
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != ManifestMediaType {
		return nil, Descriptor{}, errors.New("registry returned unsupported manifest media type")
	}
	if response.ContentLength > metadataLimit {
		return nil, Descriptor{}, errors.New("registry manifest exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, metadataLimit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, Descriptor{}, ctx.Err()
		}
		return nil, Descriptor{}, errors.New("registry manifest transfer failed")
	}
	if len(data) == 0 || int64(len(data)) > metadataLimit || digest(data) != expected {
		return nil, Descriptor{}, errors.New("registry manifest digest or size mismatch")
	}
	d := Descriptor{MediaType: ManifestMediaType, Digest: expected, Size: int64(len(data))}
	if err := responseDescriptor(response, d); err != nil {
		return nil, Descriptor{}, err
	}
	return data, d, nil
}

func (r *Registry) uploadLocation(response *http.Response) *url.URL {
	raw := response.Header.Get("Location")
	if raw == "" || len(raw) > 8192 {
		return nil
	}
	relative, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	target := response.Request.URL.ResolveReference(relative)
	if !safeURL(target) || !sameOrigin(r.base, target) {
		return nil
	}
	if _, exists := target.Query()["digest"]; exists {
		return nil
	}
	return target
}
