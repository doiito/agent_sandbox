// Package otlp provides bounded OTLP/HTTP JSON export without runtime SDK dependencies.
package otlp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Endpoint            string   `json:"endpoint"`
	ServiceName         string   `json:"service_name,omitempty"`
	InstanceID          string   `json:"instance_id,omitempty"`
	Source              string   `json:"source,omitempty"`
	Signals             []string `json:"signals,omitempty"`
	IntervalMS          int      `json:"interval_ms,omitempty"`
	TimeoutMS           int      `json:"timeout_ms,omitempty"`
	QueueCapacity       int      `json:"queue_capacity,omitempty"`
	BatchSize           int      `json:"batch_size,omitempty"`
	MaxBatchBytes       int      `json:"max_batch_bytes,omitempty"`
	TraceSamplePermille *int     `json:"trace_sample_permille,omitempty"`
	CAFile              string   `json:"ca_file,omitempty"`
	ClientCertFile      string   `json:"client_cert_file,omitempty"`
	ClientKeyFile       string   `json:"client_key_file,omitempty"`
	BearerTokenFile     string   `json:"bearer_token_file,omitempty"`
	AllowLoopbackHTTP   bool     `json:"allow_loopback_http,omitempty"`
}

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (c Config) normalized() Config {
	c.Signals = append([]string(nil), c.Signals...)
	if c.ServiceName == "" {
		c.ServiceName = "osv-sandbox"
	}
	if c.Source == "" {
		c.Source = "host.api"
	}
	if len(c.Signals) == 0 {
		c.Signals = []string{"metrics", "logs", "traces"}
	}
	if c.IntervalMS == 0 {
		c.IntervalMS = 1000
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 5000
	}
	if c.QueueCapacity == 0 {
		c.QueueCapacity = 1024
	}
	if c.BatchSize == 0 {
		c.BatchSize = min(128, c.QueueCapacity)
	}
	if c.MaxBatchBytes == 0 {
		c.MaxBatchBytes = 1 << 20
	}
	if c.TraceSamplePermille == nil {
		value := 1000
		c.TraceSamplePermille = &value
	} else {
		value := *c.TraceSamplePermille
		c.TraceSamplePermille = &value
	}
	return c
}

// Validate checks policy without opening credentials or making a network request.
func (c Config) Validate() error {
	c = c.normalized()
	if _, err := c.endpoint(); err != nil {
		return err
	}
	if !identityPattern.MatchString(c.ServiceName) || c.InstanceID != "" && !identityPattern.MatchString(c.InstanceID) || !validSource(c.Source) {
		return errors.New("invalid OTLP service identity")
	}
	if c.IntervalMS < 100 || c.IntervalMS > 60000 || c.TimeoutMS < 100 || c.TimeoutMS > 30000 ||
		c.QueueCapacity < 1 || c.QueueCapacity > 16384 || c.BatchSize < 1 || c.BatchSize > 1024 || c.BatchSize > c.QueueCapacity ||
		c.MaxBatchBytes < 64<<10 || c.MaxBatchBytes > 4<<20 || *c.TraceSamplePermille < 0 || *c.TraceSamplePermille > 1000 {
		return errors.New("OTLP timing, queue, batch or sampling limit is out of range")
	}
	seen := map[string]bool{}
	for _, name := range c.Signals {
		if signalIndex(name) < 0 || seen[name] {
			return errors.New("OTLP signals must be unique metrics, logs or traces")
		}
		seen[name] = true
	}
	if (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return errors.New("OTLP client certificate and key must be configured together")
	}
	for _, path := range []string{c.CAFile, c.ClientCertFile, c.ClientKeyFile, c.BearerTokenFile} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return errors.New("OTLP credential paths must be canonical and absolute")
		}
	}
	return nil
}

func (c Config) endpoint() (*url.URL, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || len(c.Endpoint) > 2048 || u == nil || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
		return nil, errors.New("OTLP endpoint must be an HTTP(S) origin/base path without credentials, query or fragment")
	}
	if u.Scheme != "https" {
		address, parseErr := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || !c.AllowLoopbackHTTP || parseErr != nil || !address.IsLoopback() {
			return nil, errors.New("OTLP requires HTTPS or explicit loopback-IP HTTP")
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, errors.New("OTLP base path must be canonical")
		}
	}
	if strings.Contains(u.Path, "//") || strings.ContainsAny(u.Path, "\r\n\t ") {
		return nil, errors.New("OTLP base path must be canonical")
	}
	if port := u.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return nil, errors.New("invalid OTLP endpoint port")
		}
	}
	return u, nil
}

func boundedFile(path string, limit int64, private bool) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || private && resolved != path {
		return nil, errors.New("OTLP credential path is unavailable or unsafe")
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("OTLP credential cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("OTLP credential must be a bounded regular file")
	}
	if private {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode().Perm()&0o077 != 0 || owner.Uid != 0 && owner.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("OTLP private credentials require caller/root ownership and mode 0600 or stricter")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("OTLP credential exceeds its bound")
	}
	return data, nil
}

func newHTTPClient(c Config) (*http.Client, string, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		data, err := boundedFile(c.CAFile, 1<<20, false)
		if err != nil {
			return nil, "", err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, "", errors.New("OTLP CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if c.ClientCertFile != "" {
		cert, err := boundedFile(c.ClientCertFile, 1<<20, false)
		if err != nil {
			return nil, "", err
		}
		key, err := boundedFile(c.ClientKeyFile, 64<<10, true)
		if err != nil {
			return nil, "", err
		}
		identity, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, "", errors.New("invalid OTLP client certificate/key")
		}
		tlsConfig.Certificates = []tls.Certificate{identity}
	}
	token := ""
	if c.BearerTokenFile != "" {
		data, err := boundedFile(c.BearerTokenFile, 4096, true)
		if err != nil {
			return nil, "", err
		}
		token = strings.TrimSpace(string(data))
		if token == "" || strings.IndexFunc(token, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
			return nil, "", errors.New("invalid OTLP Bearer token")
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true,
		DialContext:         (&net.Dialer{Timeout: time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: time.Duration(c.TimeoutMS) * time.Millisecond,
		MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second,
		ForceAttemptHTTP2: true}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token, nil
}
