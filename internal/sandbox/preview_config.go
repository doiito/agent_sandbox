package sandbox

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PreviewConfig is a separate browser TLS endpoint. The control endpoint keeps
// its existing mTLS policy and never shares the preview authorization cookie.
type PreviewConfig struct {
	Listen     string `json:"listen"`
	OriginBase string `json:"origin_base"`
	APIOrigin  string `json:"api_origin"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
}

func previewHTTPSOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ToLower(u.Host) != u.Host {
		return nil, errors.New("preview origins must be canonical HTTPS origins")
	}
	if u.Port() != "" {
		n, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || n == 0 || strconv.Itoa(int(n)) != u.Port() {
			return nil, errors.New("invalid preview origin port")
		}
	}
	return u, nil
}
func (c PreviewConfig) validate() error {
	base, err := previewHTTPSOrigin(c.OriginBase)
	if err != nil {
		return err
	}
	api, err := previewHTTPSOrigin(c.APIOrigin)
	if err != nil {
		return err
	}
	host := base.Hostname()
	if len(host) > 180 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return errors.New("preview origin_base requires a DNS suffix")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid preview DNS suffix")
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return errors.New("preview DNS suffix must be lowercase ASCII")
			}
		}
	}
	if api.Hostname() == host || strings.HasSuffix(api.Hostname(), "."+host) {
		return errors.New("preview DNS suffix must not contain the control API origin")
	}
	_, port, err := net.SplitHostPort(c.Listen)
	n, parseErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil || n == 0 || strconv.Itoa(int(n)) != port {
		return errors.New("preview requires a distinct listen address and nonzero port")
	}
	for _, path := range []string{c.CertFile, c.KeyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("preview TLS paths must be canonical and absolute")
		}
	}
	return nil
}

func LoadPreviewTLS(config *PreviewConfig) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("preview TLS configuration is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	info, err := os.Stat(config.KeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0007 != 0 {
		return nil, errors.New("preview TLS key must be a regular file inaccessible to other users")
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, errors.New("cannot load preview TLS certificate/key")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid preview TLS certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("preview TLS certificate is not currently valid")
	}
	base, _ := previewHTTPSOrigin(config.OriginBase)
	wildcard := "*." + base.Hostname()
	found := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, wildcard) {
			found = true
		}
	}
	if !found || leaf.VerifyHostname(strings.Repeat("0", 24)+"."+base.Hostname()) != nil {
		return nil, errors.New("preview certificate must cover the configured wildcard DNS suffix")
	}
	certificate.Leaf = leaf
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.NoClientCert,
		NextProtos: []string{"http/1.1"}, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}, nil
}
