package sandbox

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const egressRequestLimit = 256 << 10
const egressResponseLimit = 512 << 10

type EgressPolicy struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedCIDRs     []string `json:"allowed_cidrs,omitempty"`
	MaxConcurrent    int      `json:"max_concurrent,omitempty"`
	MaxRequestBytes  int      `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int      `json:"max_response_bytes,omitempty"`
	TimeoutMS        int      `json:"timeout_ms,omitempty"`
	MaxRedirects     int      `json:"max_redirects,omitempty"`
}
type egressRules struct {
	policy  EgressPolicy
	origins map[string]bool
	prefix  []netip.Prefix
}

func compileEgressPolicy(input EgressPolicy) (*egressRules, error) {
	if input.MaxConcurrent == 0 {
		input.MaxConcurrent = 2
	}
	if input.MaxRequestBytes == 0 {
		input.MaxRequestBytes = egressRequestLimit
	}
	if input.MaxResponseBytes == 0 {
		input.MaxResponseBytes = egressResponseLimit
	}
	if input.TimeoutMS == 0 {
		input.TimeoutMS = 10000
	}
	if len(input.AllowedOrigins) < 1 || len(input.AllowedOrigins) > 64 || len(input.AllowedCIDRs) > 64 ||
		input.MaxConcurrent < 1 || input.MaxConcurrent > 16 || input.MaxRequestBytes < 1 || input.MaxRequestBytes > egressRequestLimit || input.MaxResponseBytes < 1 || input.MaxResponseBytes > egressResponseLimit || input.TimeoutMS < 100 || input.TimeoutMS > 30000 || input.MaxRedirects < 0 || input.MaxRedirects > 5 {
		return nil, errors.New("invalid egress policy bounds")
	}
	rules := &egressRules{policy: input, origins: map[string]bool{}}
	rules.policy.AllowedOrigins = make([]string, 0, len(input.AllowedOrigins))
	for _, value := range input.AllowedOrigins {
		u, origin, err := egressURL(value)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || rules.origins[origin] {
			return nil, errors.New("invalid or duplicate egress allowed origin")
		}
		rules.origins[origin] = true
		rules.policy.AllowedOrigins = append(rules.policy.AllowedOrigins, origin)
	}
	for _, value := range input.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, errors.New("egress CIDRs must be canonical IPv4 or IPv6 prefixes")
		}
		rules.prefix = append(rules.prefix, prefix)
	}
	return rules, nil
}

func egressURL(value string) (*url.URL, string, error) {
	u, err := url.Parse(value)
	if err != nil || len(value) > 8192 || (u.Scheme != "https" && u.Scheme != "http") || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" || strings.Contains(u.Host, "%") {
		return nil, "", errors.New("invalid HTTP egress URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || len(host) > 253 {
		return nil, "", errors.New("invalid egress host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, "", errors.New("invalid egress DNS name")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, "", errors.New("egress DNS names must use ASCII labels")
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, "", errors.New("invalid egress port")
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(n))
	return u, u.Scheme + "://" + u.Host, nil
}

var nonPublicEgress = func() []netip.Prefix {
	// Non-public/special-use destinations. Explicit administrator CIDRs can
	// authorize a private service, but never unspecified, multicast or link-local.
	values := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8"}
	var result []netip.Prefix
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}()

func (rules *egressRules) allowsIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() || ip.String() == "100.100.100.200" || ip.String() == "fd00:ec2::254" {
		return false
	}
	if len(rules.prefix) > 0 {
		for _, prefix := range rules.prefix {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range nonPublicEgress {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
