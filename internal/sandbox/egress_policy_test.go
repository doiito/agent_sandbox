package sandbox

import (
	"net/netip"
	"strings"
	"testing"
)

func TestEgressPolicyOriginsAndDestinations(t *testing.T) {
	rules, err := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://EXAMPLE.com", "http://[2001:4860::1]:8080"}})
	if err != nil || !rules.origins["https://example.com:443"] || !rules.origins["http://[2001:4860::1]:8080"] {
		t.Fatal(rules, err)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !rules.allowsIP(netip.MustParseAddr(ip)) {
			t.Fatal("public address rejected", ip)
		}
	}
	for _, ip := range []string{"0.1.2.3", "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "100.64.1.1", "192.0.2.10", "198.18.0.1", "198.51.100.1", "203.0.113.1", "192.88.99.1", "224.0.0.1", "255.255.255.255", "240.1.2.3", "::1", "::", "::ffff:127.0.0.1", "fe80::1", "fd00:ec2::254", "fc00::1", "ff02::1", "2001:db8::1", "2002:808:808::1", "3fff::1", "5f00::1", "64:ff9b::808:808"} {
		if rules.allowsIP(netip.MustParseAddr(ip)) {
			t.Fatal("special/private address allowed by default", ip)
		}
	}
	private, err := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://private.example"}, AllowedCIDRs: []string{"10.0.0.0/8", "127.0.0.1/32", "::1/128", "fd00::/8"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "127.0.0.1", "::1", "fd01::1"} {
		if !private.allowsIP(netip.MustParseAddr(ip)) {
			t.Fatal("explicit private service denied", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "169.254.169.254", "fd00:ec2::254"} {
		if private.allowsIP(netip.MustParseAddr(ip)) {
			t.Fatal("CIDR override escaped its scope", ip)
		}
	}
}

func TestEgressPolicyRejectsAmbiguousURLsAndBounds(t *testing.T) {
	for _, input := range []string{"file:///etc/passwd", "ftp://example.com", "https://u:p@example.com", "https://example.com/#fragment", "https://example.com.", "https://*.example.com", "https://例子.com", "https://[fe80::1%25eth0]", "https://example.com:0", "https://example.com:65536", "https://a..example.com", "https://bad_name.example", "https://-bad.example", "https://example.com:bad"} {
		if _, _, err := egressURL(input); err == nil {
			t.Fatal("ambiguous URL accepted", input)
		}
	}
	for _, policy := range []EgressPolicy{
		{}, {AllowedOrigins: []string{"https://example.com/path"}}, {AllowedOrigins: []string{"https://example.com?query"}},
		{AllowedOrigins: []string{"https://example.com?"}}, {AllowedOrigins: []string{"https://example.com", "https://example.com:443"}},
		{AllowedOrigins: []string{"https://example.com"}, AllowedCIDRs: []string{"10.1.0.0/8"}},
		{AllowedOrigins: []string{"https://example.com"}, MaxConcurrent: 17}, {AllowedOrigins: []string{"https://example.com"}, MaxRequestBytes: egressRequestLimit + 1},
		{AllowedOrigins: []string{"https://example.com"}, MaxResponseBytes: egressResponseLimit + 1}, {AllowedOrigins: []string{"https://example.com"}, TimeoutMS: 30001},
		{AllowedOrigins: []string{"https://example.com"}, MaxRedirects: 6},
	} {
		if _, err := compileEgressPolicy(policy); err == nil {
			t.Fatal("invalid policy accepted", policy)
		}
	}
	rules, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://example.com"}})
	for _, request := range []NetworkFetchRequest{
		{Method: "CONNECT"}, {Method: "TRACE"}, {Method: "get"}, {BodyBase64: "%%%"}, {BodyBase64: "YQ=="}, {Method: "POST", BodyBase64: "YQ==\n"},
		{Headers: map[string]string{"Host": "other"}}, {Headers: map[string]string{"Proxy-Authorization": "secret"}}, {Headers: map[string]string{"Connection": "upgrade"}},
		{Headers: map[string]string{"X-Test": "one\r\nHost: other"}}, {Headers: map[string]string{"X-Test": "\x01"}}, {Headers: map[string]string{"X-A": "", "x-a": "duplicate"}},
		{Headers: map[string]string{"X-A": strings.Repeat("x", 4097)}}, {TimeoutMS: -1}, {TimeoutMS: rules.policy.TimeoutMS + 1},
	} {
		if _, _, _, err := prepareEgressRequest(request, rules); err == nil {
			t.Fatal("invalid request accepted", request)
		}
	}
}
