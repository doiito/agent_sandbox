package sandbox

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func portErrorIs(t *testing.T, err error, code string) {
	t.Helper()
	var typed *PortRequestError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("want port %s, got %v", code, err)
	}
}

func TestPortPolicyStrictLoadingDefaultDenyAndReservedProxy(t *testing.T) {
	for _, name := range []string{"absent", "valid", "zero", "reversed", "overlap", "unsorted", "too_many", "quota_zero", "quota_large", "unknown", "overflow"} {
		t.Run(name, func(t *testing.T) {
			policy := map[string]any{"allowed_ports": []map[string]int{{"from": 1024, "to": 65535}}, "max_concurrent": 2, "preview": true}
			switch name {
			case "zero":
				policy["allowed_ports"] = []map[string]int{{"from": 0, "to": 8080}}
			case "reversed":
				policy["allowed_ports"] = []map[string]int{{"from": 8081, "to": 8080}}
			case "overlap":
				policy["allowed_ports"] = []map[string]int{{"from": 3000, "to": 4000}, {"from": 4000, "to": 5000}}
			case "unsorted":
				policy["allowed_ports"] = []map[string]int{{"from": 8080, "to": 8080}, {"from": 3000, "to": 3000}}
			case "too_many":
				ranges := []map[string]int{}
				for i := 1; i <= 17; i++ {
					ranges = append(ranges, map[string]int{"from": i, "to": i})
				}
				policy["allowed_ports"] = ranges
			case "quota_zero":
				policy["max_concurrent"] = 0
			case "quota_large":
				policy["max_concurrent"] = 129
			case "unknown":
				policy["address"] = "host.example"
			case "overflow":
				policy["allowed_ports"] = []map[string]int{{"from": 65536, "to": 65536}}
			}
			tenant := map[string]any{"id": "tenant-a", "token_sha256": strings.Repeat("a", 64), "allowed_entrypoints": []string{"*"}, "requests_per_second": 10, "burst": 10, "max_concurrent": 2}
			if name != "absent" {
				tenant["ports"] = policy
			}
			body, _ := json.Marshal(map[string]any{"protocol": "osv-sandbox-auth/v1", "tenants": []any{tenant}})
			path := filepath.Join(t.TempDir(), "auth.json")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			auth, err := LoadAuthenticator(path)
			if name != "absent" && name != "valid" {
				if err == nil {
					t.Fatal("invalid policy accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			owner := auth.portTenant("tenant-a")
			if auth.portTenant("other") != nil {
				t.Fatal("unknown tenant gained policy")
			}
			if name == "absent" {
				_, err = owner.acquirePort(8080)
				portErrorIs(t, err, "denied")
				return
			}
			for _, port := range []uint16{0, 80, 3128} {
				_, err = owner.acquirePort(port)
				portErrorIs(t, err, "denied")
			}
			a, err := owner.acquirePort(8080)
			if err != nil {
				t.Fatal(err)
			}
			b, err := owner.acquirePort(3000)
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.acquirePort(8080)
			portErrorIs(t, err, "quota")
			a()
			a()
			b()
			if len(owner.portSem) != 0 {
				t.Fatal("capacity retained")
			}
			if !owner.policy.Ports.Preview {
				t.Fatal("preview opt-in lost")
			}
		})
	}
	legacy := NewSingleTokenAuthenticator("fixture-token").portTenant("legacy")
	_, err := legacy.acquirePort(8080)
	portErrorIs(t, err, "denied")
}
