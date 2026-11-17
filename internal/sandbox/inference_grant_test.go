package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func inferenceTestGuestProfile(backend string) *SignedGuestInference {
	transport := "linux-loopback-v1"
	if backend == "firecracker-osv" {
		transport = "osv-vsock-cabi-v1"
	}
	profile := &SignedGuestInference{Protocol: guestInferenceProfileProtocol, Architecture: "amd64", Transport: transport, FilesSHA256: map[string]string{}}
	for _, path := range guestInferencePaths(backend) {
		profile.FilesSHA256[path] = strings.Repeat("a", 64)
	}
	return profile
}

func TestInferenceGuestPolicyGrantRejectsChangedServicePolicy(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(provider.Close)
	_, _, original, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	binding := inferenceTestBinding()
	grant := inferenceGuestTestGrant(t, original, binding)
	for _, change := range []string{"price", "egress-timeout", "endpoint-path"} {
		t.Run(change, func(t *testing.T) {
			server, root, current, _, _ := inferenceServiceFixture(t, provider.URL, func(n *EgressPolicy, p *InferencePolicy) {
				switch change {
				case "price":
					p.Endpoints[0].Price.RequestUnits++
				case "egress-timeout":
					n.TimeoutMS++
				case "endpoint-path":
					p.Endpoints[0].URL += "/changed"
				}
			})
			if _, err := root.task(context.Background(), "bind", binding); err != nil {
				t.Fatal(err)
			}
			conn, _, err := dialGuestProxyEgress(context.Background(), current, binding.Tenant, binding.VMID, binding.LeaseID, grant)
			if conn != nil {
				conn.Close()
			}
			if err == nil || calls.Load() != 0 || len(server.slots) != 0 {
				t.Fatal("old root grant adopted changed service policy")
			}
			bill, err := server.inference.ledger.boundTask(binding, true)
			if err != nil || len(bill.Invocations) != 0 || bill.HeldUnits != 0 || bill.SettledUnits != 0 {
				t.Fatal("policy refusal consumed budget", err)
			}
		})
	}
}

func TestInferenceGuestOuterPolicyCannotBeSuppliedByInnerRequest(t *testing.T) {
	server, _, _, _, _ := inferenceServiceFixture(t, "http://127.0.0.1:1/model", nil)
	for _, item := range []struct {
		name, marker, digest string
		status               int
	}{
		{"missing", "remote-infer-v1", "", 400},
		{"uppercase", "remote-infer-v1", strings.Repeat("A", 64), 400},
		{"short", "remote-infer-v1", "abc", 400},
		{"digest-without-grant", "", strings.Repeat("a", 64), 400},
		{"unknown-marker", "remote-infer-v2", strings.Repeat("a", 64), 400},
		{"stale", "remote-infer-v1", strings.Repeat("0", 64), 503},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := guestProxyUpgradeRequest().WithContext(context.WithValue(context.Background(), egressPeerKey{}, uint32(0)))
			r.Header.Set("X-OSV-Tenant", inferenceTestBinding().Tenant)
			r.Header.Set("X-OSV-Task", inferenceTestBinding().TaskID)
			r.Header.Set("X-OSV-Inference", item.marker)
			r.Header.Set("X-OSV-Inference-Policy", item.digest)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, r)
			if response.Code != item.status || len(server.slots) != 0 {
				t.Fatal("invalid outer policy was admitted", response.Code)
			}
		})
	}
}
