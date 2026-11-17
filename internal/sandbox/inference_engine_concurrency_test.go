package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferenceEngineConcurrentBudgetPrecedesEveryHTTPAttempt(t *testing.T) {
	arrived, release := make(chan struct{}, 8), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		calls.Add(1)
		arrived <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	engine, ledger, _, _ := inferenceEngineFixture(t, server.URL, func(n *EgressPolicy, p *InferencePolicy) {
		n.TimeoutMS = 10000
		quote, _ := p.Endpoints[0].Price.cost(2, uint64(n.MaxResponseBytes))
		*p.BudgetUnits = 2 * quote
	}, nil)
	// Unblock the fixture even if a failed assertion aborts the test early.
	defer close(release)
	results := make(chan error, 8)
	for n := 1; n <= 8; n++ {
		request := inferenceRequest(n)
		request.Payload = json.RawMessage(`{}`)
		go func() { _, err := engine.invoke(context.Background(), inferenceTestBinding(), request); results <- err }()
	}
	for n := 0; n < 2; n++ {
		select {
		case <-arrived:
		case <-time.After(3 * time.Second):
			t.Fatal("two reserved invocations did not reach provider")
		}
	}
	// Leave both successful requests blocked until all other admissions have
	// been rejected; settling one early could legitimately free new budget.
	for n := 0; n < 6; n++ {
		select {
		case err := <-results:
			expectInferenceFailure(t, err, "inference_budget")
		case <-time.After(3 * time.Second):
			t.Fatal("budget rejection waited for provider completion")
		}
	}
	bill, err := ledger.bill("tenant-a", inferenceTestBinding().TaskID)
	if err != nil || len(bill.Invocations) != 2 || bill.SettledUnits != 0 || calls.Load() != 2 || bill.HeldUnits != *bill.BudgetUnits {
		t.Fatal("concurrent request escaped durable worst-case reservation", bill, err)
	}
	// Sending two tokens releases just these accepted requests while keeping a
	// single deferred close for reliable fixture cleanup.
	for n := 0; n < 2; n++ {
		release <- struct{}{}
	}
	for n := 0; n < 2; n++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("settlement did not complete")
		}
	}
	bill, err = ledger.bill("tenant-a", inferenceTestBinding().TaskID)
	if err != nil || bill.HeldUnits != 0 || bill.SettledUnits != 30 {
		t.Fatal("unused budget was not released after known completion", bill, err)
	}
}

func TestInferenceEngineSharesExistingEgressQuotas(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	engine, _, tenant, _ := inferenceEngineFixture(t, server.URL, func(n *EgressPolicy, _ *InferencePolicy) { n.MaxConcurrent = 1 }, nil)
	release, err := engine.egress.acquireProxySlot(tenant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	expectInferenceFailure(t, err, "inference_busy")
	if calls.Load() != 0 {
		release()
		t.Fatal("inference bypassed the ordinary egress tenant quota")
	}
	_, err = engine.invokeFromGuest(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	release()
	expectInferenceFailure(t, err, "inference_busy")
	result, err := engine.invokeFromGuest(context.Background(), inferenceTestBinding(), inferenceRequest(1))
	if err != nil || result.Invocation.State != "succeeded" || calls.Load() != 1 {
		t.Fatal("rate-admitted guest did not acquire the shared work quota once", err)
	}
}

func TestInferenceEngineDNSAndTLSFailuresNeverBecomeUncertainCharges(t *testing.T) {
	for _, name := range []string{"dns-address", "dns-error", "tls", "dial"} {
		t.Run(name, func(t *testing.T) {
			var calls, dials atomic.Int32
			server, _ := egressTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			engine, ledger, _, _ := inferenceEngineFixture(t, server.URL, nil, nil)
			code := "inference_tls"
			if name == "dns-address" || name == "dns-error" {
				// Recompile the configured endpoint with a DNS name while keeping
				// its policy fixed before initializing the core.
				engine, ledger, _, _ = inferenceEngineFixture(t, "https://allowed.test:443/invoke", nil, nil)
				engine.egress.engine.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
					if name == "dns-error" {
						return nil, errors.New("private resolver detail")
					}
					return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
				}
				code = "inference_ip_denied"
				if name == "dns-error" {
					code = "inference_dns"
				}
			}
			originalDial := engine.egress.engine.dial
			engine.egress.engine.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if name == "dial" {
					return nil, errors.New("private dial detail")
				}
				return originalDial(ctx, network, address)
			}
			if name == "dial" {
				code = "inference_upstream"
			}
			_, err := engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
			expectInferenceFailure(t, err, code)
			bill, receipt := inferenceOneReceipt(t, ledger)
			if receipt.Dispatched || receipt.State != "failed" || bill.SettledUnits != 0 || bill.HeldUnits != 0 || calls.Load() != 0 {
				t.Fatal("pre-HTTP failure invented provider execution or cost", bill)
			}
			if (name == "dns-address" || name == "dns-error") && dials.Load() != 0 {
				t.Fatal("denied or unresolved DNS answer was dialed")
			}
		})
	}
}

func TestInferenceEngineAuditFailureWithholdsDataAndStopsFurtherSpend(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"answer":42}`))
			}))
			t.Cleanup(server.Close)
			engine, ledger, _, _ := inferenceEngineFixture(t, server.URL, nil, &egressMemoryAudit{failAt: failAt})
			result, err := engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
			expectInferenceFailure(t, err, "inference_audit")
			bill, receipt := inferenceOneReceipt(t, ledger)
			if len(result.Data) != 0 {
				t.Fatal("data escaped before durable completion audit")
			}
			if failAt < 3 && (calls.Load() != 0 || receipt.Dispatched || bill.SettledUnits != 0 || bill.HeldUnits != 0) {
				t.Fatal("audit failure before dial consumed model budget", bill)
			}
			if failAt == 3 && (calls.Load() != 1 || receipt.State != "succeeded" || bill.SettledUnits == 0) {
				t.Fatal("known model completion was lost after audit failure", bill)
			}
			before := calls.Load()
			_, err = engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(2))
			expectInferenceFailure(t, err, "inference_unavailable")
			if calls.Load() != before {
				t.Fatal("audit fault did not latch admissions closed")
			}
		})
	}
}

func TestInferenceEngineCompletionCommitFaultWithholdsDataAndRecoversCanonicalBill(t *testing.T) {
	for _, stage := range []string{"before_rename", "after_rename"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)
			engine, ledger, _, directory := inferenceEngineFixture(t, server.URL, nil, nil)
			writes := 0
			ledger.fault = func(point string) error {
				if point == stage {
					writes++
					if writes == 2 {
						return errors.New("simulated completion commit fault")
					}
				}
				return nil
			}
			result, err := engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(1))
			expectInferenceFailure(t, err, "inference_store")
			if len(result.Data) != 0 || calls.Load() != 1 {
				t.Fatal("result escaped an unconfirmed bill commit")
			}
			_, err = engine.invoke(context.Background(), inferenceTestBinding(), inferenceRequest(2))
			expectInferenceFailure(t, err, "inference_unavailable")
			engine.Close()
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenInferenceLedger(directory, 16)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			bill, receipt := inferenceOneReceipt(t, reopened)
			if stage == "before_rename" && (receipt.State != "uncertain" || bill.HeldUnits != receipt.ReservedUnits || bill.SettledUnits != 0) {
				t.Fatal("unconfirmed completion released its reservation", bill)
			}
			if stage == "after_rename" && (receipt.State != "succeeded" || bill.HeldUnits != 0 || bill.SettledUnits == 0) {
				t.Fatal("canonical completed record was overwritten during recovery", bill)
			}
			if calls.Load() != 1 {
				t.Fatal("recovery repeated the provider request")
			}
		})
	}
}
