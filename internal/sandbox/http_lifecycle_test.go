package sandbox

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionListStableTenantPagesAndCurrentLiveness(t *testing.T) {
	auth := sessionAuthForTest()
	tenant, _ := auth.Authenticate("Bearer token-a")
	tenant.policy.MaxConcurrent = 4
	tenant.sem = make(chan struct{}, 4)
	handler := NewAPIWithAuthenticator(&fakeSessionRunner{}, auth, slog.Default())
	body := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `","ttl_ms":10000}`
	create := func(token string) SessionInfo {
		response := sessionHTTPCall(handler, token, "POST", "/v2/sessions", body)
		var info SessionInfo
		if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &info) != nil {
			t.Fatal(response.Code, response.Body.String())
		}
		return info
	}
	first, second, third := create("token-a"), create("token-a"), create("token-b")
	defer func() {
		for _, row := range []struct{ token, id string }{{"token-a", first.ID}, {"token-a", second.ID}, {"token-b", third.ID}} {
			sessionHTTPCall(handler, row.token, "DELETE", "/v2/sessions/"+row.id, "")
		}
	}()
	query := func(token, path string) SessionListPage {
		response := sessionHTTPCall(handler, token, "GET", path, "")
		var page SessionListPage
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil {
			t.Fatal(response.Code, response.Body.String())
		}
		return page
	}
	page := query("token-a", "/v2/sessions?limit=1&order=asc")
	if len(page.Sessions) != 1 || page.Sessions[0].ID != first.ID || page.NextCursor == "" {
		t.Fatal("unstable first page", page)
	}
	later := create("token-a")
	defer sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+later.ID, "")
	next := query("token-a", "/v2/sessions?limit=1&order=asc&cursor="+page.NextCursor)
	if len(next.Sessions) != 1 || next.Sessions[0].ID != second.ID || next.NextCursor != "" {
		t.Fatal("new item mixed into snapshot", next)
	}
	denied := sessionHTTPCall(handler, "token-b", "GET", "/v2/sessions?limit=1&order=asc&cursor="+page.NextCursor, "")
	if denied.Code != 404 {
		t.Fatal("foreign cursor accepted", denied.Code)
	}
	ownB := query("token-b", "/v2/sessions")
	if len(ownB.Sessions) != 1 || ownB.Sessions[0].ID != third.ID {
		t.Fatal("foreign session leaked", ownB)
	}
	sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+second.ID, "")
	afterDelete := query("token-a", "/v2/sessions?limit=1&order=asc&cursor="+page.NextCursor)
	if len(afterDelete.Sessions) != 0 {
		t.Fatal("deleted item stayed live", afterDelete)
	}
	for i := 0; i < 9; i++ {
		query("token-a", "/v2/sessions?limit=1&order=asc")
	}
	stale := sessionHTTPCall(handler, "token-a", "GET", "/v2/sessions?limit=1&order=asc&cursor="+page.NextCursor, "")
	if stale.Code != 404 {
		t.Fatal("snapshot count bound not enforced", stale.Code)
	}
	for _, path := range []string{"/v2/sessions?limit=0", "/v2/sessions?limit=101", "/v2/sessions?order=random", "/v2/sessions?cursor=bad"} {
		if response := sessionHTTPCall(handler, "token-a", "GET", path, ""); response.Code != 400 {
			t.Fatal("invalid page accepted", path, response.Code)
		}
	}
}
func TestSessionAPITimeoutRenewalAndExpiryDoNotResurrect(t *testing.T) {
	runner := &fakeSessionRunner{closeStarted: make(chan struct{}, 1)}
	auth := sessionAuthForTest()
	handler := NewAPIWithAuthenticator(runner, auth, slog.Default())
	body := `{"backend":"firecracker-linux","artifact_manifest_sha256":"` + strings.Repeat("a", 64) + `","ttl_ms":150}`
	created := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", body)
	var info SessionInfo
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &info) != nil {
		t.Fatal(created.Body.String())
	}
	path := "/v2/sessions/" + info.ID
	updated := sessionHTTPCall(handler, "token-a", "POST", path+"/timeout", `{"ttl_ms":1000}`)
	if updated.Code != 200 {
		t.Fatal(updated.Code, updated.Body.String())
	}
	time.Sleep(200 * time.Millisecond)
	if response := sessionHTTPCall(handler, "token-a", "GET", path, ""); response.Code != 200 {
		t.Fatal("old API timer fired after renewal", response.Code)
	}
	denied := sessionHTTPCall(handler, "token-b", "POST", path+"/timeout", `{"ttl_ms":1000}`)
	if denied.Code != 404 {
		t.Fatal("foreign renewal accepted")
	}
	invalid := sessionHTTPCall(handler, "token-a", "POST", path+"/timeout", `{"ttl_ms":0}`)
	if invalid.Code != 400 {
		t.Fatal("invalid renewal accepted")
	}
	// Expiry closes asynchronously. Polling Info at the exact timer boundary
	// can intentionally quarantine quota when it races the close RPC. Observe
	// the fake owner's close and actual slot release instead of asserting that
	// an absent API row is already a cleanup acknowledgment.
	select {
	case <-runner.closeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("renewed session did not close at expiry")
	}
	tenant, _ := auth.Authenticate("Bearer token-a")
	deadline := time.Now().Add(time.Second)
	for len(tenant.sem) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(tenant.sem) != 0 {
		t.Fatal("acknowledged expiry did not release quota")
	}
	if response := sessionHTTPCall(handler, "token-a", "POST", path+"/timeout", `{"ttl_ms":1000}`); response.Code != http.StatusNotFound {
		t.Fatal("expired API session resurrected", response.Code)
	}
	if response := sessionHTTPCall(handler, "token-a", "POST", "/v2/sessions", body); response.Code != 201 {
		t.Fatal("expiry retained quota", response.Code)
	} else {
		var next SessionInfo
		json.Unmarshal(response.Body.Bytes(), &next)
		sessionHTTPCall(handler, "token-a", "DELETE", "/v2/sessions/"+next.ID, "")
	}
}
