package sandbox

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIRequiresAuthentication(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/v1/doctor", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d", w.Code)
	}
}

func TestAPIRejectsUnknownJSONFields(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", strings.NewReader(`{"unknown":true}`))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIEndToEndWithHelperBackend(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := bytes.NewBufferString(`{"entrypoint":"/agent","args":["echo","hello"]}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", body)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"protocol_ok":true`) {
		t.Fatalf("unexpected response %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIExportsAuthenticatedPrometheusMetrics(t *testing.T) {
	m := testManager(t, "output")
	h := NewAPI(m, "secret", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "osv_sandbox_jobs_total") {
		t.Fatalf("unexpected metrics response %d: %s", w.Code, w.Body.String())
	}
}
