package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExplicitProxyHandlesLoopbackTargetWithoutDirectBypass(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://127.0.0.1:1/private" {
			t.Error("proxy did not receive absolute target", r.URL)
		}
		_, _ = w.Write([]byte{0, 255})
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	var output, errors bytes.Buffer
	if code := run([]string{"http://127.0.0.1:1/private"}, &output, &errors); code != 0 || !bytes.Equal(output.Bytes(), []byte{0, 255}) {
		t.Fatal(code, output.Bytes(), errors.String())
	}
}

func TestHTTPSRejectsUntrustedCAAndNonSuccessStatusIsExplicit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "must-not-succeed") }))
	defer server.Close()
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	var output, errors bytes.Buffer
	if code := run([]string{server.URL}, &output, &errors); code != 1 || output.Len() != 0 {
		t.Fatal("untrusted TLS accepted", code, output.String())
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404); fmt.Fprint(w, "missing") }))
	defer plain.Close()
	if code := run([]string{plain.URL}, &output, &errors); code != 22 || output.String() != "missing" {
		t.Fatal(code, output.String())
	}
}
