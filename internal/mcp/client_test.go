package mcp

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientBodyBoundsAndStatusNormalization(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		ok     bool
	}{
		{204, "", true}, {200, `{"ok":true}`, true},
		{200, `null`, false}, {200, `[]`, false}, {200, "", false},
		{200, strings.Repeat("x", maxAPIResponse+1), false},
		{403, `{"code":"bad credential-text"}`, false},
	} {
		s := mockServer(1, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})
		value, err := s.api.call(context.Background(), "DELETE", "/test", nil)
		if (err == nil) != test.ok {
			t.Fatalf("status %d: %v", test.status, err)
		}
		if test.status == 204 && string(value) != `{"status":204}` {
			t.Fatal("successful empty close was misclassified", string(value))
		}
	}
}

func TestConfigRejectsInvalidOriginsAndUnknownSettings(t *testing.T) {
	for _, origin := range []string{"http://localhost", "https://u:p@localhost", "https://localhost/api", "https://localhost?", "https://localhost?q=1", "https://localhost/#fragment"} {
		if _, err := NewServer(Config{APIURL: origin}); err == nil || !strings.Contains(err.Error(), "HTTPS origin") {
			t.Fatal("invalid fixed origin accepted", origin, err)
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, content := range []string{`{"api_url":"https://localhost","skip_tls_verify":true}`, `{}`, strings.Repeat(" ", 65537)} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		config, err := LoadConfig(path)
		if content == `{}` {
			_, err = NewServer(config)
		}
		if err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
