package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgsHelpVersionAndBillSyntax(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		code int
		text string
	}{
		{"help", []string{"-help"}, 0, "bill-export"},
		{"export-help", []string{"bill-export", "-help"}, 0, "-tenant"},
		{"verify-help", []string{"bill-verify", "-help"}, 0, "-archive"},
		{"version", []string{"-config", "/missing/config", "-version"}, 0, "osv-sandbox-network-fetch/v1"},
		{"unknown", []string{"bill-remove"}, 2, "unknown bill command"},
		{"export-no-path", []string{"bill-export", "-tenant", "t", "-task", "task"}, 2, "requires"},
		{"verify-extra-tenant", []string{"bill-verify", "-archive", "/file", "-tenant", "t"}, 2, "requires only"},
		{"retire-extra-output", []string{"bill-retire", "-archive", "/file", "-output", "/other"}, 2, "requires only"},
		{"extra-positional", []string{"bill-verify", "-archive", "/file", "extra"}, 2, "unexpected bill arguments"},
		{"unknown-flag", []string{"-not-a-flag"}, 2, "flag provided but not defined"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if code := runArgs(test.args, &out, &diagnostic); code != test.code || !strings.Contains(out.String()+diagnostic.String(), test.text) {
				t.Fatalf("code %d, output %q, diagnostic %q", code, out.String(), diagnostic.String())
			}
			if strings.Contains(diagnostic.String(), "configuration rejected") {
				t.Fatal("help, version or syntax validation opened daemon configuration")
			}
			if test.name == "version" {
				var version map[string]string
				if json.Unmarshal(out.Bytes(), &version) != nil || version["name"] != "osv-sandbox-egress" {
					t.Fatal("version output stopped being JSON")
				}
			}
		})
	}
}

func TestBillVerifyDoesNotLoadDaemonConfiguration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only maintenance command")
	}
	archive := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(archive, []byte(`{"invalid":"archive"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runArgs([]string{"-config", "/missing/config", "bill-verify", "-archive", archive}, &out, &diagnostic)
	if code != 1 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "bill maintenance failed") || strings.Contains(diagnostic.String(), "configuration rejected") {
		t.Fatal("offline verify depended on daemon configuration", code, diagnostic.String())
	}
}
