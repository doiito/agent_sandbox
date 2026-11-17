package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireProductionRejectsDiagnosticConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"artifact_root":"/tmp","allowed_entrypoints":["/agent"]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path, false); err != nil {
		t.Fatalf("diagnostic config should remain usable: %v", err)
	}
	if _, err := loadConfig(path, true); err == nil || !strings.Contains(err.Error(), "requires production=true") {
		t.Fatalf("required production mode was bypassed: %v", err)
	}
}
