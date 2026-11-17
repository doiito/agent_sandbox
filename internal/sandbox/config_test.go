package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionConfigPathTrust(t *testing.T) {
	if err := trustedProductionConfigPath("/etc/passwd"); err != nil {
		t.Fatalf("trusted system file rejected: %v", err)
	}
	root := t.TempDir()
	config := filepath.Join(root, "config.json")
	if err := os.WriteFile(config, []byte(`{"production":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trustedProductionConfigPath(config); err == nil {
		t.Fatal("accepted configuration below world-writable /tmp")
	}
	if err := os.Chmod(config, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := trustedProductionConfigPath(config); err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Fatalf("writable configuration was not rejected at its file: %v", err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if err := trustedProductionConfigPath(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symbolic-link configuration was not rejected: %v", err)
	}
	if err := trustedProductionConfigPath("etc/passwd"); err == nil {
		t.Fatal("accepted relative production configuration")
	}
}

func TestLoadConfigRejectsUntrustedProductionPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"production":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "untrusted production configuration") {
		t.Fatalf("untrusted production configuration accepted: %v", err)
	}
}

func TestManagedRunRootPathTrust(t *testing.T) {
	if err := trustedManagedRunRootPath("/etc"); err != nil {
		t.Fatalf("trusted system directory rejected: %v", err)
	}
	if err := trustedManagedRunRootPath("/etc/passwd"); err == nil || !strings.Contains(err.Error(), "wrong file type") {
		t.Fatalf("accepted regular file as runtime directory: %v", err)
	}
	root := t.TempDir()
	if err := trustedManagedRunRootPath(root); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("accepted runtime directory below writable /tmp: %v", err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := trustedManagedRunRootPath(root); err == nil || !strings.Contains(err.Error(), root) {
		t.Fatalf("writable runtime directory not rejected at its leaf: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if err := trustedManagedRunRootPath(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("accepted symbolic runtime directory: %v", err)
	}
	for _, path := range []string{"etc", "/etc/../etc", "/etc/"} {
		if err := trustedManagedRunRootPath(path); err == nil {
			t.Fatalf("accepted noncanonical runtime directory %q", path)
		}
	}
}
