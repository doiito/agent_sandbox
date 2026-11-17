package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledEgressPublicRootsMatchProvenance(t *testing.T) {
	root := filepath.Join("..", "..", "assets", "trust", "mozilla-2026-10-20")
	bundle, e1 := os.ReadFile(filepath.Join(root, "cacert.pem"))
	source, e2 := os.ReadFile(filepath.Join(root, "source-lock.json"))
	license, e3 := os.ReadFile(filepath.Join(root, "LICENSE"))
	if e1 != nil || e2 != nil || e3 != nil {
		t.Fatal(e1, e2, e3)
	}
	version, count, err := verifyEgressRoots(bundle, source, license)
	if err != nil || version != "2026-10-20" || count != 118 {
		t.Fatal(version, count, err)
	}
	mutated := append([]byte(nil), bundle...)
	mutated[len(mutated)-1] ^= 1
	if _, _, err = verifyEgressRoots(mutated, source, license); err == nil {
		t.Fatal("changed trust bundle accepted")
	}
	if _, _, err = verifyEgressRoots(bundle, source, append(license, 'x')); err == nil {
		t.Fatal("changed license accepted")
	}
}
