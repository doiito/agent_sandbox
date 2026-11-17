package offlinebundle

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type stageMutationWriter struct {
	bytes.Buffer
	mutate func()
	once   bool
}

func (w *stageMutationWriter) Write(data []byte) (int, error) {
	if !w.once {
		w.once = true
		w.mutate()
	}
	return w.Buffer.Write(data)
}

func TestPackWithReferenceBindsActualPackedPayload(t *testing.T) {
	source, public, private := fixture(t)
	sdk := filepath.Join(source, "sdk/python/osv_sandbox_client.py")
	if err := os.MkdirAll(filepath.Dir(sdk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sdk, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	commit := strings.Repeat("a", 40)
	var original bytes.Buffer
	if err := Pack(source, &original, "candidate", "amd64", commit, expires, private); err != nil {
		t.Fatal(err)
	}
	reference, err := Verify(bytes.NewReader(original.Bytes()), public, "amd64", "")
	if err != nil {
		t.Fatal(err)
	}
	var accepted bytes.Buffer
	if err := PackWithReference(source, &accepted, "formal", "amd64", strings.Repeat("b", 40), expires, private, reference); err != nil {
		t.Fatal(err)
	}
	parsed, err := Verify(bytes.NewReader(accepted.Bytes()), public, "amd64", "")
	if err != nil || parsed.Version != "formal" || !slices.Equal(parsed.Files, reference.Files) {
		t.Fatal("formal wrapper changed validated payload", err)
	}
	// A same-size SDK edit after preflight must fail before any output header.
	if err := os.WriteFile(sdk, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	var rejected bytes.Buffer
	if err := PackWithReference(source, &rejected, "formal", "amd64", commit, expires, private, reference); err == nil || rejected.Len() != 0 {
		t.Fatal("modified SDK packed", err, rejected.Len())
	}
	if err := os.WriteFile(sdk, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A later mutation is caught by the existing write-time hash check; callers
	// must discard the partial output (the CLI removes it on every pack error).
	writer := &stageMutationWriter{mutate: func() {
		if err := os.WriteFile(sdk, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}}
	if err := PackWithReference(source, writer, "formal", "amd64", commit, expires, private, reference); err == nil {
		t.Fatal("write-time mutation accepted")
	}
	if _, err := Verify(bytes.NewReader(writer.Bytes()), public, "amd64", ""); err == nil {
		t.Fatal("partial mutated archive verified")
	}
}
