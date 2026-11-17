package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInferenceAdminClosedBillExportVerifyAndExactRetire(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"private-response"}`))
	}))
	t.Cleanup(provider.Close)
	s, root, main, _, _ := inferenceServiceFixture(t, provider.URL, nil)
	ctx, binding := context.Background(), inferenceTestBinding()
	if _, err := root.task(ctx, "bind", binding); err != nil {
		t.Fatal(err)
	}
	if _, err := root.invoke(ctx, binding, inferenceRequest(1)); err != nil {
		t.Fatal(err)
	}
	config := EgressServiceConfig{SocketPath: main, GuestProxy: true, Inference: &InferenceServiceConfig{}}
	path := filepath.Join(t.TempDir(), "archives", "bill.json")
	export := InferenceBillAdminRequest{Operation: "bill-export", Tenant: binding.Tenant, TaskID: binding.TaskID, Path: path}
	if _, err := RunInferenceBillAdmin(ctx, config, export); err == nil {
		t.Fatal("open task exported")
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed export published a directory or archive", err)
	}
	if _, err := root.task(ctx, "close", binding); err != nil {
		t.Fatal(err)
	}
	report, err := RunInferenceBillAdmin(ctx, config, export)
	if err != nil || !report.Verified || report.Retired || report.Tenant != binding.Tenant || report.TaskID != binding.TaskID || !validSHA256Hex(report.SHA256) {
		t.Fatal("closed bill export failed", report, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"hello", "private-response", provider.URL} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("archive contains model payload or endpoint")
		}
	}
	for name, mode := range map[string]os.FileMode{filepath.Dir(path): 0o700, path: 0o600} {
		if info, err := os.Stat(name); err != nil || info.Mode().Perm() != mode {
			t.Fatal("archive storage permissions", name, err)
		}
	}
	if _, err := RunInferenceBillAdmin(ctx, config, export); err == nil {
		t.Fatal("duplicate export replaced archive")
	}
	if current, _ := os.ReadFile(path); !bytes.Equal(current, data) {
		t.Fatal("existing archive changed")
	}
	verify := InferenceBillAdminRequest{Operation: "bill-verify", Path: path}
	verified, err := RunInferenceBillAdmin(ctx, EgressServiceConfig{}, verify)
	if err != nil || !verified.Verified || verified.SHA256 != report.SHA256 {
		t.Fatal("offline archive verification failed", verified, err)
	}
	// An internally valid but different closed record must not remove the live
	// bill. The egress service compares the exact archived digest itself.
	var archive inferenceBillArchive
	var record inferenceTaskRecord
	if json.Unmarshal(data, &archive) != nil || json.Unmarshal(archive.Record, &record) != nil {
		t.Fatal("export shape")
	}
	record.MaxInvocations++
	archive.Record, _ = json.Marshal(record)
	archive.SHA256 = inferenceDigest(archive.Record)
	changed := filepath.Join(filepath.Dir(path), "different.json")
	if err := saveInferenceArchive(changed, archive); err != nil {
		t.Fatal(err)
	}
	if _, err := RunInferenceBillAdmin(ctx, config, InferenceBillAdminRequest{Operation: "bill-retire", Path: changed}); err == nil {
		t.Fatal("different valid archive retired the original record")
	}
	if _, err := s.inference.ledger.bill(binding.Tenant, binding.TaskID); err != nil {
		t.Fatal("failed retirement lost original bill", err)
	}
	// Recover an interrupted link publication: the archive can have a remaining
	// temporary hard link, and durable verification must still work.
	leftover := filepath.Join(filepath.Dir(path), ".interrupted-export")
	if err := os.Link(path, leftover); err != nil {
		t.Fatal(err)
	}
	retired, err := RunInferenceBillAdmin(ctx, config, InferenceBillAdminRequest{Operation: "bill-retire", Path: path})
	if err != nil || !retired.Retired || retired.SHA256 != report.SHA256 {
		t.Fatal("exact durable archive did not retire", retired, err)
	}
	if _, err := s.inference.ledger.bill(binding.Tenant, binding.TaskID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired bill remained in live ledger", err)
	}
	if after, err := RunInferenceBillAdmin(ctx, EgressServiceConfig{}, verify); err != nil || !after.Verified || calls.Load() != 1 {
		t.Fatal("retirement lost archive or replayed a model", after, err)
	}
}

func TestInferenceAdminRejectsUntrustedArchivesAndDestinations(t *testing.T) {
	requireGuestProxyRoot(t)
	record := inferenceTaskRecord{Version: 1, Binding: inferenceTestBinding(), MaxInvocations: 1, Closed: true, Invocations: []InferenceInvocationReceipt{}}
	canonical, _ := json.Marshal(record)
	valid := inferenceBillArchive{Protocol: "osv-sandbox-inference-archive/v1", Record: canonical, SHA256: inferenceDigest(canonical)}
	for _, name := range []string{"digest", "open", "unknown-field", "noncanonical", "duplicate-field", "accounting"} {
		t.Run(name, func(t *testing.T) {
			archive := valid
			archive.Record = append(json.RawMessage(nil), canonical...)
			switch name {
			case "digest":
				archive.SHA256 = strings.Repeat("0", 64)
			case "open":
				archive.Record = bytes.Replace(archive.Record, []byte(`"closed":true`), []byte(`"closed":false`), 1)
			case "unknown-field":
				archive.Record = append([]byte(`{"unexpected":true,`), archive.Record[1:]...)
			case "noncanonical":
				archive.Record = append([]byte(" "), archive.Record...)
			case "duplicate-field":
				archive.Record = append([]byte(`{"closed":true,`), archive.Record[1:]...)
			case "accounting":
				bad := record
				bad.Invocations = []InferenceInvocationReceipt{{ID: inferenceRequest(1).ID, Endpoint: "model", State: "succeeded", SettledUnits: 1}}
				archive.Record, _ = json.Marshal(bad)
			}
			if name != "digest" {
				archive.SHA256 = inferenceDigest(archive.Record)
			}
			if _, err := validateInferenceArchive(archive); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
	base := t.TempDir()
	archivePath := filepath.Join(base, "bill.json")
	if err := saveInferenceArchive(archivePath, valid); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(base, "link.json")
	if err := os.Symlink(archivePath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readInferenceArchive(symlink, true); err == nil {
		t.Fatal("symbolic link archive accepted")
	}
	if err := saveInferenceArchive(symlink, valid); err == nil {
		t.Fatal("symbolic link destination replaced")
	}
	if err := os.Chmod(archivePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readInferenceArchive(archivePath, true); err == nil {
		t.Fatal("public archive accepted")
	}
	if _, _, err := readInferenceArchive("relative/bill.json", true); err == nil {
		t.Fatal("relative archive accepted")
	}
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := saveInferenceArchive(filepath.Join(base, "new.json"), valid); err == nil {
		t.Fatal("shared writable archive parent accepted")
	}
}
