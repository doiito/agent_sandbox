package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func artifactTestRequest() linuxArtifactRequest {
	return linuxArtifactRequest{Protocol: linuxArtifactProtocol, SessionID: "0123456789abcdef01234567",
		ArtifactID: "abcdef0123456789abcdef01", Nonce: strings.Repeat("c", 64), Path: "/workspace"}
}

func artifactTestFrames(request linuxArtifactRequest, source string, entries []linuxArtifactEntry, content map[string][]byte) []linuxArtifactFrame {
	frames := []linuxArtifactFrame{{Kind: "ready", Path: request.Path, SourceKind: source}}
	totals := linuxArtifactTotals{Entries: len(entries)}
	for _, entry := range entries {
		e := entry
		frames = append(frames, linuxArtifactFrame{Kind: "entry", Entry: &e})
		if e.Type != "file" {
			continue
		}
		totals.Files++
		data := content[e.Path]
		totals.PayloadBytes += int64(len(data))
		for offset := 0; offset < len(data); offset += artifactDataBytes {
			position := int64(offset)
			chunk := data[offset:min(offset+artifactDataBytes, len(data))]
			frames = append(frames, linuxArtifactFrame{Kind: "data", Offset: &position, DataBase64: base64.StdEncoding.EncodeToString(chunk)})
		}
		position := int64(len(data))
		frames = append(frames, linuxArtifactFrame{Kind: "file_end", Offset: &position})
	}
	return append(frames, linuxArtifactFrame{Kind: "end", Totals: &totals})
}

func artifactTestWire(request linuxArtifactRequest, frames []linuxArtifactFrame) []byte {
	var wire bytes.Buffer
	for i, f := range frames {
		sequence := i
		f.Protocol, f.SessionID, f.ArtifactID, f.Nonce, f.Binding, f.Sequence = request.Protocol, request.SessionID, request.ArtifactID, request.Nonce, request.Binding, &sequence
		payload, err := json.Marshal(f)
		if err != nil {
			panic(err)
		}
		wire.WriteString(linuxArtifactPrefix)
		wire.Write(payload)
		wire.WriteByte('\n')
	}
	return wire.Bytes()
}

func artifactTestBuild(t *testing.T, workdir string, request linuxArtifactRequest, wire []byte) *artifactBlob {
	t.Helper()
	blob, err := buildSessionArtifact(context.Background(), workdir, request, io.NopCloser(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blob.Close() })
	return blob
}

func artifactTestSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestSessionArtifactTarRoundTripLargeBinaryAndManifest(t *testing.T) {
	request := artifactTestRequest()
	request.Binding = &linuxGuestBinding{SessionID: request.SessionID, Nonce: strings.Repeat("d", 64)}
	large := bytes.Repeat([]byte{0, 255, 128, 10, 13, 42, 1}, 180_001)
	entries := []linuxArtifactEntry{
		{Path: "bin", Type: "directory", Mode: 0o40700},
		{Path: "bin/工具", Type: "file", Mode: 0o104777, Size: int64(len(large))},
		{Path: "empty", Type: "directory", Mode: 0o40777},
		{Path: "zero", Type: "file", Mode: 0o100600},
	}
	wire := artifactTestWire(request, artifactTestFrames(request, "directory", entries, map[string][]byte{"bin/工具": large}))
	dir := t.TempDir()
	blob := artifactTestBuild(t, dir, request, wire)
	if !blob.info.valid() || blob.info.Entries != 4 || blob.info.Files != 2 || blob.info.PayloadBytes != int64(len(large)) {
		t.Fatal(blob.info)
	}
	archive, err := io.ReadAll(io.NewSectionReader(blob.file, 0, blob.info.Size))
	if err != nil || artifactTestSHA(archive) != blob.info.SHA256 {
		t.Fatal("archive digest mismatch", err)
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	header, err := reader.Next()
	if err != nil || header.Name != artifactManifestName || header.Mode != 0o644 {
		t.Fatal(header, err)
	}
	manifest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Schema     string                  `json:"schema"`
		SourcePath string                  `json:"source_path"`
		Entries    []artifactManifestEntry `json:"entries"`
	}
	if json.Unmarshal(manifest, &document) != nil || document.Schema != "osv-workspace-artifact/v1" ||
		document.SourcePath != "/workspace" || len(document.Entries) != 4 ||
		document.Entries[1].SHA256 != artifactTestSHA(large) || document.Entries[3].SHA256 != artifactTestSHA(nil) {
		t.Fatal("invalid manifest", string(manifest))
	}
	for i, want := range []string{"bin/", "bin/工具", "empty/", "zero"} {
		header, err = reader.Next()
		if err != nil || header.Name != want || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0)) ||
			header.Mode & ^int64(0o777) != 0 || header.Linkname != "" || len(header.Xattrs) != 0 {
			t.Fatal("unexpected archive member", header, err)
		}
		data, err := io.ReadAll(reader)
		if err != nil || i == 1 && (!bytes.Equal(data, large) || header.Mode != 0o755) || i != 1 && len(data) != 0 {
			t.Fatal("archive payload mismatch", want, err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("unexpected trailing member", err)
	}
	again := artifactTestBuild(t, dir, request, wire)
	if again.info.SHA256 != blob.info.SHA256 {
		t.Fatal("non deterministic archive")
	}
	if names, err := os.ReadDir(dir); err != nil || len(names) != 0 {
		t.Fatal("published spool pathname", names, err)
	}
}

func TestSessionArtifactEmptyDirectoryAndSingleFile(t *testing.T) {
	for _, source := range []string{"directory", "file"} {
		t.Run(source, func(t *testing.T) {
			request := artifactTestRequest()
			var entries []linuxArtifactEntry
			if source == "file" {
				request.Path = "/workspace/报告.bin"
				entries = []linuxArtifactEntry{{Path: "报告.bin", Type: "file", Mode: 0o100644}}
			}
			blob := artifactTestBuild(t, t.TempDir(), request, artifactTestWire(request, artifactTestFrames(request, source, entries, nil)))
			if !blob.info.valid() || blob.info.SourceKind != source {
				t.Fatal(blob.info)
			}
		})
	}
}

func TestSessionArtifactRejectsUnsafeAndIncompleteStreams(t *testing.T) {
	request := artifactTestRequest()
	valid := func() []linuxArtifactFrame {
		return artifactTestFrames(request, "directory", []linuxArtifactEntry{{Path: "ok", Type: "file", Mode: 0o100644, Size: 3}}, map[string][]byte{"ok": {0, 255, 1}})
	}
	mutations := map[string]func([]linuxArtifactFrame) []linuxArtifactFrame{
		"escape":                  func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = "../secret"; return f },
		"absolute":                func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = "/etc/passwd"; return f },
		"drive":                   func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = "C:/secret"; return f },
		"backslash":               func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = "a\\b"; return f },
		"reserved":                func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = artifactManifestName; return f },
		"parent_missing":          func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Path = "dir/ok"; return f },
		"symlink":                 func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Mode = 0o120777; return f },
		"hardlink_kind":           func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Type = "hardlink"; return f },
		"fifo":                    func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Mode = 0o10644; return f },
		"declared_size":           func(f []linuxArtifactFrame) []linuxArtifactFrame { f[1].Entry.Size++; return f },
		"offset":                  func(f []linuxArtifactFrame) []linuxArtifactFrame { *f[2].Offset = 1; return f },
		"base64":                  func(f []linuxArtifactFrame) []linuxArtifactFrame { f[2].DataBase64 = "AA/="; return f },
		"foreign_fields":          func(f []linuxArtifactFrame) []linuxArtifactFrame { f[2].Path = "/workspace"; return f },
		"false_totals":            func(f []linuxArtifactFrame) []linuxArtifactFrame { f[len(f)-1].Totals.Files++; return f },
		"missing_file_end":        func(f []linuxArtifactFrame) []linuxArtifactFrame { return append(f[:3], f[4:]...) },
		"missing_terminal":        func(f []linuxArtifactFrame) []linuxArtifactFrame { return f[:len(f)-1] },
		"duplicate_entry":         func(f []linuxArtifactFrame) []linuxArtifactFrame { return append(f[:4], append(f[1:4], f[4:]...)...) },
		"false_success_with_code": func(f []linuxArtifactFrame) []linuxArtifactFrame { f[len(f)-1].Code = "io_error"; return f },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			blob, err := buildSessionArtifact(context.Background(), dir, request, io.NopCloser(bytes.NewReader(artifactTestWire(request, mutate(valid())))))
			if err == nil || blob != nil {
				t.Fatal("accepted malformed transcript", err)
			}
			if names, err := os.ReadDir(dir); err != nil || len(names) != 0 {
				t.Fatal("leaked spool", names, err)
			}
		})
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"session": func(b []byte) []byte {
			return bytes.Replace(b, []byte(request.SessionID), []byte(strings.Repeat("e", 24)), 1)
		},
		"nonce": func(b []byte) []byte {
			return bytes.Replace(b, []byte(request.Nonce), []byte(strings.Repeat("f", 64)), 1)
		},
		"sequence": func(b []byte) []byte { return bytes.Replace(b, []byte(`"sequence":1`), []byte(`"sequence":0`), 1) },
		"unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"kind":"ready"`), []byte(`"unknown":true,"kind":"ready"`), 1)
		},
		"missing_sequence": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"sequence":0,`), nil, 1)
		},
		"null_sequence": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"sequence":0`), []byte(`"sequence":null`), 1)
		},
		"trailing":  func(b []byte) []byte { return append(b, 'X') },
		"truncated": func(b []byte) []byte { return b[:len(b)-2] },
		"oversized": func(b []byte) []byte { return []byte(strings.Repeat("x", artifactFrameBytes+1) + "\n") },
	} {
		t.Run(name, func(t *testing.T) {
			blob, err := buildSessionArtifact(context.Background(), t.TempDir(), request, io.NopCloser(bytes.NewReader(mutate(artifactTestWire(request, valid())))))
			if err == nil || blob != nil {
				t.Fatal("accepted malformed wire", err)
			}
		})
	}
}

func TestSessionArtifactLimitsIncludeTarOverhead(t *testing.T) {
	request := artifactTestRequest()
	dir := t.TempDir()
	content, err := newArtifactSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	if err := content.Truncate(sessionArtifactBytes); err != nil {
		t.Fatal(err)
	}
	entry := artifactManifestEntry{Path: "large", Type: "file", Mode: 0o644, Size: sessionArtifactBytes, SHA256: strings.Repeat("a", 64)}
	blob, err := createArtifactTar(context.Background(), dir, request, "directory", []artifactManifestEntry{entry}, content, 1, sessionArtifactBytes)
	if !errors.Is(err, ErrArtifactTooLarge) || blob != nil {
		t.Fatal("archive overhead was not charged", err)
	}
	for _, path := range []string{strings.Repeat("a/", sessionArtifactDepth) + "file", strings.Repeat("a", 256), "nul\x00", "new\nline", string([]byte{255})} {
		if validArtifactMemberPath(path) {
			t.Fatal("unsafe member accepted", path)
		}
	}
	entries := make([]linuxArtifactEntry, sessionArtifactEntries+1)
	for i := range entries {
		// Fixed width names keep the transcript in bytewise lexical order.
		entries[i] = linuxArtifactEntry{Path: "d" + hex.EncodeToString([]byte{byte(i >> 8), byte(i)}), Type: "directory", Mode: 0o40755}
	}
	blob, err = buildSessionArtifact(context.Background(), dir, request, io.NopCloser(bytes.NewReader(artifactTestWire(request, artifactTestFrames(request, "directory", entries, nil)))))
	if !errors.Is(err, ErrArtifactTooLarge) || blob != nil {
		t.Fatal("entry limit not enforced", err)
	}
}

func TestSessionArtifactCancellationAndGuestFailure(t *testing.T) {
	request := artifactTestRequest()
	for _, code := range []string{"not_found", "denied", "conflict", "too_large", "expired", "unsupported", "io_error"} {
		wire := artifactTestWire(request, []linuxArtifactFrame{{Kind: "end", Code: code}})
		blob, err := buildSessionArtifact(context.Background(), t.TempDir(), request, io.NopCloser(bytes.NewReader(wire)))
		if !errors.Is(err, artifactEndError(code)) || blob != nil {
			t.Fatal(code, err)
		}
	}
	for _, atEOF := range []bool{false, true} {
		t.Run(map[bool]string{false: "first_frame", true: "after_success"}[atEOF], func(t *testing.T) {
			reader, writer := io.Pipe()
			defer writer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := buildSessionArtifact(ctx, t.TempDir(), request, reader); done <- err }()
			if atEOF {
				_, err := writer.Write(artifactTestWire(request, artifactTestFrames(request, "directory", nil, nil)))
				if err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation did not unblock guest stream")
			}
		})
	}
}
