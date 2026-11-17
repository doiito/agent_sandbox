package sandbox

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

type linuxArtifactRequest struct {
	Protocol   string             `json:"protocol"`
	SessionID  string             `json:"session_id"`
	ArtifactID string             `json:"artifact_id"`
	Nonce      string             `json:"nonce"`
	Path       string             `json:"path"`
	Binding    *linuxGuestBinding `json:"binding,omitempty"`
}

type linuxArtifactEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

type linuxArtifactTotals struct {
	Entries      int   `json:"entries"`
	Files        int   `json:"files"`
	PayloadBytes int64 `json:"payload_bytes"`
}

type linuxArtifactFrame struct {
	Protocol   string               `json:"protocol"`
	SessionID  string               `json:"session_id"`
	ArtifactID string               `json:"artifact_id"`
	Nonce      string               `json:"nonce"`
	Binding    *linuxGuestBinding   `json:"binding,omitempty"`
	Sequence   *int                 `json:"sequence"`
	Kind       string               `json:"kind"`
	Path       string               `json:"path,omitempty"`
	SourceKind string               `json:"source_kind,omitempty"`
	Entry      *linuxArtifactEntry  `json:"entry,omitempty"`
	Offset     *int64               `json:"offset,omitempty"`
	DataBase64 string               `json:"data_base64,omitempty"`
	Totals     *linuxArtifactTotals `json:"totals,omitempty"`
	Code       string               `json:"code,omitempty"`
}

func (f linuxArtifactFrame) shape(entry, offset, totals bool) bool {
	return (f.Entry != nil) == entry && (f.Offset != nil) == offset && (f.Totals != nil) == totals
}

type artifactManifestEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
	offset int64
}

type artifactBlob struct {
	file *os.File
	info SessionArtifactInfo
}

func (b *artifactBlob) Close() error {
	if b == nil || b.file == nil {
		return nil
	}
	return b.file.Close()
}

// The private workdir belongs to the launcher. Files never have a published
// pathname, including while incomplete or when their owner crashes.
func newArtifactSpool(workdir string) (*os.File, error) {
	file, err := os.CreateTemp(workdir, ".artifact-")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

type artifactFrameReader struct {
	reader  *bufio.Reader
	request linuxArtifactRequest
	next    int
}

func (r *artifactFrameReader) read(ctx context.Context) (linuxArtifactFrame, error) {
	if err := ctx.Err(); err != nil {
		return linuxArtifactFrame{}, err
	}
	if r.next >= artifactFrameCount {
		return linuxArtifactFrame{}, errArtifactProtocol
	}
	raw, err := readLauncherFrame(r.reader, artifactFrameBytes)
	if err != nil || !strings.HasPrefix(string(raw), linuxArtifactPrefix) {
		if ctx.Err() != nil {
			return linuxArtifactFrame{}, ctx.Err()
		}
		return linuxArtifactFrame{}, errArtifactProtocol
	}
	var frame linuxArtifactFrame
	if decodeLauncherFrame(raw[len(linuxArtifactPrefix):], &frame) != nil ||
		frame.Protocol != linuxArtifactProtocol || frame.SessionID != r.request.SessionID ||
		frame.ArtifactID != r.request.ArtifactID || frame.Nonce != r.request.Nonce || frame.Sequence == nil || *frame.Sequence != r.next ||
		(frame.Binding == nil) != (r.request.Binding == nil) || frame.Binding != nil && *frame.Binding != *r.request.Binding {
		return linuxArtifactFrame{}, errArtifactProtocol
	}
	r.next++
	return frame, nil
}

func (r *artifactFrameReader) eof(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err := r.reader.ReadByte(); err != io.EOF {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errArtifactProtocol
	}
	return ctx.Err()
}

func artifactEndError(code string) error {
	switch code {
	case "not_found":
		return ErrFileNotFound
	case "denied":
		return ErrFileDenied
	case "too_large", "operation_limit":
		return ErrArtifactTooLarge
	case "conflict":
		return ErrArtifactChanged
	case "invalid_path":
		return ErrInvalidFilePath
	case "io_error":
		return ErrFileIO
	case "unsupported":
		return ErrArtifactsUnsupported
	case "expired":
		return ErrSessionClosed
	default:
		return errArtifactProtocol
	}
}

func (r *artifactFrameReader) failure(ctx context.Context, frame linuxArtifactFrame) error {
	if !frame.shape(false, false, false) || frame.Path != "" || frame.SourceKind != "" || frame.DataBase64 != "" {
		return errArtifactProtocol
	}
	if err := r.eof(ctx); err != nil {
		return err
	}
	return artifactEndError(frame.Code)
}

// buildSessionArtifact owns the stream and returns only a complete, hashed tar.
// The guest supplies filesystem records; archive headers are produced here.
func buildSessionArtifact(ctx context.Context, workdir string, request linuxArtifactRequest, stream io.ReadCloser) (*artifactBlob, error) {
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	if (SessionArtifactCreateRequest{Path: request.Path}).Validate() != nil ||
		!validSessionID(request.SessionID) || !validSessionID(request.ArtifactID) || !validSHA256Hex(request.Nonce) ||
		request.Protocol != linuxArtifactProtocol || request.Binding != nil && (!request.Binding.valid() || request.Binding.SessionID != request.SessionID) {
		return nil, errArtifactProtocol
	}
	reader := artifactFrameReader{reader: bufio.NewReaderSize(stream, 4096), request: request}
	ready, err := reader.read(ctx)
	if err != nil {
		return nil, err
	}
	if ready.Kind == "end" && ready.Code != "" {
		return nil, reader.failure(ctx, ready)
	}
	if ready.Kind != "ready" || !ready.shape(false, false, false) || ready.Path != request.Path ||
		(ready.SourceKind != "file" && ready.SourceKind != "directory") ||
		request.Path == "/workspace" && ready.SourceKind != "directory" || ready.Code != "" || ready.DataBase64 != "" {
		return nil, errArtifactProtocol
	}
	content, err := newArtifactSpool(workdir)
	if err != nil {
		return nil, err
	}
	defer content.Close()
	stopContent := context.AfterFunc(ctx, func() { _ = content.Close() })
	defer stopContent()
	entries := make([]artifactManifestEntry, 0)
	types := make(map[string]string)
	var total, received int64
	var fileCount, namesSize int
	var active *artifactManifestEntry
	var digest hash.Hash
	for {
		frame, err := reader.read(ctx)
		if err != nil {
			return nil, err
		}
		if frame.Kind == "end" && frame.Code != "" {
			return nil, reader.failure(ctx, frame)
		}
		if frame.Path != "" || frame.SourceKind != "" || frame.Code != "" {
			return nil, errArtifactProtocol
		}
		switch frame.Kind {
		case "entry":
			if active != nil || !frame.shape(true, false, false) || frame.DataBase64 != "" {
				return nil, errArtifactProtocol
			}
			e := *frame.Entry
			if len(entries) >= sessionArtifactEntries || namesSize+len(e.Path) > sessionArtifactPathBytes {
				return nil, ErrArtifactTooLarge
			}
			if !validArtifactMemberPath(e.Path) || len(entries) > 0 && e.Path <= entries[len(entries)-1].Path ||
				e.Size < 0 || e.Mode & ^uint32(0o177777) != 0 {
				return nil, errArtifactProtocol
			}
			if ready.SourceKind == "file" && (len(entries) != 0 || e.Path != path.Base(request.Path) || e.Type != "file") {
				return nil, errArtifactProtocol
			}
			for parent := path.Dir(e.Path); parent != "."; parent = path.Dir(parent) {
				if types[parent] != "directory" {
					return nil, errArtifactProtocol
				}
			}
			mode := int64(0o644)
			switch e.Type {
			case "directory":
				if e.Size != 0 || e.Mode&0o170000 != 0o040000 {
					return nil, errArtifactProtocol
				}
				mode = 0o755
			case "file":
				if e.Mode&0o170000 != 0o100000 {
					return nil, errArtifactProtocol
				}
				if e.Size > sessionArtifactBytes-total {
					return nil, ErrArtifactTooLarge
				}
				if e.Mode&0o111 != 0 {
					mode = 0o755
				}
				fileCount++
			default:
				return nil, errArtifactProtocol
			}
			types[e.Path] = e.Type
			namesSize += len(e.Path)
			entries = append(entries, artifactManifestEntry{Path: e.Path, Type: e.Type, Size: e.Size, Mode: mode, offset: total})
			if e.Type == "file" {
				active = &entries[len(entries)-1]
				received, digest = 0, sha256.New()
			}
		case "data":
			if active == nil || !frame.shape(false, true, false) || *frame.Offset != received ||
				frame.DataBase64 == "" || len(frame.DataBase64) > base64.StdEncoding.EncodedLen(artifactDataBytes) {
				return nil, errArtifactProtocol
			}
			data, err := base64.StdEncoding.Strict().DecodeString(frame.DataBase64)
			expected := min(int64(artifactDataBytes), active.Size-received)
			if err != nil || len(data) == 0 || int64(len(data)) != expected || base64.StdEncoding.EncodeToString(data) != frame.DataBase64 {
				return nil, errArtifactProtocol
			}
			if n, err := content.Write(data); err != nil || n != len(data) {
				if err == nil {
					err = io.ErrShortWrite
				}
				return nil, err
			}
			_, _ = digest.Write(data)
			received += int64(len(data))
			total += int64(len(data))
		case "file_end":
			if active == nil || !frame.shape(false, true, false) || *frame.Offset != active.Size || received != active.Size || frame.DataBase64 != "" {
				return nil, errArtifactProtocol
			}
			active.SHA256 = hex.EncodeToString(digest.Sum(nil))
			active, digest = nil, nil
		case "end":
			if active != nil || !frame.shape(false, false, true) || frame.DataBase64 != "" ||
				frame.Totals.Entries != len(entries) || frame.Totals.Files != fileCount || frame.Totals.PayloadBytes != total ||
				ready.SourceKind == "file" && (len(entries) != 1 || fileCount != 1) {
				return nil, errArtifactProtocol
			}
			if err := reader.eof(ctx); err != nil {
				return nil, err
			}
			return createArtifactTar(ctx, workdir, request, ready.SourceKind, entries, content, fileCount, total)
		default:
			return nil, errArtifactProtocol
		}
	}
}

type artifactLimitedWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *artifactLimitedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > sessionArtifactBytes-w.bytes {
		return 0, ErrArtifactTooLarge
	}
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	return n, err
}

func createArtifactTar(ctx context.Context, workdir string, request linuxArtifactRequest, sourceKind string, entries []artifactManifestEntry, content *os.File, files int, payloadBytes int64) (*artifactBlob, error) {
	manifest, err := json.Marshal(struct {
		Schema     string                  `json:"schema"`
		SourcePath string                  `json:"source_path"`
		SourceKind string                  `json:"source_kind"`
		Entries    []artifactManifestEntry `json:"entries"`
	}{"osv-workspace-artifact/v1", request.Path, sourceKind, entries})
	if err != nil {
		return nil, err
	}
	manifest = append(manifest, '\n')
	file, err := newArtifactSpool(workdir)
	if err != nil {
		return nil, err
	}
	success := false
	stopFile := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer stopFile()
	defer func() {
		if !success {
			_ = file.Close()
		}
	}()
	digest := sha256.New()
	limited := &artifactLimitedWriter{writer: io.MultiWriter(file, digest)}
	writer := tar.NewWriter(limited)
	header := func(name string, mode, size int64, directory bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		kind := byte(tar.TypeReg)
		if directory {
			kind, name = tar.TypeDir, name+"/"
		}
		return writer.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Mode: mode, Size: size,
			ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX})
	}
	if err = header(artifactManifestName, 0o644, int64(len(manifest)), false); err != nil {
		return nil, err
	}
	if _, err = writer.Write(manifest); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err = header(entry.Path, entry.Mode, entry.Size, entry.Type == "directory"); err != nil {
			return nil, err
		}
		if entry.Type == "file" {
			if _, err = io.CopyN(writer, io.NewSectionReader(content, entry.offset, entry.Size), entry.Size); err != nil {
				return nil, err
			}
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	info := SessionArtifactInfo{ID: request.ArtifactID, SessionID: request.SessionID, Path: request.Path,
		SourceKind: sourceKind, Format: "tar", Size: limited.bytes, SHA256: hex.EncodeToString(digest.Sum(nil)),
		Entries: len(entries), Files: files, PayloadBytes: payloadBytes}
	if !info.valid() {
		return nil, errors.New("invalid completed artifact metadata")
	}
	if !stopFile() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	success = true
	return &artifactBlob{file: file, info: info}, nil
}
