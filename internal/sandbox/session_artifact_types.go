package sandbox

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	sessionArtifactLimit     = 2
	sessionArtifactBytes     = 32 << 20
	sessionArtifactEntries   = 1024
	sessionArtifactPathBytes = 64 << 10
	sessionArtifactDepth     = 16
	sessionArtifactReadBytes = 512 << 10
	artifactDataBytes        = 64 << 10
	artifactFrameBytes       = 128 << 10
	artifactFrameCount       = 4096
	artifactManifestName     = ".osv-artifact-manifest.json"
	linuxArtifactProtocol    = "fc-artifact/v1"
	linuxArtifactPrefix      = "FC_ARTIFACT_EVENT "
)

var (
	ErrArtifactsUnsupported = errors.New("workspace artifacts are not supported by the selected template")
	ErrArtifactLimit        = errors.New("session artifact limit reached; delete an artifact before exporting another")
	ErrArtifactTooLarge     = errors.New("workspace artifact exceeds archive, entry, path or depth limits")
	ErrArtifactNotFound     = errors.New("session artifact not found")
	ErrArtifactRange        = errors.New("invalid artifact byte range")
	ErrArtifactChanged      = errors.New("workspace changed during artifact export")
	errArtifactProtocol     = errors.New("invalid workspace artifact protocol")
)

type SessionArtifactCreateRequest struct {
	Path string `json:"path"`
}

func (r SessionArtifactCreateRequest) Validate() error {
	if !utf8.ValidString(r.Path) {
		return ErrInvalidFilePath
	}
	return (SessionFileRequest{Action: "info", Path: r.Path}).Validate()
}

type SessionArtifactReadRequest struct {
	Offset int64 `json:"offset"`
	Length int   `json:"length"`
}

func (r SessionArtifactReadRequest) Validate() error {
	if r.Offset < 0 || r.Offset > sessionArtifactBytes || r.Length < 1 || r.Length > sessionArtifactReadBytes {
		return ErrArtifactRange
	}
	return nil
}

type SessionArtifactInfo struct {
	ID           string `json:"id"`
	SessionID    string `json:"session_id"`
	Path         string `json:"path"`
	SourceKind   string `json:"source_kind"`
	Format       string `json:"format"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Entries      int    `json:"entries"`
	Files        int    `json:"files"`
	PayloadBytes int64  `json:"payload_bytes"`
}

func (v SessionArtifactInfo) valid() bool {
	if !validSessionID(v.ID) || !validSessionID(v.SessionID) ||
		(SessionArtifactCreateRequest{Path: v.Path}).Validate() != nil || v.Format != "tar" ||
		(v.SourceKind != "file" && v.SourceKind != "directory") || v.Path == "/workspace" && v.SourceKind != "directory" ||
		v.Size < 2048 || v.Size > sessionArtifactBytes || v.Size%512 != 0 || !validSHA256Hex(v.SHA256) ||
		v.Entries < 0 || v.Entries > sessionArtifactEntries || v.Files < 0 || v.Files > v.Entries ||
		v.PayloadBytes < 0 || v.PayloadBytes > v.Size {
		return false
	}
	return (v.SourceKind != "file" || v.Entries == 1 && v.Files == 1) &&
		(v.Files != 0 || v.PayloadBytes == 0)
}

func (v SessionArtifactInfo) ValidateFor(sessionID, sourcePath string) error {
	if !v.valid() || v.SessionID != sessionID || v.Path != sourcePath {
		return errors.New("invalid artifact metadata binding or limits")
	}
	return nil
}

type SessionArtifactChunk struct {
	ID            string `json:"id"`
	SessionID     string `json:"session_id"`
	Offset        int64  `json:"offset"`
	TotalSize     int64  `json:"total_size"`
	DataBase64    string `json:"data_base64"`
	DataSHA256    string `json:"data_sha256"`
	ArchiveSHA256 string `json:"archive_sha256"`
	EOF           bool   `json:"eof"`
}

func (v SessionArtifactChunk) valid(sessionID, artifactID string, request SessionArtifactReadRequest) bool {
	if request.Validate() != nil || v.ID != artifactID || v.SessionID != sessionID ||
		!validSessionID(v.ID) || !validSessionID(v.SessionID) || v.Offset != request.Offset ||
		v.TotalSize < 2048 || v.TotalSize > sessionArtifactBytes || v.TotalSize%512 != 0 ||
		v.Offset > v.TotalSize || !validSHA256Hex(v.DataSHA256) || !validSHA256Hex(v.ArchiveSHA256) ||
		len(v.DataBase64) > base64.StdEncoding.EncodedLen(sessionArtifactReadBytes) {
		return false
	}
	data, err := base64.StdEncoding.Strict().DecodeString(v.DataBase64)
	if err != nil || base64.StdEncoding.EncodeToString(data) != v.DataBase64 ||
		int64(len(data)) != min(int64(request.Length), v.TotalSize-v.Offset) || v.EOF != (v.Offset+int64(len(data)) == v.TotalSize) {
		return false
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]) == v.DataSHA256
}

func (v SessionArtifactChunk) ValidateFor(sessionID, artifactID string, request SessionArtifactReadRequest) error {
	if !v.valid(sessionID, artifactID, request) {
		return errors.New("invalid artifact chunk binding, range or digest")
	}
	return nil
}

func validArtifactMemberPath(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsRune(value, '\\') {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > sessionArtifactDepth || len(parts[0]) >= 2 &&
		((parts[0][0] >= 'a' && parts[0][0] <= 'z') || (parts[0][0] >= 'A' && parts[0][0] <= 'Z')) && parts[0][1] == ':' {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
		for _, ch := range part {
			if unicode.IsControl(ch) {
				return false
			}
		}
	}
	return value != artifactManifestName
}
