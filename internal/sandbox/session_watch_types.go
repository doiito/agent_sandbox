package sandbox

import (
	"errors"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	sessionWatchActiveLimit    = 4
	sessionWatchHistoryLimit   = 16
	sessionWatchEventLimit     = 256
	sessionWatchByteLimit      = 64 * 1024
	sessionWatchPageLimit      = 64
	sessionWatchDirectoryLimit = 128
	sessionWatchFrameLimit     = 32 * 1024
)

var ErrWatchUnsupported = errors.New("directory watching requires a signed Linux workspace-watch-v1 template")
var ErrWatchNotFound = errors.New("directory watcher not found")
var ErrWatchCursor = errors.New("directory watcher cursor is invalid or has already been acknowledged")

type SessionWatchRequest struct {
	Path         string `json:"path"`
	Recursive    bool   `json:"recursive,omitempty"`
	IncludeEntry bool   `json:"include_entry,omitempty"`
	TimeoutMS    int    `json:"timeout_ms,omitempty"`
}

func (r SessionWatchRequest) Validate() error {
	if !utf8.ValidString(r.Path) {
		return ErrInvalidFilePath
	}
	if err := (SessionFileRequest{Action: "info", Path: r.Path}).Validate(); err != nil {
		return err
	}
	if r.TimeoutMS < 0 || r.TimeoutMS > sessionMaxLifetimeMS {
		return errors.New("watch timeout_ms must be in [0,600000]")
	}
	return nil
}

type SessionWatchInfo struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Path         string    `json:"path"`
	Recursive    bool      `json:"recursive"`
	IncludeEntry bool      `json:"include_entry"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"created_at"`
	ErrorCode    string    `json:"error_code,omitempty"`
}

type SessionWatchEvent struct {
	Sequence int              `json:"sequence"`
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	Entry    *SessionFileInfo `json:"entry,omitempty"`
}

type SessionWatchPage struct {
	Info         SessionWatchInfo    `json:"info"`
	Events       []SessionWatchEvent `json:"events"`
	NextSequence int                 `json:"next_sequence"`
	Complete     bool                `json:"complete"`
}

func (e SessionWatchEvent) validate(request SessionWatchRequest, previous int) error {
	if e.Sequence != previous+1 || e.Sequence <= 0 || e.Sequence > 1<<31-1 {
		return errors.New("invalid watch event sequence")
	}
	switch e.Type {
	case "create", "write", "chmod", "rename", "remove":
	default:
		return errors.New("invalid watch event type")
	}
	full := request.Path
	if e.Name == "." {
		if e.Type != "chmod" {
			return ErrInvalidFilePath
		}
	} else {
		if !request.Recursive && strings.ContainsRune(e.Name, '/') || e.Name == "" || strings.HasPrefix(e.Name, "/") || !utf8.ValidString(e.Name) {
			return ErrInvalidFilePath
		}
		full += "/" + e.Name
		if err := (SessionFileRequest{Action: "info", Path: full}).Validate(); err != nil {
			return err
		}
	}
	if e.Entry != nil && (!request.IncludeEntry || e.Type == "remove" || e.Type == "rename" || !validSessionFileInfo(*e.Entry, full, path.Base(full))) {
		return errors.New("invalid watch event entry metadata")
	}
	return nil
}

func validWatchEndCode(code string) bool {
	switch code {
	case "closed", "expired", "unsupported", "invalid_binding", "overflow", "operation_limit", "directory_changed", "invalid_name", "topology_changed", "io_error", "not_found", "denied", "too_large", "conflict":
		return true
	}
	return false
}
