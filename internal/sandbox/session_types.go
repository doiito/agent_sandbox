package sandbox

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	sessionMinTTLMS               = 1_000
	sessionMaxTTLMS               = 300_000
	sessionFileLimit              = 512 * 1024
	sessionFileListLimit          = 256
	sessionFileListNameBytesLimit = 64 * 1024
)

var ErrSessionClosed = errors.New("sandbox session is closed")
var ErrInvalidFilePath = errors.New("invalid workspace file path")
var ErrFileNotFound = errors.New("workspace file not found")
var ErrFileDenied = errors.New("workspace file access denied")
var ErrFileTooLarge = errors.New("workspace file exceeds 512 KiB")
var ErrFileIO = errors.New("workspace file operation failed")
var ErrFileConflict = errors.New("workspace destination conflicts with the source")
var ErrFileOperationLimit = errors.New("workspace operation exceeds entry or directory depth limit")

type SessionCreateRequest struct {
	Backend                string      `json:"backend"`
	ArtifactManifestSHA256 string      `json:"artifact_manifest_sha256"`
	MemoryMiB              int         `json:"memory_mib,omitempty"`
	VCPUs                  int         `json:"vcpus,omitempty"`
	TTLMS                  int         `json:"ttl_ms,omitempty"`
	Network                string      `json:"network,omitempty"`
	InputFiles             []InputFile `json:"input_files,omitempty"`
	tenantID               string
	startupStarted         time.Time
}

func (r *SessionCreateRequest) Normalize(config Config) {
	if r.MemoryMiB == 0 {
		r.MemoryMiB = config.Defaults.MemoryMiB
	}
	if r.VCPUs == 0 {
		r.VCPUs = config.Defaults.VCPUs
	}
	if r.TTLMS == 0 {
		r.TTLMS = min(sessionMaxTTLMS, sessionLifetimeMS(config))
	}
	if r.Network == "" {
		r.Network = "none"
	}
}

func (r SessionCreateRequest) Validate(config Config) error {
	if err := r.ValidateArguments(config); err != nil {
		return err
	}
	if r.Network == "proxy" && config.EgressSocket == "" {
		return errors.New("guest proxy egress service is not configured")
	}
	return nil
}

// ValidateArguments is for capability-based gateways; it does not certify a
// deployment or authorize network access. The server still calls Validate.
func (r SessionCreateRequest) ValidateArguments(config Config) error {
	if config.Backend != "firecracker-linux" {
		return errors.New("sessions are supported only by firecracker-linux")
	}
	if r.Backend == "" || !validSHA256Hex(r.ArtifactManifestSHA256) {
		return ErrInvalidSelector
	}
	if r.TTLMS < sessionMinTTLMS || r.TTLMS > sessionMaxTTLMS {
		return fmt.Errorf("ttl_ms must be in [%d,%d]", sessionMinTTLMS, sessionMaxTTLMS)
	}
	if r.TTLMS > sessionLifetimeMS(config) {
		return ErrTimeoutBeyondLifetime
	}
	if len(config.AllowedEntrypoints) == 0 {
		return errors.New("session backend has no allowed entrypoint")
	}
	job := r.asRunRequest(config)
	return job.ValidateArguments(config)
}

func (r SessionCreateRequest) asRunRequest(config Config) RunRequest {
	return RunRequest{
		Entrypoint: config.AllowedEntrypoints[0],
		Backend:    r.Backend, ArtifactManifestSHA256: r.ArtifactManifestSHA256,
		MemoryMiB: r.MemoryMiB, VCPUs: r.VCPUs, TimeoutMS: config.Defaults.TimeoutMS,
		Network: r.Network, InputFiles: r.InputFiles, tenantID: r.tenantID,
	}
}

type SessionCommandRequest struct {
	InteractiveStdin bool              `json:"interactive_stdin,omitempty"`
	Entrypoint       string            `json:"entrypoint"`
	Args             []string          `json:"args,omitempty"`
	TimeoutMS        int               `json:"timeout_ms,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	Cwd              string            `json:"cwd,omitempty"`
}

func (r *SessionCommandRequest) Normalize(config Config) {
	if r.TimeoutMS == 0 {
		r.TimeoutMS = config.Defaults.TimeoutMS
	}
}

func (r SessionCommandRequest) Validate(config Config, memoryMiB, vcpus int) error {
	if err := validateSessionEnvironment(r.Environment, r.Cwd); err != nil {
		return err
	}
	if r.Entrypoint == "" {
		return errors.New("entrypoint is required")
	}
	job := RunRequest{
		Entrypoint: r.Entrypoint, Args: r.Args,
		MemoryMiB: memoryMiB, VCPUs: vcpus, TimeoutMS: r.TimeoutMS,
		Network: "none",
	}
	return job.Validate(config)
}

func validateSessionEnvironment(env map[string]string, cwd string) error {
	if len(env) > 32 {
		return errors.New("environment exceeds 32 entries")
	}
	total := 0
	for name, value := range env {
		if name == "" || len(name) > 64 || len(value) > 1024 || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
			return errors.New("invalid environment name or value")
		}
		for i, ch := range name {
			if !(ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || i > 0 && ch >= '0' && ch <= '9') {
				return errors.New("invalid environment name")
			}
		}
		total += len(name) + len(value)
	}
	if total > 8192 {
		return errors.New("environment exceeds 8 KiB")
	}
	if cwd != "" {
		if !strings.HasPrefix(cwd, "/") || len(cwd) > 1024 || !utf8.ValidString(cwd) {
			return errors.New("cwd must be a guest absolute path")
		}
		for _, ch := range cwd {
			if unicode.IsControl(ch) {
				return errors.New("invalid cwd")
			}
		}
	}
	return nil
}

type SessionInfo struct {
	Network                string         `json:"network,omitempty"`
	LeaseRevision          uint64         `json:"lease_revision,omitempty"`
	MaxExpiresAt           time.Time      `json:"max_expires_at,omitempty"`
	RemainingTTLMS         int64          `json:"remaining_ttl_ms,omitempty"`
	MemoryMiB              int            `json:"memory_mib,omitempty"`
	VCPUs                  int            `json:"vcpus,omitempty"`
	GuestProtocol          string         `json:"guest_protocol,omitempty"`
	ID                     string         `json:"id"`
	State                  string         `json:"state"`
	Backend                string         `json:"backend"`
	ArtifactManifestSHA256 string         `json:"artifact_manifest_sha256"`
	CreatedAt              time.Time      `json:"created_at"`
	ExpiresAt              time.Time      `json:"expires_at"`
	StartupMode            string         `json:"startup_mode,omitempty"`
	StartupDurationUS      int64          `json:"startup_duration_us,omitempty"`
	StartupTiming          *StartupTiming `json:"startup_timing,omitempty"`
	VMBootDurationUS       int64          `json:"vm_boot_duration_us,omitempty"`
}

type SessionCommandResult struct {
	SessionID string    `json:"session_id"`
	RunResult RunResult `json:"result"`
}

type SessionFileRequest struct {
	Action      string            `json:"action"`
	Path        string            `json:"path"`
	Destination *string           `json:"destination,omitempty"`
	DataBase64  *string           `json:"data_base64,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (r SessionFileRequest) Validate() error {
	if r.Action == "rename" {
		if r.Destination == nil {
			return errors.New("rename requires destination")
		}
		if err := (SessionFileRequest{Action: "read", Path: *r.Destination}).Validate(); err != nil {
			return err
		}
	} else if r.Destination != nil {
		return errors.New("destination is only valid for rename")
	}
	if (r.Action == "list" || r.Action == "stat" || r.Action == "info") && r.Path == "/workspace" {
		if r.DataBase64 != nil || r.Metadata != nil {
			return errors.New("file action does not accept file data or metadata")
		}
		return nil
	}
	if !strings.HasPrefix(r.Path, "/workspace/") || len(r.Path) > len("/workspace/")+1024 ||
		strings.ContainsRune(r.Path, '\\') {
		return ErrInvalidFilePath
	}
	relative := strings.TrimPrefix(r.Path, "/workspace/")
	if relative == "" {
		return ErrInvalidFilePath
	}
	for _, ch := range relative {
		if unicode.IsControl(ch) {
			return ErrInvalidFilePath
		}
	}
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return ErrInvalidFilePath
		}
	}
	if r.Action == "mkdir" && strings.Count(relative, "/") >= 16 {
		return ErrInvalidFilePath
	}
	switch r.Action {
	case "read", "list", "stat", "info", "delete", "mkdir", "rename", "remove":
		if r.DataBase64 != nil || r.Metadata != nil {
			return errors.New("file action does not accept file data or metadata")
		}
	case "write":
		if r.DataBase64 == nil {
			return errors.New("write requires data_base64")
		}
		if len(*r.DataBase64) > base64.StdEncoding.EncodedLen(sessionFileLimit) {
			return ErrFileTooLarge
		}
		data, err := base64.StdEncoding.Strict().DecodeString(*r.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(data) != *r.DataBase64 {
			return errors.New("data_base64 must be canonical base64")
		}
		if len(data) > sessionFileLimit {
			return ErrFileTooLarge
		}
		if !validSessionFileMetadata(r.Metadata) {
			return errors.New("invalid or oversized file metadata")
		}
	default:
		return errors.New("unsupported session file action")
	}
	return nil
}

type SessionFileResult struct {
	SessionID   string             `json:"session_id"`
	Action      string             `json:"action"`
	Path        string             `json:"path"`
	Destination *string            `json:"destination,omitempty"`
	Size        int                `json:"size"`
	DataBase64  *string            `json:"data_base64,omitempty"`
	Kind        string             `json:"kind,omitempty"`
	Entries     *[]string          `json:"entries,omitempty"`
	Created     *bool              `json:"created,omitempty"`
	Info        *SessionFileInfo   `json:"info,omitempty"`
	EntryInfos  *[]SessionFileInfo `json:"entry_infos,omitempty"`
}

type SessionFileInfo struct {
	Name           string            `json:"name"`
	Path           string            `json:"path"`
	Type           string            `json:"type"`
	Size           int64             `json:"size"`
	Mode           uint32            `json:"mode"`
	Permissions    string            `json:"permissions"`
	Owner          string            `json:"owner"`
	Group          string            `json:"group"`
	ModifiedTimeMS int64             `json:"modified_time_ms"`
	SymlinkTarget  *string           `json:"symlink_target,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func filePermissionText(mode uint32) string {
	chars := []byte("---------")
	bits := []uint32{0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001}
	for index, bit := range bits {
		if mode&bit != 0 {
			chars[index] = "rwx"[index%3]
		}
	}
	for _, item := range []struct {
		index int
		bit   uint32
	}{{2, 0o4000}, {5, 0o2000}, {8, 0o1000}} {
		if mode&item.bit != 0 {
			if item.index == 8 {
				if chars[item.index] == 'x' {
					chars[item.index] = 't'
				} else {
					chars[item.index] = 'T'
				}
			} else {
				if chars[item.index] == 'x' {
					chars[item.index] = 's'
				} else {
					chars[item.index] = 'S'
				}
			}
		}
	}
	return string(chars)
}

func validSessionFileInfo(info SessionFileInfo, path, name string) bool {
	if info.Path != path || info.Name != name || info.Size < 0 || info.Size > 1<<40 ||
		info.Mode > 0o177777 ||
		info.ModifiedTimeMS < 0 || info.ModifiedTimeMS > 4_102_444_800_000 ||
		info.Permissions != filePermissionText(info.Mode) {
		return false
	}
	typeBits := info.Mode & 0o170000
	if info.Type != "file" && info.Type != "directory" && info.Type != "symlink" && info.Type != "other" ||
		info.Type == "file" && typeBits != 0o100000 ||
		info.Type == "directory" && typeBits != 0o040000 ||
		info.Type == "symlink" && typeBits != 0o120000 ||
		info.Type == "other" && (typeBits != 0o010000 && typeBits != 0o020000 &&
			typeBits != 0o060000 && typeBits != 0o140000) {
		return false
	}
	if info.Type == "symlink" {
		if info.SymlinkTarget == nil || *info.SymlinkTarget == "" ||
			len(*info.SymlinkTarget) > 4096 || !utf8.ValidString(*info.SymlinkTarget) ||
			strings.ContainsRune(*info.SymlinkTarget, 0) || info.Metadata != nil ||
			info.Size != int64(len(*info.SymlinkTarget)) {
			return false
		}
	} else if info.SymlinkTarget != nil {
		return false
	}
	if !validSessionFileMetadata(info.Metadata) {
		return false
	}
	for _, value := range []string{info.Owner, info.Group} {
		if value == "" || len(value) > 128 || !utf8.ValidString(value) {
			return false
		}
		for _, char := range value {
			if unicode.IsControl(char) {
				return false
			}
		}
	}
	return true
}

func validSessionFileMetadata(metadata map[string]string) bool {
	if len(metadata) > 16 {
		return false
	}
	metadataBytes := 0
	for key, value := range metadata {
		if key == "" || len(key) > 246 {
			return false
		}
		for _, ch := range key {
			if ch > 127 || !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
				return false
			}
		}
		for _, ch := range value {
			if ch < 0x20 || ch > 0x7e {
				return false
			}
		}
		metadataBytes += len(key) + len(value)
		if metadataBytes > 16*1024 {
			return false
		}
	}
	return true
}

func validateSessionFileInfoList(path string, names []string, infos []SessionFileInfo) bool {
	if len(infos) > len(names) {
		return false
	}
	position := 0
	for _, info := range infos {
		for position < len(names) && names[position] < info.Name {
			position++
		}
		if position == len(names) || names[position] != info.Name ||
			!validSessionFileInfo(info, path+"/"+info.Name, info.Name) {
			return false
		}
		position++
	}
	return true
}

func validateSessionFileEntries(entries []string) error {
	if len(entries) > sessionFileListLimit {
		return ErrFileTooLarge
	}
	total := 0
	previous := ""
	for i, name := range entries {
		if name == "" || name == "." || name == ".." || len(name) > 255 ||
			strings.ContainsAny(name, "/\\") || !utf8.ValidString(name) {
			return ErrInvalidFilePath
		}
		for _, ch := range name {
			if unicode.IsControl(ch) {
				return ErrInvalidFilePath
			}
		}
		if i > 0 && previous >= name {
			return ErrInvalidFilePath
		}
		total += len(name)
		if total > sessionFileListNameBytesLimit {
			return ErrFileTooLarge
		}
		previous = name
	}
	return nil
}
