package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const linuxPristineProtocol = "fc-agent/v3"

type linuxGuestBinding struct {
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"`
}

type linuxPrepareRequest struct {
	Network    string            `json:"network,omitempty"`
	Binding    linuxGuestBinding `json:"binding"`
	Mode       string            `json:"mode"`
	TTLMS      int               `json:"ttl_ms"`
	InputFiles []InputFile       `json:"input_files,omitempty"`
}

func newLinuxGuestBinding(sessionID string) (linuxGuestBinding, error) {
	if !validSessionID(sessionID) {
		return linuxGuestBinding{}, errors.New("invalid preparation session ID")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return linuxGuestBinding{}, err
	}
	return linuxGuestBinding{SessionID: sessionID, Nonce: hex.EncodeToString(nonce[:])}, nil
}

func (b linuxGuestBinding) valid() bool {
	return validSessionID(b.SessionID) && validSHA256Hex(b.Nonce)
}

func (r linuxPrepareRequest) validate() error {
	if r.Network != "" && r.Network != "none" && r.Network != "proxy" {
		return errors.New("invalid Linux prepare network")
	}
	if !r.Binding.valid() || (r.Mode != "job" && r.Mode != "session") || r.TTLMS < 1000 || r.TTLMS > 300000 && (r.Mode != "session" || r.TTLMS > sessionMaxLifetimeMS) {
		return errors.New("invalid pristine preparation binding, mode or lease")
	}
	return validateInputFiles(r.InputFiles)
}

func validateInputFiles(files []InputFile) error {
	if len(files) > 64 {
		return errors.New("at most 64 input files are allowed")
	}
	paths := make(map[string]struct{}, len(files))
	var nameBytes, dataBytes int
	for _, input := range files {
		nameBytes += len(input.Path)
		parts := strings.Split(input.Path, "/")
		if input.Path == "" || len(input.Path) > 1024 || !utf8.ValidString(input.Path) ||
			len(parts) > 16 || strings.ContainsRune(input.Path, '\\') || nameBytes > 32*1024 {
			return errors.New("invalid or oversized input path")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || len(part) > 255 {
				return errors.New("input paths must be clean relative paths")
			}
			for _, ch := range part {
				if unicode.IsControl(ch) {
					return errors.New("input paths cannot contain control characters")
				}
			}
		}
		if _, exists := paths[input.Path]; exists {
			return errors.New("duplicate input file path")
		}
		paths[input.Path] = struct{}{}
		if input.Mode != 0 && input.Mode != 0o444 {
			return errors.New("input files are data-only and mode must be 0444")
		}
		if len(input.Data) > 512*1024-dataBytes {
			return errors.New("input files exceed 512 KiB")
		}
		dataBytes += len(input.Data)
	}
	for path := range paths {
		for offset := strings.LastIndexByte(path, '/'); offset >= 0; offset = strings.LastIndexByte(path, '/') {
			path = path[:offset]
			if _, exists := paths[path]; exists {
				return errors.New("input file conflicts with a parent directory")
			}
		}
	}
	return nil
}

func validatePreparedResult(request linuxJobRequest, result json.RawMessage) error {
	var envelope struct {
		Binding    *linuxGuestBinding `json:"binding"`
		GuestState string             `json:"guest_state"`
		Revision   int                `json:"pristine_revision"`
		Remaining  *int               `json:"remaining_lifetime_ms"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		return err
	}
	expected := request.Binding
	if request.Prepare != nil {
		expected = &request.Prepare.Binding
	}
	if expected == nil {
		if request.Operation == "shutdown" {
			return nil
		}
		if request.Operation != "ping" || envelope.Revision != 2 || envelope.Binding != nil || envelope.GuestState != "pristine" ||
			envelope.Remaining == nil || *envelope.Remaining <= 0 || *envelope.Remaining > 600000 {
			return errors.New("guest did not prove pristine readiness")
		}
		return nil
	}
	if envelope.Revision != 2 || envelope.Binding == nil || *envelope.Binding != *expected || envelope.GuestState != "prepared" ||
		envelope.Remaining == nil || *envelope.Remaining < 0 || *envelope.Remaining > sessionMaxLifetimeMS {
		return errors.New("prepared guest result failed binding, state or lifetime validation")
	}
	if request.Prepare != nil && (*envelope.Remaining <= 0 || *envelope.Remaining > request.Prepare.TTLMS) {
		return errors.New("prepared acknowledgment has invalid lease")
	}
	return nil
}
