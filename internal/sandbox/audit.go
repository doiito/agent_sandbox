package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

type AuditEvent struct {
	ArtifactID      string    `json:"artifact_id,omitempty"`
	ArtifactBytes   int64     `json:"artifact_bytes,omitempty"`
	ArtifactEntries int       `json:"artifact_entries,omitempty"`
	PreviewID       string    `json:"preview_id,omitempty"`
	Protocol        string    `json:"protocol"`
	At              time.Time `json:"at"`
	Event           string    `json:"event"`
	RequestID       string    `json:"request_id,omitempty"`
	Tenant          string    `json:"tenant,omitempty"`
	PeerUID         uint32    `json:"peer_uid"`
	PeerPID         int32     `json:"peer_pid"`
	JobID           string    `json:"job_id,omitempty"`
	State           string    `json:"state,omitempty"`
	Code            string    `json:"code,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	VMID            string    `json:"vm_id,omitempty"`
	ProfileSHA256   string    `json:"profile_sha256,omitempty"`
	StartupMode     string    `json:"startup_mode,omitempty"`
	ConnectionID    string    `json:"connection_id,omitempty"`
	Port            uint16    `json:"port,omitempty"`
	SentBytes       uint64    `json:"sent_bytes,omitempty"`
	ReceivedBytes   uint64    `json:"received_bytes,omitempty"`
}

type AuditRecorder interface {
	Append(AuditEvent) error
	Err() error
}

// AuditLog serializes each record's write and sync. Once a record is lost,
// successful later syncs cannot establish completeness: restart is required.
type AuditLog struct {
	mu     sync.Mutex
	writer io.Writer
	sync   func() error
	file   *os.File
	failed error
}

func OpenAuditLog(path string) (*AuditLog, error) {
	if err := ValidateAuditLogTarget(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateAuditTail(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &AuditLog{writer: f, sync: f.Sync, file: f}, nil
}

func validateAuditTail(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("audit target is not a regular file")
	}
	if info.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
		return err
	}
	if last[0] != '\n' {
		return errors.New("audit log has an incomplete tail; preserve and repair before restart")
	}
	return nil
}

func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	return a.file.Close()
}

func (a *AuditLog) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failed
}

func (a *AuditLog) Append(event AuditEvent) error {
	event.Protocol, event.At = "osv-sandbox-audit/v1", time.Now().UTC()
	return a.appendRecord(event)
}

func (a *AuditLog) appendRecord(event any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed != nil {
		return a.failed
	}
	payload, err := json.Marshal(event)
	if err == nil {
		payload = append(payload, '\n')
		var written int
		written, err = a.writer.Write(payload)
		if err == nil && written != len(payload) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = a.sync()
	}
	if err != nil {
		a.failed = fmt.Errorf("audit persistence: %w", err)
		return a.failed
	}
	return nil
}

func auditAvailability(recorder AuditRecorder) DoctorCheck {
	check := DoctorCheck{Name: "audit", Detail: "durable admission and completion records; no persistence failure recorded"}
	if recorder == nil {
		check.Detail = "durable audit recorder is unavailable"
	} else if err := recorder.Err(); err != nil {
		check.Detail = "audit persistence failed; restart after repair required"
	} else {
		check.OK = true
	}
	return check
}

var errAuditUnavailable = errors.New("audit durability failure")
