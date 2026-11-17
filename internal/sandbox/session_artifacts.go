package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (s *Session) checkArtifacts() error {
	if s.manager == nil || !s.manager.hasLinuxArtifactFeature() || !s.backend.WorkspaceArtifacts {
		return ErrArtifactsUnsupported
	}
	if s.closed.Load() || s.ctx.Err() != nil {
		return ErrSessionClosed
	}
	return nil
}

func (s *Session) recordArtifact(id, state string, info *SessionArtifactInfo, duration time.Duration) error {
	if s.artifactAudit != nil {
		return s.artifactAudit(id, state, info, duration)
	}
	return nil
}

func (s *Session) CreateArtifact(ctx context.Context, request SessionArtifactCreateRequest) (SessionArtifactInfo, error) {
	if err := s.checkArtifacts(); err != nil {
		return SessionArtifactInfo{}, err
	}
	if err := request.Validate(); err != nil {
		return SessionArtifactInfo{}, err
	}
	if !s.opMu.TryLock() {
		return SessionArtifactInfo{}, ErrBusy
	}
	defer s.opMu.Unlock()
	if err := s.checkArtifacts(); err != nil {
		return SessionArtifactInfo{}, err
	}
	id, err := randomID()
	if err != nil {
		return SessionArtifactInfo{}, err
	}
	if err := s.artifacts.reserve(id); err != nil {
		return SessionArtifactInfo{}, err
	}
	defer s.artifacts.abort(id)
	identity, err := newLinuxGuestBinding(s.info.ID)
	if err != nil {
		return SessionArtifactInfo{}, err
	}
	transfer, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopSession := context.AfterFunc(s.ctx, cancel)
	defer stopSession()
	defer cancel()
	if err := transfer.Err(); err != nil {
		return SessionArtifactInfo{}, err
	}
	started := time.Now()
	if err := s.recordArtifact(id, "admitted", nil, 0); err != nil {
		_ = s.Close()
		return SessionArtifactInfo{}, fmt.Errorf("%w: artifact admission audit failed", ErrUnavailable)
	}
	blob, err := s.backend.exportSessionArtifact(transfer, linuxArtifactRequest{SessionID: s.info.ID,
		ArtifactID: id, Nonce: identity.Nonce, Path: request.Path, Binding: s.binding}, s.workdir)
	if err != nil {
		auditErr := s.recordArtifact(id, "failed", nil, time.Since(started))
		if auditErr != nil || transfer.Err() != nil || !knownArtifactRejection(err) {
			_ = s.Close()
			return SessionArtifactInfo{}, fmt.Errorf("%w: artifact transfer failed", ErrUnavailable)
		}
		return SessionArtifactInfo{}, err
	}
	if transfer.Err() != nil || s.closed.Load() {
		_ = blob.Close()
		_ = s.Close()
		return SessionArtifactInfo{}, ErrSessionClosed
	}
	if err := s.recordArtifact(id, "created", &blob.info, time.Since(started)); err != nil {
		_ = blob.Close()
		_ = s.Close()
		return SessionArtifactInfo{}, fmt.Errorf("%w: artifact completion audit failed", ErrUnavailable)
	}
	if transfer.Err() != nil || s.closed.Load() {
		_ = blob.Close()
		_ = s.Close()
		return SessionArtifactInfo{}, ErrSessionClosed
	}
	if err := s.artifacts.commit(blob); err != nil {
		return SessionArtifactInfo{}, err
	}
	return blob.info, nil
}

func knownArtifactRejection(err error) bool {
	for _, expected := range []error{ErrFileNotFound, ErrFileDenied, ErrArtifactTooLarge, ErrArtifactChanged,
		ErrInvalidFilePath, ErrFileIO, ErrArtifactsUnsupported} {
		if errors.Is(err, expected) {
			return true
		}
	}
	return false
}

func (s *Session) ReadArtifact(ctx context.Context, id string, request SessionArtifactReadRequest) (SessionArtifactChunk, error) {
	if err := s.checkArtifacts(); err != nil {
		return SessionArtifactChunk{}, err
	}
	chunk, err := s.artifacts.read(ctx, id, request)
	if err != nil && !errors.Is(err, ErrArtifactRange) && !errors.Is(err, ErrArtifactNotFound) && !errors.Is(err, ErrSessionClosed) && ctx.Err() == nil {
		return SessionArtifactChunk{}, fmt.Errorf("%w: read artifact cache", ErrUnavailable)
	}
	return chunk, err
}

func (s *Session) DeleteArtifact(ctx context.Context, id string) error {
	if err := s.checkArtifacts(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.artifacts.delete(id); err != nil {
		return err
	}
	if err := s.recordArtifact(id, "deleted", nil, 0); err != nil {
		_ = s.Close()
		return fmt.Errorf("%w: artifact deletion audit failed", ErrUnavailable)
	}
	return nil
}
