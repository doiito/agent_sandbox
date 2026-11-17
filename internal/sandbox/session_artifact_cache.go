package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sync"
)

// artifactCache owns committed FDs. Nil entries reserve capacity before a
// caller opens any spool; close also invalidates outstanding reservations.
// A bounded ReadAt under mu makes read/delete/close linearizable.
type artifactCache struct {
	mu     sync.Mutex
	closed bool
	items  map[string]*artifactBlob
}

func (c *artifactCache) reserve(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrSessionClosed
	}
	if !validSessionID(id) {
		return errArtifactProtocol
	}
	if _, exists := c.items[id]; exists {
		return errArtifactProtocol
	}
	if len(c.items) >= sessionArtifactLimit {
		return ErrArtifactLimit
	}
	if c.items == nil {
		c.items = make(map[string]*artifactBlob)
	}
	c.items[id] = nil
	return nil
}

func (c *artifactCache) abort(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, exists := c.items[id]; exists && item == nil {
		delete(c.items, id)
	}
}

// commit always consumes ownership of blob, even when publication fails.
func (c *artifactCache) commit(blob *artifactBlob) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if blob == nil {
		return errArtifactProtocol
	}
	if c.closed {
		_ = blob.Close()
		return ErrSessionClosed
	}
	if !blob.info.valid() || blob.file == nil {
		_ = blob.Close()
		return errArtifactProtocol
	}
	if item, exists := c.items[blob.info.ID]; !exists || item != nil {
		_ = blob.Close()
		return errArtifactProtocol
	}
	c.items[blob.info.ID] = blob
	return nil
}

func (c *artifactCache) read(ctx context.Context, id string, request SessionArtifactReadRequest) (SessionArtifactChunk, error) {
	if err := request.Validate(); err != nil {
		return SessionArtifactChunk{}, err
	}
	if !validSessionID(id) {
		return SessionArtifactChunk{}, ErrArtifactNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return SessionArtifactChunk{}, ErrSessionClosed
	}
	if err := ctx.Err(); err != nil {
		return SessionArtifactChunk{}, err
	}
	item := c.items[id]
	if item == nil {
		return SessionArtifactChunk{}, ErrArtifactNotFound
	}
	if request.Offset > item.info.Size {
		return SessionArtifactChunk{}, ErrArtifactRange
	}
	count := min(int64(request.Length), item.info.Size-request.Offset)
	data := make([]byte, int(count))
	if count > 0 {
		n, err := item.file.ReadAt(data, request.Offset)
		if err != nil || int64(n) != count {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return SessionArtifactChunk{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return SessionArtifactChunk{}, err
	}
	digest := sha256.Sum256(data)
	return SessionArtifactChunk{ID: id, SessionID: item.info.SessionID, Offset: request.Offset,
		TotalSize: item.info.Size, DataBase64: base64.StdEncoding.EncodeToString(data),
		DataSHA256: hex.EncodeToString(digest[:]), ArchiveSHA256: item.info.SHA256,
		EOF: request.Offset+count == item.info.Size}, nil
}

func (c *artifactCache) delete(id string) error {
	if !validSessionID(id) {
		return ErrArtifactNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrSessionClosed
	}
	item := c.items[id]
	if item == nil {
		return ErrArtifactNotFound
	}
	delete(c.items, id)
	return item.Close()
}

func (c *artifactCache) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var errs []error
	for _, item := range c.items {
		if item != nil {
			errs = append(errs, item.Close())
		}
	}
	c.items = nil
	return errors.Join(errs...)
}
