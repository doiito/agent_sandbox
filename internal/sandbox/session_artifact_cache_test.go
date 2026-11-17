package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func artifactCacheFixture(t *testing.T, id string) *artifactBlob {
	t.Helper()
	request := artifactTestRequest()
	request.ArtifactID = id
	data := bytes.Repeat([]byte{0, 128, 255, 5}, 180001)
	frames := artifactTestFrames(request, "directory", []linuxArtifactEntry{{Path: "binary", Type: "file", Size: int64(len(data)), Mode: 0o100644}}, map[string][]byte{"binary": data})
	return artifactTestBuild(t, t.TempDir(), request, artifactTestWire(request, frames))
}

func TestSessionArtifactCacheQuotaDownloadAndDelete(t *testing.T) {
	var cache artifactCache
	defer cache.close()
	id, second, third := strings.Repeat("a", 24), strings.Repeat("b", 24), strings.Repeat("c", 24)
	if err := cache.reserve(id); err != nil {
		t.Fatal(err)
	}
	if err := cache.reserve(second); err != nil {
		t.Fatal(err)
	}
	if err := cache.reserve(third); !errors.Is(err, ErrArtifactLimit) {
		t.Fatal("pending exports not charged", err)
	}
	if _, err := cache.read(context.Background(), second, SessionArtifactReadRequest{Length: 1}); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatal("unpublished artifact visible", err)
	}
	if err := cache.delete(second); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatal("pending reservation deleted", err)
	}
	cache.abort(second)
	if err := cache.reserve(third); err != nil {
		t.Fatal(err)
	}
	cache.abort(third)
	blob := artifactCacheFixture(t, id)
	if err := cache.commit(blob); err != nil {
		t.Fatal(err)
	}
	var archive []byte
	for offset := int64(0); offset < blob.info.Size; {
		chunk, err := cache.read(context.Background(), id, SessionArtifactReadRequest{Offset: offset, Length: sessionArtifactReadBytes})
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.Strict().DecodeString(chunk.DataBase64)
		if err != nil || len(data) == 0 || len(data) > sessionArtifactReadBytes || chunk.DataSHA256 != artifactTestSHA(data) ||
			chunk.ArchiveSHA256 != blob.info.SHA256 || chunk.ID != id || chunk.SessionID != blob.info.SessionID || chunk.Offset != offset || chunk.TotalSize != blob.info.Size ||
			chunk.EOF != (offset+int64(len(data)) == blob.info.Size) {
			t.Fatal("invalid download block", err)
		}
		archive = append(archive, data...)
		offset += int64(len(data))
	}
	if artifactTestSHA(archive) != blob.info.SHA256 {
		t.Fatal("download checksum mismatch")
	}
	eof, err := cache.read(context.Background(), id, SessionArtifactReadRequest{Offset: blob.info.Size, Length: 1})
	if err != nil || !eof.EOF || eof.DataBase64 != "" || eof.DataSHA256 != artifactTestSHA(nil) {
		t.Fatal(eof, err)
	}
	for _, request := range []SessionArtifactReadRequest{{Offset: -1, Length: 1}, {Offset: blob.info.Size + 1, Length: 1}, {Length: 0}, {Length: sessionArtifactReadBytes + 1}} {
		if _, err := cache.read(context.Background(), id, request); !errors.Is(err, ErrArtifactRange) {
			t.Fatal("range accepted", request, err)
		}
	}
	if err := cache.delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := blob.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("deleted artifact FD remains open", err)
	}
	if _, err := cache.read(context.Background(), id, SessionArtifactReadRequest{Length: 1}); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatal(err)
	}
	if err := cache.reserve(id); err != nil {
		t.Fatal("deleted capacity was not reusable", err)
	}
}

func TestSessionArtifactCacheCloseRejectsLatePublicationAndReleasesFDs(t *testing.T) {
	var cache artifactCache
	id, second := strings.Repeat("a", 24), strings.Repeat("b", 24)
	first, late := artifactCacheFixture(t, id), artifactCacheFixture(t, second)
	if err := cache.reserve(id); err != nil {
		t.Fatal(err)
	}
	if err := cache.commit(first); err != nil {
		t.Fatal(err)
	}
	if err := cache.reserve(second); err != nil {
		t.Fatal(err)
	}
	if err := cache.close(); err != nil {
		t.Fatal(err)
	}
	if err := cache.commit(late); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("late publication allowed", err)
	}
	for _, blob := range []*artifactBlob{first, late} {
		if _, err := blob.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("closed cache leaked FD", err)
		}
	}
	if err := cache.reserve(strings.Repeat("c", 24)); !errors.Is(err, ErrSessionClosed) {
		t.Fatal(err)
	}
	if err := cache.close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
}

func TestSessionArtifactCacheConcurrentReadDeleteClose(t *testing.T) {
	var cache artifactCache
	id := strings.Repeat("a", 24)
	blob := artifactCacheFixture(t, id)
	if err := cache.reserve(id); err != nil {
		t.Fatal(err)
	}
	if err := cache.commit(blob); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			chunk, err := cache.read(context.Background(), id, SessionArtifactReadRequest{Length: sessionArtifactReadBytes})
			if err != nil && !errors.Is(err, ErrSessionClosed) && !errors.Is(err, ErrArtifactNotFound) {
				t.Error(err)
			}
			if err == nil {
				data, _ := base64.StdEncoding.DecodeString(chunk.DataBase64)
				if artifactTestSHA(data) != chunk.DataSHA256 {
					t.Error("torn read")
				}
			}
		}()
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		err := cache.delete(id)
		if err != nil && !errors.Is(err, ErrSessionClosed) {
			t.Error(err)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		if err := cache.close(); err != nil {
			t.Error(err)
		}
	}()
	close(start)
	workers.Wait()
	if _, err := blob.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("race left open FD", err)
	}
}
