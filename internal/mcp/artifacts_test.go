package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func artifactFixture() (sandbox.CapabilityReport, sandbox.SessionArtifactInfo, sandbox.SessionArtifactChunk) {
	cap := testCapabilities()
	cap.ArtifactManifestProtocol = "osv-sandbox-artifacts/v8"
	cap.Features.SessionArtifacts = true
	cap.Limits.SessionArtifactCount, cap.Limits.SessionArtifactMaxBytes = 2, 32<<20
	cap.Limits.SessionArtifactReadBytes, cap.Limits.SessionArtifactEntries = 512<<10, 1024
	cap.Limits.SessionArtifactDepth, cap.Limits.SessionArtifactPathBytes = 16, 64<<10
	info := sandbox.SessionArtifactInfo{ID: strings.Repeat("c", 24), SessionID: strings.Repeat("a", 24), Path: "/workspace", SourceKind: "directory", Format: "tar", Size: 524288 + 4096, SHA256: strings.Repeat("d", 64), Entries: 1, Files: 1, PayloadBytes: 524288}
	data := bytes.Repeat([]byte{0, 255}, 256<<10)
	digest := sha256.Sum256(data)
	chunk := sandbox.SessionArtifactChunk{ID: info.ID, SessionID: info.SessionID, TotalSize: info.Size, DataBase64: base64.StdEncoding.EncodeToString(data), DataSHA256: hex.EncodeToString(digest[:]), ArchiveSHA256: info.SHA256}
	return cap, info, chunk
}

func TestArtifactToolsUseOwnerCapabilitiesAndBoundedCreateReadDelete(t *testing.T) {
	cap, info, chunk := artifactFixture()
	var calls []string
	s := mockServer(4, func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/capabilities") {
			return reply(sandbox.SessionCapabilityReport{SessionID: info.SessionID, CapabilityReport: cap}), nil
		}
		if r.Method == "DELETE" {
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		if strings.HasSuffix(r.URL.Path, "/read") {
			var req sandbox.SessionArtifactReadRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Length != 512<<10 {
				t.Error("incorrect read body")
			}
			return reply(chunk), nil
		}
		return reply(info), nil
	})
	// New-admission discovery can be OSv/unavailable; the admitted owner is
	// authoritative for all three artifact operations.
	created := s.callTool(context.Background(), "sandbox.fs.artifact.create", rawObject(map[string]any{"session_id": info.SessionID, "path": "/workspace"}), sandbox.CapabilityReport{})
	if created.IsError || created.Rollback == nil {
		t.Fatal(string(created.Data))
	}
	read := s.callTool(context.Background(), "sandbox.fs.artifact.read", rawObject(map[string]any{"session_id": info.SessionID, "artifact_id": info.ID, "offset": 0, "length": 512 << 10}), sandbox.CapabilityReport{})
	if read.IsError || read.Rollback != nil {
		t.Fatal(string(read.Data))
	}
	encoded, err := json.Marshal(callResult(read))
	if err != nil || len(encoded) > maxOutputFrame {
		t.Fatal("maximum binary read exceeds MCP envelope", len(encoded), err)
	}
	deleted := s.callTool(context.Background(), "sandbox.fs.artifact.delete", rawObject(map[string]any{"session_id": info.SessionID, "artifact_id": info.ID}), sandbox.CapabilityReport{})
	if deleted.IsError || !bytes.Contains(deleted.Data, []byte(`"deleted":true`)) {
		t.Fatal(string(deleted.Data))
	}
	if len(calls) != 6 {
		t.Fatal("unexpected admission query or replay", calls)
	}
	created.Rollback()
	if !strings.HasPrefix(calls[len(calls)-1], "DELETE ") {
		t.Fatal("undelivered create was not rolled back", calls)
	}
}

func TestArtifactToolCatalogPreservesOwnedOperationsAfterTemplateRetirement(t *testing.T) {
	cap, _, _ := artifactFixture()
	catalog := sandbox.TemplateCatalogReport{Templates: []sandbox.TemplateReport{{Capabilities: cap, Available: false}}}
	tools := toolsFor(sandbox.CapabilityReport{}, &catalog)
	found := map[string]bool{}
	for _, tool := range tools {
		found[tool.Name] = true
	}
	for name := range artifactOperations {
		if !found[name] {
			t.Fatal("retired owner lost artifact tool", name)
		}
	}
	if found["sandbox.session.create"] {
		t.Fatal("retired template admitted new sessions")
	}
	cap.Features.SessionArtifacts = false
	if len(artifactToolsFor(cap)) != 0 {
		t.Fatal("legacy template gained artifact tools")
	}
}

func TestArtifactV8KeepsExistingCodePortAndInferenceToolGates(t *testing.T) {
	code := codeCapabilityForTest()
	code.ArtifactManifestProtocol = "osv-sandbox-artifacts/v8"
	if !codeCapable(code) {
		t.Fatal("v8 lost signed code tools")
	}
	port := testCapabilities()
	port.Features.PortForward = true
	port.ArtifactManifestProtocol = "osv-sandbox-artifacts/v8"
	if !portCapable(port) {
		t.Fatal("v8 lost signed port tools")
	}
	inference, _, _ := inferenceFixture(t)
	inference.ArtifactManifestProtocol = "osv-sandbox-artifacts/v8"
	if !inferenceCapable(inference.CapabilityReport) {
		t.Fatal("v8 lost signed inference tools")
	}
	inference.Backend = "firecracker-osv"
	if inferenceCapable(inference.CapabilityReport) {
		t.Fatal("OSv gained a Linux v8 profile")
	}
}

func TestArtifactToolsRejectInvalidArgumentsBeforeTransport(t *testing.T) {
	s := mockServer(1, func(*http.Request) (*http.Response, error) {
		t.Error("invalid arguments reached API")
		return nil, errors.New("unexpected")
	})
	for _, args := range []json.RawMessage{
		json.RawMessage(`{"session_id":"bad","path":"/workspace"}`),
		rawObject(map[string]any{"session_id": strings.Repeat("a", 24), "path": "/workspace/../secret"}),
		rawObject(map[string]any{"session_id": strings.Repeat("a", 24), "path": "/workspace", "offset": 0}),
	} {
		if !s.callTool(context.Background(), "sandbox.fs.artifact.create", args, sandbox.CapabilityReport{}).IsError {
			t.Fatal("invalid create accepted")
		}
	}
	for _, args := range []map[string]any{
		{"session_id": strings.Repeat("a", 24), "artifact_id": strings.Repeat("c", 24), "length": 1},
		{"session_id": strings.Repeat("a", 24), "artifact_id": strings.Repeat("c", 24), "offset": 0, "length": 524289},
	} {
		if !s.callTool(context.Background(), "sandbox.fs.artifact.read", rawObject(args), sandbox.CapabilityReport{}).IsError {
			t.Fatal("invalid read accepted")
		}
	}
}

func TestArtifactToolsRejectCorruptChunksAndNeverRetryUncertainCreate(t *testing.T) {
	cap, info, chunk := artifactFixture()
	for _, corrupt := range []string{"binding", "hash", "create-loss"} {
		t.Run(corrupt, func(t *testing.T) {
			posts := 0
			s := mockServer(1, func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					return reply(sandbox.SessionCapabilityReport{SessionID: info.SessionID, CapabilityReport: cap}), nil
				}
				posts++
				if corrupt == "create-loss" {
					return nil, errors.New("private transport detail")
				}
				copy := chunk
				if corrupt == "binding" {
					copy.SessionID = strings.Repeat("e", 24)
				} else {
					copy.DataSHA256 = strings.Repeat("0", 64)
				}
				return reply(copy), nil
			})
			name := "sandbox.fs.artifact.read"
			args := map[string]any{"session_id": info.SessionID, "artifact_id": info.ID, "offset": 0, "length": 524288}
			if corrupt == "create-loss" {
				name = "sandbox.fs.artifact.create"
				args = map[string]any{"session_id": info.SessionID, "path": "/workspace"}
			}
			value := s.callTool(context.Background(), name, rawObject(args), cap)
			if !value.IsError || posts != 1 || value.Rollback != nil || bytes.Contains(value.Data, []byte("private transport detail")) {
				t.Fatal("corrupt/uncertain operation accepted or replayed", posts, string(value.Data))
			}
		})
	}
}
