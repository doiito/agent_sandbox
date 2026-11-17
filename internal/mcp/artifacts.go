package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var artifactOperations = map[string]bool{"sandbox.fs.artifact.create": true, "sandbox.fs.artifact.read": true, "sandbox.fs.artifact.delete": true}

func artifactCapable(cap sandbox.CapabilityReport) bool {
	l := cap.Limits
	return cap.Backend == "firecracker-linux" && cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v8" && cap.ArtifactAuthenticated && digestPattern.MatchString(cap.ArtifactManifestSHA256) && cap.Features.Sessions && cap.Features.SessionArtifacts &&
		l.SessionArtifactCount > 0 && l.SessionArtifactCount <= 2 && l.SessionArtifactMaxBytes >= 2048 && l.SessionArtifactMaxBytes <= 32<<20 &&
		l.SessionArtifactReadBytes > 0 && l.SessionArtifactReadBytes <= 512<<10 && l.SessionArtifactEntries > 0 && l.SessionArtifactEntries <= 1024 &&
		l.SessionArtifactDepth > 0 && l.SessionArtifactDepth <= 16 && l.SessionArtifactPathBytes > 0 && l.SessionArtifactPathBytes <= 64<<10
}

func artifactToolsFor(cap sandbox.CapabilityReport) []tool {
	if !artifactCapable(cap) {
		return nil
	}
	identity := func() map[string]any {
		return map[string]any{"session_id": handleSchema(), "artifact_id": handleSchema()}
	}
	read := identity()
	read["offset"] = integerSchema(0, cap.Limits.SessionArtifactMaxBytes)
	read["length"] = integerSchema(1, cap.Limits.SessionArtifactReadBytes)
	return []tool{
		toolDefinition("sandbox.fs.artifact.create", "Create an immutable bounded tar from this session's workspace file/directory. Returns an artifact ID, total size and SHA256; read chunks and delete explicitly after use. Does not extract or upload to external storage.", false, map[string]any{"session_id": handleSchema(), "path": map[string]any{"type": "string", "pattern": "^/workspace(?:/|$)", "maxLength": 1035}}, "session_id", "path"),
		toolDefinition("sandbox.fs.artifact.read", "Read one cached tar byte range (up to 512 KiB) as canonical base64. Returns chunk and complete archive SHA256; compare total size and archive digest with create. No guest command or automatic extraction.", true, read, "session_id", "artifact_id", "offset", "length"),
		toolDefinition("sandbox.fs.artifact.delete", "Delete a cached session artifact and release its quota. A missing ID returns not found; never replays a create.", false, identity(), "session_id", "artifact_id"),
	}
}

type artifactToolRequest struct {
	Session string `json:"session_id"`
	ID      string `json:"artifact_id,omitempty"`
	Path    string `json:"path,omitempty"`
	Offset  *int64 `json:"offset,omitempty"`
	Length  *int   `json:"length,omitempty"`
}

func (s *Server) callArtifactTool(ctx context.Context, name string, args json.RawMessage) outcome {
	var v artifactToolRequest
	fields, ok := object(args)
	if !artifactOperations[name] || !ok || decodeStrict(args, &v) != nil || !handlePattern.MatchString(v.Session) {
		return invalidArgs()
	}
	creating := strings.HasSuffix(name, ".create")
	if creating {
		if len(fields) != 2 || v.ID != "" || v.Offset != nil || v.Length != nil || (sandbox.SessionArtifactCreateRequest{Path: v.Path}).Validate() != nil {
			return invalidArgs()
		}
	} else if !handlePattern.MatchString(v.ID) || v.Path != "" {
		return invalidArgs()
	}
	if strings.HasSuffix(name, ".read") {
		if len(fields) != 4 || v.Offset == nil || v.Length == nil || (sandbox.SessionArtifactReadRequest{Offset: *v.Offset, Length: *v.Length}).Validate() != nil {
			return invalidArgs()
		}
	} else if !creating && (len(fields) != 2 || v.Offset != nil || v.Length != nil) {
		return invalidArgs()
	}
	limit := 10 * time.Second
	if creating {
		limit = 35 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cap, err := s.api.ownerCapabilities(bounded, v.Session)
	if err != nil {
		return failure(err)
	}
	if !artifactCapable(cap) {
		return toolFailure("unsupported", "workspace artifacts are unavailable for this owned session")
	}
	path := "/v2/sessions/" + v.Session + "/artifacts"
	method := "POST"
	var body any = sandbox.SessionArtifactCreateRequest{Path: v.Path}
	if !creating {
		path += "/" + v.ID
		if strings.HasSuffix(name, ".read") {
			if *v.Length > cap.Limits.SessionArtifactReadBytes {
				return invalidArgs()
			}
			path += "/read"
			body = sandbox.SessionArtifactReadRequest{Offset: *v.Offset, Length: *v.Length}
		} else {
			method = "DELETE"
			body = nil
		}
	}
	data, err := s.api.call(bounded, method, path, body)
	if err != nil {
		return failure(err)
	}
	if creating {
		var info sandbox.SessionArtifactInfo
		if decodeStrict(data, &info) != nil || info.ValidateFor(v.Session, v.Path) != nil {
			return toolFailure("protocol_error", "invalid artifact create response")
		}
		return outcome{Data: rawObject(info), Rollback: s.api.rollback("DELETE", path+"/"+info.ID)}
	}
	if method == "POST" {
		var chunk sandbox.SessionArtifactChunk
		if decodeStrict(data, &chunk) != nil || chunk.ValidateFor(v.Session, v.ID, sandbox.SessionArtifactReadRequest{Offset: *v.Offset, Length: *v.Length}) != nil {
			return toolFailure("protocol_error", "invalid artifact chunk response")
		}
		return outcome{Data: rawObject(chunk)}
	}
	var deleted struct {
		Status int `json:"status"`
	}
	if decodeStrict(data, &deleted) != nil || deleted.Status != 204 {
		return toolFailure("protocol_error", "invalid artifact delete response")
	}
	return outcome{Data: rawObject(map[string]any{"session_id": v.Session, "artifact_id": v.ID, "deleted": true})}
}
