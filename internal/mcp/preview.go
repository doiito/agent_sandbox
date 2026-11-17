package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var previewOperations = map[string]bool{"sandbox.preview.create": true, "sandbox.preview.info": true, "sandbox.preview.revoke": true}

func previewToolsFor(cap sandbox.CapabilityReport) []tool {
	if !portCapable(cap) || !cap.Features.PortPreview {
		return nil
	}
	identity := func() map[string]any {
		return map[string]any{"session_id": handleSchema(), "preview_id": handleSchema(), "port": integerSchema(1, 65535)}
	}
	required := []string{"session_id", "preview_id", "port"}
	create := identity()
	create["ttl_ms"] = integerSchema(1000, 300000)
	return []tool{
		toolDefinition("sandbox.preview.create", "Create one session-owned browser grant, default TTL 300000ms capped by the VM lease. Returns a single-use bootstrap_url. Never replay an uncertain create; query/revoke the known ID. Survives MCP exit; no automatic rollback on RPC cancellation.", false, create, required...),
		toolDefinition("sandbox.preview.info", "Query a known browser grant without new admission discovery. Does not reissue the bootstrap secret or extend TTL.", true, identity(), required...),
		toolDefinition("sandbox.preview.revoke", "Revoke a known browser authorization independently of new admission. Does not assert physical guest connection cleanup.", false, identity(), required...),
	}
}

type previewToolRequest struct {
	Session string  `json:"session_id"`
	ID      string  `json:"preview_id"`
	Port    uint16  `json:"port"`
	TTL     *uint64 `json:"ttl_ms,omitempty"`
}

func parsePreviewTool(name string, args json.RawMessage) (previewToolRequest, error) {
	var value previewToolRequest
	fields, ok := object(args)
	if !previewOperations[name] || !ok || decodeStrict(args, &value) != nil || !handlePattern.MatchString(value.Session) || !handlePattern.MatchString(value.ID) || value.Port == 0 ||
		(value.TTL != nil && (name != "sandbox.preview.create" || *value.TTL < 1000 || *value.TTL > 300000)) {
		return value, errors.New("invalid preview arguments")
	}
	if _, present := fields["ttl_ms"]; present && value.TTL == nil {
		return value, errors.New("invalid preview TTL")
	}
	return value, nil
}

func previewToolFailure(err error, value previewToolRequest, uncertain bool) outcome {
	base := failure(err)
	var data map[string]json.RawMessage
	_ = json.Unmarshal(base.Data, &data)
	data["session_id"], data["preview_id"], data["port"] = rawObject(value.Session), rawObject(value.ID), rawObject(value.Port)
	data["outcome_uncertain"] = rawObject(uncertain)
	base.Data = rawObject(data)
	return base
}

func (s *Server) callPreviewTool(ctx context.Context, name string, args json.RawMessage) outcome {
	value, err := parsePreviewTool(name, args)
	if err != nil {
		return invalidArgs()
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	creating := name == "sandbox.preview.create"
	method := "GET"
	path := fmt.Sprintf("/v2/sessions/%s/previews/%s", value.Session, value.ID)
	var body any
	if creating {
		cap, e := s.api.ownerCapabilities(bounded, value.Session)
		if e != nil {
			return previewToolFailure(e, value, false)
		}
		if !portCapable(cap) || !cap.Features.PortPreview {
			return previewToolFailure(errors.New("authenticated preview unsupported by session"), value, false)
		}
		method, path = "POST", fmt.Sprintf("/v2/sessions/%s/ports/%d/previews/%s", value.Session, value.Port, value.ID)
		ttl := uint64(300000)
		if value.TTL != nil {
			ttl = *value.TTL
		}
		body = map[string]uint64{"ttl_ms": ttl}
	} else if name == "sandbox.preview.revoke" {
		method = "DELETE"
	}
	data, e := s.api.call(bounded, method, path, body)
	if e != nil {
		return previewToolFailure(e, value, method != "GET")
	}
	var info sandbox.PreviewGrantInfo
	fields, ok := object(data)
	fieldCount := 8
	if creating {
		fieldCount++
	}
	_, hasBootstrap := fields["bootstrap_url"]
	if !ok || len(fields) != fieldCount || hasBootstrap != creating || decodeStrict(data, &info) != nil || info.ValidateFor(value.Session, value.ID, value.Port, creating) != nil || (method == "DELETE" && info.Status == "active") {
		return previewToolFailure(errors.New("invalid preview control proof"), value, method != "GET")
	}
	// Grants belong to the API session, not this MCP connection. In particular,
	// never Rollback a successful or uncertain create after an RPC cancellation.
	return outcome{Data: rawObject(info)}
}
