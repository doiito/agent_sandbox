package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var handlePattern = regexp.MustCompile(`^[0-9a-f]{24}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations map[string]bool `json:"annotations"`
}
type outcome struct {
	Data     json.RawMessage
	IsError  bool
	Rollback func()
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func textSchema() map[string]any { return map[string]any{"type": "string"} }
func handleSchema() map[string]any {
	return map[string]any{"type": "string", "pattern": handlePattern.String()}
}
func integerSchema(minimum, maximum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": maximum}
}
func toolDefinition(name, description string, readOnly bool, properties map[string]any, required ...string) tool {
	return tool{name, description, objectSchema(properties, required...), map[string]bool{"readOnlyHint": readOnly, "destructiveHint": !readOnly, "openWorldHint": false}}
}
func commandProperties(cap sandbox.CapabilityReport) map[string]any {
	props := map[string]any{"entrypoint": map[string]any{"type": "string", "enum": cap.AllowedEntrypoints}, "args": map[string]any{"type": "array", "maxItems": 64, "items": map[string]any{"type": "string", "maxLength": 4096}}, "timeout_ms": integerSchema(1, cap.Limits.MaxTimeoutMS)}
	if cap.Features.Environment {
		props["environment"] = map[string]any{"type": "object", "maxProperties": 32, "additionalProperties": map[string]any{"type": "string", "maxLength": 1024}}
	}
	if cap.Features.WorkingDirectory {
		props["cwd"] = map[string]any{"type": "string", "maxLength": 1024, "pattern": "^/"}
	}
	return props
}
func toolsFor(cap sandbox.CapabilityReport, catalogs ...*sandbox.TemplateCatalogReport) []tool {
	if len(catalogs) > 0 && catalogs[0] != nil {
		return catalogToolsFor(cap, catalogs[0])
	}
	tools := []tool{toolDefinition("sandbox.capabilities", "Read current tenant-visible API capabilities and resource limits. Optional session_id reads the existing owner's bound contract without re-entering new VM admission; do not combine it with a template selector.", true, map[string]any{"session_id": handleSchema()}), toolDefinition("sandbox.templates", "List actually authenticated templates and entrypoints on this API. No backend fallback.", true, map[string]any{})}
	if cap.Features.NetworkFetch && cap.NetworkFetchPolicy != nil {
		policy := cap.NetworkFetchPolicy
		network := toolDefinition("sandbox.net.fetch", "Fetch HTTP/HTTPS through the tenant-authorized egress service. Inspect capabilities.network_fetch_policy for allowed origins, CIDRs and limits. Binary bodies use base64; redirects require explicit follow_redirects and every hop is checked. This does not enable guest NIC/network access.", false,
			map[string]any{"url": map[string]any{"type": "string", "maxLength": 8192}, "method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}}, "headers": map[string]any{"type": "object", "maxProperties": 32, "additionalProperties": map[string]any{"type": "string", "maxLength": 4096}}, "body_base64": map[string]any{"type": "string", "contentEncoding": "base64", "maxLength": ((policy.MaxRequestBytes + 2) / 3) * 4}, "follow_redirects": map[string]any{"type": "boolean"}, "timeout_ms": integerSchema(100, policy.TimeoutMS)}, "url")
		network.Annotations["openWorldHint"] = true
		tools = append(tools, network)
	}
	if cap.ArtifactAuthenticated && digestPattern.MatchString(cap.ArtifactManifestSHA256) && cap.Features.OneShotJob && len(cap.AllowedEntrypoints) > 0 {
		props := commandProperties(cap)
		if cap.Features.Sessions {
			props["session_id"] = handleSchema()
		}
		props["memory_mib"] = integerSchema(cap.Limits.MinMemoryMiB, cap.Limits.MaxMemoryMiB)
		props["vcpus"] = integerSchema(1, cap.Limits.MaxVCPUs)
		networks := []string{"none"}
		if cap.Features.NetworkEgress {
			networks = append(networks, "proxy")
		}
		props["network"] = map[string]any{"type": "string", "enum": networks}
		props["backend"] = map[string]any{"type": "string", "enum": []string{cap.Backend}}
		props["artifact_manifest_sha256"] = map[string]any{"type": "string", "const": cap.ArtifactManifestSHA256}
		if cap.Features.Stdin {
			props["stdin"] = map[string]any{"type": []string{"string", "null"}, "contentEncoding": "base64", "maxLength": 21848}
		}
		if cap.Features.InputFiles {
			props["input_files"] = map[string]any{"type": "array", "maxItems": 64, "items": objectSchema(map[string]any{"path": textSchema(), "data": map[string]any{"type": "string", "contentEncoding": "base64"}, "mode": map[string]any{"type": "integer", "enum": []int{0, 292}}}, "path", "data")}
		}
		tools = append(tools, toolDefinition("sandbox.exec", "Execute an allowed guest entrypoint once with bounded output. Optional session_id executes synchronously in that session; cancelling synchronous session execution can close the VM. No host execution or network bypass.", false, props, "entrypoint"))
	}
	tools = append(tools, inferenceToolsFor(cap)...)
	if !cap.Features.Sessions {
		return sortedTools(tools)
	}
	tools = append(tools, codeToolsFor(cap)...)
	tools = append(tools, portToolsFor(cap)...)
	tools = append(tools, previewToolsFor(cap)...)
	tools = append(tools, artifactToolsFor(cap)...)
	create := map[string]any{"memory_mib": integerSchema(cap.Limits.MinMemoryMiB, cap.Limits.MaxMemoryMiB), "vcpus": integerSchema(1, cap.Limits.MaxVCPUs), "ttl_ms": integerSchema(1000, cap.Limits.SessionMaxTTLMS), "network": map[string]any{"type": "string", "enum": []string{"none"}}, "backend": map[string]any{"type": "string", "enum": []string{cap.Backend}}, "artifact_manifest_sha256": map[string]any{"type": "string", "const": cap.ArtifactManifestSHA256}, "input_files": map[string]any{"type": "array", "maxItems": 64, "items": objectSchema(map[string]any{"path": textSchema(), "data": map[string]any{"type": "string", "contentEncoding": "base64"}, "mode": map[string]any{"type": "integer", "enum": []int{0, 292}}}, "path", "data")}}
	if cap.Features.NetworkEgress {
		create["network"] = map[string]any{"type": "string", "enum": []string{"none", "proxy"}}
	}
	tools = append(tools, toolDefinition("sandbox.session.create", "Create a tenant-owned VM session. Return its explicit ID; it survives MCP process shutdown until closed or TTL expires.", false, create), toolDefinition("sandbox.session.get", "Get current owner-confirmed session metadata.", true, map[string]any{"session_id": handleSchema()}, "session_id"), toolDefinition("sandbox.session.close", "Destroy this session and all its guest work; release resources.", false, map[string]any{"session_id": handleSchema()}, "session_id"))
	if cap.Features.SessionListing {
		tools = append(tools, toolDefinition("sandbox.session.list", "List only this tenant's live sessions using stable API pagination.", true, map[string]any{"limit": integerSchema(1, 100), "cursor": textSchema(), "order": map[string]any{"type": "string", "enum": []string{"asc", "desc"}}}))
	}
	if cap.Features.SessionTimeoutUpdate {
		tools = append(tools, toolDefinition("sandbox.session.set_timeout", "Reset remaining TTL within the immutable VM lifetime; cannot resurrect expired sessions.", false, map[string]any{"session_id": handleSchema(), "ttl_ms": integerSchema(1000, cap.Limits.SessionMaxTTLMS)}, "session_id", "ttl_ms"))
	}
	if cap.Features.SessionFiles {
		for _, op := range []string{"read", "write", "list", "info", "mkdir", "rename", "remove"} {
			props := map[string]any{"session_id": handleSchema(), "path": map[string]any{"type": "string", "maxLength": 1035, "pattern": "^/workspace(?:/|$)"}}
			required := []string{"session_id", "path"}
			readOnly := op == "read" || op == "list" || op == "info"
			if op == "write" {
				props["data_base64"] = map[string]any{"type": "string", "contentEncoding": "base64", "maxLength": 699052}
				props["metadata"] = map[string]any{"type": "object", "maxProperties": 16, "additionalProperties": textSchema()}
				required = append(required, "data_base64")
			}
			if op == "rename" {
				props["destination"] = textSchema()
				required = append(required, "destination")
			}
			tools = append(tools, toolDefinition("sandbox.fs."+op, "Guest /workspace "+op+" through existing confined API; bytes use base64. No host filesystem access.", readOnly, props, required...))
		}
	}
	if cap.Features.FileWatch {
		props := map[string]any{"session_id": handleSchema(), "path": textSchema(), "recursive": map[string]any{"type": "boolean"}, "include_entry": map[string]any{"type": "boolean"}, "timeout_ms": integerSchema(0, 600000)}
		tools = append(tools, toolDefinition("sandbox.watch.start", "Watch a guest workspace directory. Events are bounded; overflow is explicit. Each watcher has one cursor consumer.", false, props, "session_id", "path"), toolDefinition("sandbox.watch.list", "List this session's bounded watcher history.", true, map[string]any{"session_id": handleSchema()}, "session_id"))
		tools = append(tools, toolDefinition("sandbox.watch.poll", "Read events after a sequence and acknowledge earlier events. Acknowledged events cannot be read again.", false, map[string]any{"session_id": handleSchema(), "watch_id": handleSchema(), "after": integerSchema(0, 2147483647)}, "session_id", "watch_id"), toolDefinition("sandbox.watch.stop", "Stop a directory watcher and release its guest stream.", false, map[string]any{"session_id": handleSchema(), "watch_id": handleSchema()}, "session_id", "watch_id"))
	}
	if cap.Features.BackgroundCommands {
		sessionCap := cap
		sessionCap.Features.Environment = cap.Features.SessionEnvironment
		sessionCap.Features.WorkingDirectory = cap.Features.SessionWorkingDirectory
		props := commandProperties(sessionCap)
		props["session_id"] = handleSchema()
		if cap.Features.InteractiveStdin {
			props["interactive_stdin"] = map[string]any{"type": "boolean"}
		}
		tools = append(tools, toolDefinition("sandbox.commands.start", "Start guest work and return an explicit command ID. Output observation disconnect does not stop it; use cancel or session TTL.", false, props, "session_id", "entrypoint"), toolDefinition("sandbox.commands.list", "List bounded command history for this session.", true, map[string]any{"session_id": handleSchema()}, "session_id"))
		for _, op := range []string{"get", "wait", "cancel"} {
			tools = append(tools, toolDefinition("sandbox.commands."+op, "Guest command "+op+" using its explicit ID; wait only observes and never re-executes.", op != "cancel", map[string]any{"session_id": handleSchema(), "command_id": handleSchema()}, "session_id", "command_id"))
		}
		if cap.Features.InteractiveStdin {
			tools = append(tools, toolDefinition("sandbox.commands.stdin", "Submit one bounded stdin block or EOF and return an API ticket. Never retries an uncertain write; inspect the ticket with stdin_status.", false, map[string]any{"session_id": handleSchema(), "command_id": handleSchema(), "data_base64": map[string]any{"type": "string", "contentEncoding": "base64", "maxLength": 21848}, "close": map[string]any{"type": "boolean"}}, "session_id", "command_id", "data_base64"), toolDefinition("sandbox.commands.stdin_status", "Observe pending/delivered/closed/failed input delivery by ticket sequence; never resubmits bytes.", true, map[string]any{"session_id": handleSchema(), "command_id": handleSchema(), "sequence": integerSchema(1, 256)}, "session_id", "command_id", "sequence"))
		}
	}
	return sortedTools(tools)
}
func sortedTools(tools []tool) []tool {
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools
}
func supported(tools []tool, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}
func rawObject(value any) json.RawMessage { data, _ := json.Marshal(value); return data }
func toolFailure(code, message string) outcome {
	return outcome{Data: rawObject(map[string]any{"error": map[string]any{"code": code, "message": message}}), IsError: true}
}
func failure(err error) outcome {
	var api *apiFailure
	if errors.As(err, &api) {
		return outcome{Data: rawObject(map[string]any{"error": map[string]any{"code": api.Code, "status": api.Status, "message": api.Error()}}), IsError: true}
	}
	return toolFailure("operation_failed", err.Error())
}
func configFrom(cap sandbox.CapabilityReport) sandbox.Config {
	c := sandbox.Config{Backend: cap.Backend, AllowedEntrypoints: cap.AllowedEntrypoints, Limits: sandbox.Limits{MaxConcurrent: cap.Limits.MaxConcurrent, MinMemoryMiB: cap.Limits.MinMemoryMiB, MaxMemoryMiB: cap.Limits.MaxMemoryMiB, MaxVCPUs: cap.Limits.MaxVCPUs, MaxTimeoutMS: cap.Limits.MaxTimeoutMS, MaxOutputByte: cap.Limits.MaxOutputBytes}, SessionMaxLifetimeMS: cap.Limits.SessionMaxLifetimeMS}
	c.ApplyDefaults()
	c.Defaults.MemoryMiB = c.Limits.MinMemoryMiB
	c.Defaults.VCPUs = 1
	c.Defaults.TimeoutMS = min(30000, c.Limits.MaxTimeoutMS)
	return c
}
func selector(cap sandbox.CapabilityReport, backend, digest *string) error {
	if !cap.ArtifactAuthenticated || !digestPattern.MatchString(cap.ArtifactManifestSHA256) {
		return errors.New("no authenticated template available")
	}
	if (*backend != "" && *backend != cap.Backend) || (*digest != "" && *digest != cap.ArtifactManifestSHA256) {
		return errors.New("requested template differs from current authenticated template")
	}
	*backend, *digest = cap.Backend, cap.ArtifactManifestSHA256
	return nil
}

type handles struct {
	SessionID string `json:"session_id"`
	CommandID string `json:"command_id,omitempty"`
}

func sessionPath(id string) (string, error) {
	if !handlePattern.MatchString(id) {
		return "", errors.New("invalid session_id")
	}
	return "/v2/sessions/" + id, nil
}
func commandPath(h handles) (string, error) {
	p, err := sessionPath(h.SessionID)
	if err != nil {
		return "", err
	}
	if !handlePattern.MatchString(h.CommandID) {
		return "", errors.New("invalid command_id")
	}
	return p + "/commands/" + h.CommandID, nil
}
func invalidArgs() outcome { return toolFailure("invalid_arguments", "invalid tool arguments") }
func (a *apiClient) rollback(method, path string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = a.call(ctx, method, path, nil)
	}
}

func (s *Server) callTool(ctx context.Context, name string, args json.RawMessage, cap sandbox.CapabilityReport, catalogs ...*sandbox.TemplateCatalogReport) outcome {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	if artifactOperations[name] {
		return s.callArtifactTool(ctx, name, args)
	}
	if strings.HasPrefix(name, "sandbox.code.") {
		return s.callCodeTool(ctx, name, args)
	}
	if inferenceOperations[name] {
		return s.callInferenceTool(ctx, name, args)
	}
	if portOperations[name] {
		return s.callPortTool(ctx, name, args)
	}
	if previewOperations[name] {
		return s.callPreviewTool(ctx, name, args)
	}
	if name == "sandbox.capabilities" {
		fields, ok := object(args)
		if ok {
			if _, hasOwner := fields["session_id"]; hasOwner {
				var value struct {
					SessionID string `json:"session_id"`
				}
				if decodeStrict(args, &value) != nil || !handlePattern.MatchString(value.SessionID) {
					return invalidArgs()
				}
				bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				bound, err := s.api.ownerCapabilities(bounded, value.SessionID)
				if err != nil {
					return failure(err)
				}
				return outcome{Data: rawObject(sandbox.SessionCapabilityReport{SessionID: value.SessionID, CapabilityReport: bound})}
			}
		}
	}
	var data json.RawMessage
	var err error
	var catalog *sandbox.TemplateCatalogReport
	if len(catalogs) > 0 {
		catalog = catalogs[0]
	}
	if catalog != nil {
		cap, err = s.selectedToolCapability(ctx, name, args, cap, catalog)
		if err != nil {
			return failure(err)
		}
	}
	switch name {
	case "sandbox.net.fetch":
		var request sandbox.NetworkFetchRequest
		if decodeStrict(args, &request) != nil || request.URL == "" {
			return invalidArgs()
		}
		data, err = s.api.call(ctx, "POST", "/v2/net/fetch", request)
		if err == nil {
			var result sandbox.NetworkFetchResult
			if json.Unmarshal(data, &result) != nil || result.Protocol != "osv-sandbox-network-fetch/v1" || result.Status < 100 || result.Status > 599 {
				return toolFailure("protocol_error", "invalid network fetch result")
			}
			return outcome{Data: data, IsError: result.Status >= 400}
		}
	case "sandbox.capabilities":
		var value sandbox.TemplateSelector
		if decodeStrict(args, &value) != nil {
			return invalidArgs()
		}
		if catalog == nil && (value.Backend != "" || value.ArtifactManifestSHA256 != "") {
			if err := selector(cap, &value.Backend, &value.ArtifactManifestSHA256); err != nil {
				return failure(err)
			}
		}
		return outcome{Data: rawObject(cap)}
	case "sandbox.templates":
		var empty struct{}
		if decodeStrict(args, &empty) != nil {
			return invalidArgs()
		}
		templates := []any{}
		if catalog != nil {
			for _, entry := range catalog.Templates {
				one := entry.Capabilities
				templates = append(templates, map[string]any{"id": entry.ID, "available": entry.Available, "unavailable_code": entry.UnavailableCode, "backend": one.Backend, "artifact_manifest_sha256": one.ArtifactManifestSHA256, "allowed_entrypoints": one.AllowedEntrypoints, "features": one.Features, "limits": one.Limits, "code_runtime": one.CodeRuntime, "code_languages": one.CodeLanguages})
			}
			return outcome{Data: rawObject(map[string]any{"templates": templates, "default_template_id": catalog.DefaultTemplateID})}
		}
		if cap.ArtifactAuthenticated && digestPattern.MatchString(cap.ArtifactManifestSHA256) {
			templates = append(templates, map[string]any{"backend": cap.Backend, "artifact_manifest_sha256": cap.ArtifactManifestSHA256, "allowed_entrypoints": cap.AllowedEntrypoints, "features": cap.Features, "limits": cap.Limits})
		}
		return outcome{Data: rawObject(map[string]any{"templates": templates})}
	case "sandbox.exec":
		var value struct {
			sandbox.RunRequest
			SessionID string `json:"session_id,omitempty"`
		}
		if decodeStrict(args, &value) != nil || value.Entrypoint == "" {
			return invalidArgs()
		}
		if err = selector(cap, &value.Backend, &value.ArtifactManifestSHA256); err != nil {
			return failure(err)
		}
		if value.Environment != nil && !cap.Features.Environment || value.Stdin != nil && !cap.Features.Stdin || value.Cwd != "" && !cap.Features.WorkingDirectory || len(value.InputFiles) > 0 && !cap.Features.InputFiles {
			return toolFailure("unsupported", "execution option is not supported by this template")
		}
		normalized := value.RunRequest
		normalized.Normalize(configFrom(cap))
		if normalized.Network == "proxy" && !cap.Features.NetworkEgress {
			return toolFailure("unsupported", "guest proxy is unavailable for this tenant")
		}
		if err = normalized.ValidateArguments(configFrom(cap)); err != nil {
			return failure(err)
		}
		if value.SessionID != "" {
			if !cap.Features.Sessions || value.Stdin != nil || value.MemoryMiB != 0 || value.VCPUs != 0 || len(value.InputFiles) > 0 || (value.Network != "" && value.Network != "none") {
				return toolFailure("invalid_arguments", "session exec cannot change resources/network or provide fixed stdin/input files")
			}
			path, e := sessionPath(value.SessionID)
			if e != nil {
				return failure(e)
			}
			body := sandbox.SessionCommandRequest{Entrypoint: value.Entrypoint, Args: value.Args, Environment: value.Environment, Cwd: value.Cwd, TimeoutMS: value.TimeoutMS}
			data, err = s.api.call(ctx, "POST", path+"/commands", body)
		} else {
			data, err = s.api.call(ctx, "POST", "/v2/jobs", value.RunRequest)
		}
		if err == nil {
			var result struct {
				State      string `json:"state"`
				ProtocolOK bool   `json:"protocol_ok"`
				Result     *struct {
					State      string `json:"state"`
					ProtocolOK bool   `json:"protocol_ok"`
				} `json:"result"`
			}
			if json.Unmarshal(data, &result) != nil {
				return toolFailure("protocol_error", "invalid execution result")
			}
			ok := result.State == "succeeded" && result.ProtocolOK
			if result.Result != nil {
				ok = result.Result.State == "succeeded" && result.Result.ProtocolOK
			}
			return outcome{Data: data, IsError: !ok}
		}
	case "sandbox.session.create":
		var value sandbox.SessionCreateRequest
		if decodeStrict(args, &value) != nil {
			return invalidArgs()
		}
		if err = selector(cap, &value.Backend, &value.ArtifactManifestSHA256); err != nil {
			return failure(err)
		}
		copy := value
		copy.Normalize(configFrom(cap))
		if copy.Network == "proxy" && !cap.Features.NetworkEgress {
			return toolFailure("unsupported", "guest proxy is unavailable for this tenant")
		}
		if err = copy.ValidateArguments(configFrom(cap)); err != nil {
			return failure(err)
		}
		data, err = s.api.call(ctx, "POST", "/v2/sessions", value)
		if err == nil {
			var info sandbox.SessionInfo
			if json.Unmarshal(data, &info) != nil || !handlePattern.MatchString(info.ID) {
				return toolFailure("protocol_error", "invalid created session identity")
			}
			return outcome{Data: data, Rollback: s.api.rollback("DELETE", "/v2/sessions/"+info.ID)}
		}
	case "sandbox.session.get", "sandbox.session.close":
		var value struct {
			SessionID string `json:"session_id"`
		}
		if decodeStrict(args, &value) != nil {
			return invalidArgs()
		}
		path, e := sessionPath(value.SessionID)
		if e != nil {
			return failure(e)
		}
		method := "GET"
		if name == "sandbox.session.close" {
			method = "DELETE"
		}
		data, err = s.api.call(ctx, method, path, nil)
	case "sandbox.session.set_timeout":
		var value struct {
			SessionID string `json:"session_id"`
			TTLMS     int    `json:"ttl_ms"`
		}
		if decodeStrict(args, &value) != nil || value.TTLMS < 1000 || value.TTLMS > cap.Limits.SessionMaxTTLMS {
			return invalidArgs()
		}
		path, e := sessionPath(value.SessionID)
		if e != nil {
			return failure(e)
		}
		data, err = s.api.call(ctx, "POST", path+"/timeout", map[string]int{"ttl_ms": value.TTLMS})
	case "sandbox.session.list":
		var value struct {
			Limit  int    `json:"limit,omitempty"`
			Cursor string `json:"cursor,omitempty"`
			Order  string `json:"order,omitempty"`
		}
		if decodeStrict(args, &value) != nil || value.Limit < 0 || value.Limit > 100 || len(value.Cursor) > 128 || value.Order != "" && value.Order != "asc" && value.Order != "desc" {
			return invalidArgs()
		}
		query := url.Values{}
		if value.Limit > 0 {
			query.Set("limit", strconv.Itoa(value.Limit))
		}
		if value.Cursor != "" {
			query.Set("cursor", value.Cursor)
		}
		if value.Order != "" {
			query.Set("order", value.Order)
		}
		data, err = s.api.call(ctx, "GET", "/v2/sessions?"+query.Encode(), nil)
	default:
		if strings.HasPrefix(name, "sandbox.watch.") {
			return s.callWatchTool(ctx, name, args, cap)
		} else if strings.HasPrefix(name, "sandbox.fs.") {
			var value struct {
				SessionID   string            `json:"session_id"`
				Path        string            `json:"path"`
				Destination *string           `json:"destination,omitempty"`
				DataBase64  *string           `json:"data_base64,omitempty"`
				Metadata    map[string]string `json:"metadata,omitempty"`
			}
			if decodeStrict(args, &value) != nil {
				return invalidArgs()
			}
			path, e := sessionPath(value.SessionID)
			if e != nil {
				return failure(e)
			}
			action := strings.TrimPrefix(name, "sandbox.fs.")
			body := sandbox.SessionFileRequest{Action: action, Path: value.Path, Destination: value.Destination, DataBase64: value.DataBase64, Metadata: value.Metadata}
			if e = body.Validate(); e != nil {
				return failure(e)
			}
			data, err = s.api.call(ctx, "POST", path+"/files", body)
		} else if name == "sandbox.commands.start" {
			var value struct {
				sandbox.SessionCommandRequest
				SessionID string `json:"session_id"`
			}
			if decodeStrict(args, &value) != nil || value.Entrypoint == "" {
				return invalidArgs()
			}
			if value.InteractiveStdin && !cap.Features.InteractiveStdin {
				return toolFailure("unsupported", "interactive stdin is not available")
			}
			if value.Environment != nil && !cap.Features.SessionEnvironment || value.Cwd != "" && !cap.Features.SessionWorkingDirectory {
				return toolFailure("unsupported", "session execution option is not supported")
			}
			path, e := sessionPath(value.SessionID)
			if e != nil {
				return failure(e)
			}
			infoRaw, e := s.api.call(ctx, "GET", path, nil)
			if e != nil {
				return failure(e)
			}
			var info sandbox.SessionInfo
			if json.Unmarshal(infoRaw, &info) != nil || info.ID != value.SessionID || info.State != "running" {
				return toolFailure("protocol_error", "invalid current session metadata")
			}
			check := value.SessionCommandRequest
			check.Normalize(configFrom(cap))
			if e = check.Validate(configFrom(cap), info.MemoryMiB, info.VCPUs); e != nil {
				return failure(e)
			}
			data, err = s.api.call(ctx, "POST", path+"/commands/start", value.SessionCommandRequest)
			if err == nil {
				var info struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(data, &info) != nil || !handlePattern.MatchString(info.ID) {
					return toolFailure("protocol_error", "invalid created command identity")
				}
				return outcome{Data: data, Rollback: s.api.rollback("DELETE", path+"/commands/"+info.ID)}
			}
		} else if name == "sandbox.commands.list" {
			var value struct {
				SessionID string `json:"session_id"`
			}
			if decodeStrict(args, &value) != nil {
				return invalidArgs()
			}
			path, e := sessionPath(value.SessionID)
			if e != nil {
				return failure(e)
			}
			data, err = s.api.call(ctx, "GET", path+"/commands", nil)
		} else if name == "sandbox.commands.stdin" {
			var value struct {
				SessionID  string  `json:"session_id"`
				CommandID  string  `json:"command_id"`
				DataBase64 *string `json:"data_base64"`
				Close      bool    `json:"close,omitempty"`
			}
			if decodeStrict(args, &value) != nil || value.DataBase64 == nil || len(*value.DataBase64) > 21848 {
				return invalidArgs()
			}
			path, e := commandPath(handles{value.SessionID, value.CommandID})
			if e != nil {
				return failure(e)
			}
			data, err = s.api.call(ctx, "POST", path+"/stdin", map[string]any{"data_base64": *value.DataBase64, "close": value.Close})
		} else if name == "sandbox.commands.stdin_status" {
			var value struct {
				SessionID string `json:"session_id"`
				CommandID string `json:"command_id"`
				Sequence  int    `json:"sequence"`
			}
			if decodeStrict(args, &value) != nil || value.Sequence < 1 || value.Sequence > 256 {
				return invalidArgs()
			}
			path, e := commandPath(handles{value.SessionID, value.CommandID})
			if e != nil {
				return failure(e)
			}
			data, err = s.api.call(ctx, "GET", path+"/stdin/"+strconv.Itoa(value.Sequence), nil)
		} else {
			var value handles
			if decodeStrict(args, &value) != nil {
				return invalidArgs()
			}
			path, e := commandPath(value)
			if e != nil {
				return failure(e)
			}
			method := "GET"
			if name == "sandbox.commands.cancel" {
				method = "DELETE"
			}
			for {
				data, err = s.api.call(ctx, method, path, nil)
				if err != nil || name != "sandbox.commands.wait" {
					break
				}
				var poll struct {
					Info struct {
						State string `json:"state"`
					} `json:"info"`
				}
				if json.Unmarshal(data, &poll) != nil || poll.Info.State == "" {
					return toolFailure("protocol_error", "invalid command observation")
				}
				if poll.Info.State != "starting" && poll.Info.State != "running" && poll.Info.State != "cancelling" {
					break
				}
				select {
				case <-ctx.Done():
					return failure(ctx.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
	}
	if err != nil {
		return failure(err)
	}
	if name == "sandbox.commands.wait" {
		var value struct {
			Info struct {
				State string `json:"state"`
			} `json:"info"`
		}
		if json.Unmarshal(data, &value) != nil {
			return toolFailure("protocol_error", "invalid command result")
		}
		return outcome{Data: data, IsError: value.Info.State != "succeeded"}
	}
	return outcome{Data: data}
}

func callResult(value outcome) map[string]any {
	if len(value.Data) == 0 {
		value = toolFailure("protocol_error", "empty tool result")
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(value.Data)}}, "structuredContent": value.Data, "isError": value.IsError}
}
