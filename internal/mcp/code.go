package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var codeOperations = map[string]string{
	"sandbox.code.context.create": "create", "sandbox.code.context.default": "default",
	"sandbox.code.context.list": "list", "sandbox.code.context.info": "info",
	"sandbox.code.context.restart": "restart", "sandbox.code.context.remove": "remove",
	"sandbox.code.execute": "execute", "sandbox.code.poll": "execution", "sandbox.code.cancel": "cancel",
}

func codeCapable(cap sandbox.CapabilityReport) bool {
	if !cap.ArtifactAuthenticated || !digestPattern.MatchString(cap.ArtifactManifestSHA256) ||
		!cap.Features.Sessions || !cap.Features.CodeContexts || cap.Backend != "firecracker-linux" || (cap.ArtifactManifestProtocol != "osv-sandbox-artifacts/v5" && cap.ArtifactManifestProtocol != "osv-sandbox-artifacts/v6" && cap.ArtifactManifestProtocol != "osv-sandbox-artifacts/v7" && cap.ArtifactManifestProtocol != "osv-sandbox-artifacts/v8") {
		return false
	}
	if cap.CodeRuntime.Validate() != nil {
		return false
	}
	seen := map[string]bool{}
	for _, language := range cap.CodeLanguages {
		if !slices.Contains([]string{"python", "javascript", "typescript"}, language) || seen[language] {
			return false
		}
		seen[language] = true
	}
	return true
}

func codeToolsFor(cap sandbox.CapabilityReport) []tool {
	if !codeCapable(cap) {
		return nil
	}
	identity := func(execution bool) map[string]any {
		props := map[string]any{"session_id": handleSchema(), "context_id": handleSchema(), "generation": integerSchema(1, 1<<53-1)}
		if execution {
			props["execution_id"] = handleSchema()
		}
		return props
	}
	tools := []tool{
		toolDefinition("sandbox.code.context.list", "List this owner's actual code contexts, including transition and failure state.", true, map[string]any{"session_id": handleSchema()}, "session_id"),
		toolDefinition("sandbox.code.context.info", "Observe actual context state/generation. Use idle to confirm readiness and code_not_found to confirm removal; session disappearance is different.", true, map[string]any{"session_id": handleSchema(), "context_id": handleSchema()}, "session_id", "context_id"),
		toolDefinition("sandbox.code.context.remove", "Request removal of the given generation. Accepted is not cleanup completion; observe context.info.", false, identity(false), "session_id", "context_id", "generation"),
		toolDefinition("sandbox.code.cancel", "Request cancellation for this exact execution binding, including a delayed submit. ACK is not terminal proof; continue polling. Never resubmits code.", false, identity(true), "session_id", "context_id", "generation", "execution_id"),
	}
	poll := identity(true)
	poll["after"] = integerSchema(0, 256)
	tools = append(tools, toolDefinition("sandbox.code.poll", "Observe up to 64 journal events without acknowledging/deleting them. Status may be completed before the last page. Handle explicit eviction; binary stdout/stderr are base64, rich results are MIME data.", true, poll, "session_id", "context_id", "generation", "execution_id"))
	if len(cap.CodeLanguages) > 0 {
		language := map[string]any{"type": "string", "enum": append([]string{}, cap.CodeLanguages...)}
		tools = append(tools,
			toolDefinition("sandbox.code.context.create", "Create a context using a caller-known ID and explicit authorized language. Returns actual transition state; poll info until idle. No automatic creation retry or ACK-loss rollback.", false,
				map[string]any{"session_id": handleSchema(), "context_id": handleSchema(), "language": language, "cwd": map[string]any{"type": "string", "maxLength": 1035, "pattern": "^/workspace(?:/|$)"}}, "session_id", "context_id", "language"),
			toolDefinition("sandbox.code.context.default", "Get or initialize the persistent default context for an explicit authorized language. Returns actual state.", false,
				map[string]any{"session_id": handleSchema(), "language": language}, "session_id", "language"),
			toolDefinition("sandbox.code.context.restart", "Request restart of the selected generation only. Observe info until the next generation is idle; ACK is not readiness.", false, identity(false), "session_id", "context_id", "generation"))
		execute := identity(true)
		execute["code"] = map[string]any{"type": "string", "maxLength": 65536}
		execute["environment"] = map[string]any{"type": "object", "maxProperties": 64, "additionalProperties": map[string]any{"type": "string", "maxLength": 8192}}
		execute["timeout_ms"] = integerSchema(0, 300000)
		tools = append(tools, toolDefinition("sandbox.code.execute", "Submit once with known context/generation/execution IDs. Default execution timeout 60000ms; 0 removes it, not the session lease. MCP cancellation or output loss only stops this RPC. Query/cancel the known ID; never replay source after uncertainty.", false, execute, "session_id", "context_id", "generation", "execution_id", "code"))
	}
	return tools
}

type codeToolRequest struct {
	session    string
	command    sandbox.CodeCommand
	context    string
	generation uint64
}

type codeToolProblem struct{ code, message string }

func (e *codeToolProblem) Error() string { return e.message }
func codeProtocol(message string) error {
	return &codeToolProblem{code: "protocol_error", message: message}
}

func parseCodeTool(name string, args json.RawMessage) (codeToolRequest, error) {
	var request codeToolRequest
	op, exists := codeOperations[name]
	fields, ok := object(args)
	if !exists || !ok || json.Unmarshal(fields["session_id"], &request.session) != nil || !handlePattern.MatchString(request.session) {
		return request, errors.New("invalid code arguments")
	}
	delete(fields, "session_id")
	if _, exists := fields["operation"]; exists {
		return request, errors.New("unexpected operation")
	}
	if op == "execution" {
		if json.Unmarshal(fields["context_id"], &request.context) != nil || !handlePattern.MatchString(request.context) ||
			json.Unmarshal(fields["generation"], &request.generation) != nil || request.generation == 0 || request.generation > 1<<53-1 {
			return request, errors.New("invalid execution binding")
		}
		delete(fields, "context_id")
		delete(fields, "generation")
	}
	defaults := map[string]json.RawMessage{}
	switch op {
	case "create":
		defaults["cwd"] = rawObject("/workspace")
	case "execute":
		defaults["environment"], defaults["timeout_ms"] = json.RawMessage(`{}`), json.RawMessage(`60000`)
	case "execution":
		defaults["after"] = json.RawMessage(`0`)
	}
	for key, value := range defaults {
		if _, exists := fields[key]; !exists {
			fields[key] = value
		}
	}
	fields["operation"] = rawObject(op)
	data, err := json.Marshal(fields)
	if err != nil || decodeStrict(data, &request.command) != nil {
		return request, errors.New("invalid code arguments")
	}
	if op != "execution" {
		request.context, request.generation = request.command.ContextID, request.command.Generation
	}
	return request, nil
}

func (a *apiClient) ownerCapabilities(ctx context.Context, session string) (sandbox.CapabilityReport, error) {
	path, err := sessionPath(session)
	if err != nil {
		return sandbox.CapabilityReport{}, err
	}
	data, err := a.call(ctx, "GET", path+"/capabilities", nil)
	if err != nil {
		return sandbox.CapabilityReport{}, err
	}
	var bound sandbox.SessionCapabilityReport
	if decodeStrict(data, &bound) != nil || bound.SessionID != session || !bound.ArtifactAuthenticated ||
		bound.Protocol != "osv-sandbox-capabilities/v1" || bound.Backend == "" || !digestPattern.MatchString(bound.ArtifactManifestSHA256) || bound.AllowedEntrypoints == nil {
		return sandbox.CapabilityReport{}, codeProtocol("invalid owner capability binding")
	}
	return bound.CapabilityReport, nil
}

func codeFailure(err error, request codeToolRequest, attempted bool) outcome {
	base := failure(err)
	var problem *codeToolProblem
	if errors.As(err, &problem) {
		base = toolFailure(problem.code, problem.message)
	}
	var result map[string]json.RawMessage
	_ = json.Unmarshal(base.Data, &result)
	result["session_id"] = rawObject(request.session)
	if request.context != "" {
		result["context_id"] = rawObject(request.context)
	}
	if request.generation != 0 {
		result["generation"] = rawObject(request.generation)
	}
	if request.command.ExecutionID != "" {
		result["execution_id"] = rawObject(request.command.ExecutionID)
	}
	unknown := attempted
	var api *apiFailure
	if errors.As(err, &api) && slices.Contains([]int{400, 403, 404, 409, 410, 429, 501}, api.Status) {
		unknown = false
	}
	result["delivery_unknown"] = rawObject(unknown)
	return outcome{Data: rawObject(result), IsError: true}
}

func (s *Server) callCodeTool(parent context.Context, name string, args json.RawMessage) outcome {
	request, err := parseCodeTool(name, args)
	if err != nil {
		return invalidArgs()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	cap, err := s.api.ownerCapabilities(ctx, request.session)
	if err != nil {
		return codeFailure(err, request, false)
	}
	if !codeCapable(cap) {
		return codeFailure(&codeToolProblem{code: "unsupported", message: "code contexts unsupported by this session template"}, request, false)
	}
	c := request.command
	if (c.Operation == "create" || c.Operation == "default") && !slices.Contains(cap.CodeLanguages, c.Language) {
		return codeFailure(&codeToolProblem{code: "forbidden", message: "code interpreter not authorized"}, request, false)
	}
	path, _ := sessionPath(request.session)
	var knownLanguage string
	if c.Operation == "execute" || c.Operation == "restart" {
		data, e := s.api.call(ctx, "GET", path+"/contexts/"+c.ContextID, nil)
		if e != nil {
			return codeFailure(e, request, false)
		}
		var info sandbox.CodeContext
		if decodeStrict(data, &info) != nil || (sandbox.CodeResponse{Kind: "context", Context: &info}).ValidateForSession(request.session, sandbox.CodeCommand{Operation: "info", ContextID: c.ContextID}) != nil {
			return codeFailure(codeProtocol("invalid code context identity"), request, false)
		}
		knownLanguage = info.Language
		if !slices.Contains(cap.CodeLanguages, info.Language) {
			return codeFailure(&codeToolProblem{code: "forbidden", message: "code interpreter not authorized"}, request, false)
		}
	}
	method, target := "GET", path+"/contexts"
	var body any
	switch c.Operation {
	case "create":
		method, body = "POST", map[string]any{"context_id": c.ContextID, "language": c.Language, "cwd": c.Cwd}
	case "default":
		method, target, body = "POST", path+"/contexts/default", map[string]any{"language": c.Language}
	case "info":
		target += "/" + c.ContextID
	case "restart":
		method, target, body = "POST", target+"/"+c.ContextID+"/restart", map[string]uint64{"generation": c.Generation}
	case "remove":
		method, target = "DELETE", target+"/"+c.ContextID+"?generation="+strconv.FormatUint(c.Generation, 10)
	case "execute":
		method, target, body = "POST", path+"/code-executions", map[string]any{"context_id": c.ContextID, "generation": c.Generation, "execution_id": c.ExecutionID, "code": c.Code, "environment": c.Environment, "timeout_ms": c.TimeoutMS}
	case "execution":
		target = path + "/code-executions/" + c.ExecutionID + "?after=" + strconv.FormatUint(c.After, 10)
	case "cancel":
		method, target = "DELETE", path+"/code-executions/"+c.ExecutionID+"?context_id="+c.ContextID+"&generation="+strconv.FormatUint(c.Generation, 10)
	}
	attempted := method != "GET"
	data, err := s.api.call(ctx, method, target, body)
	if err != nil {
		return codeFailure(err, request, attempted)
	}
	if len(data) > (256<<10)+1024 {
		return codeFailure(codeProtocol("code response exceeds frame budget"), request, attempted)
	}
	response := sandbox.CodeResponse{}
	var resultError bool
	switch c.Operation {
	case "create", "default", "info", "restart":
		var value sandbox.CodeContext
		if decodeStrict(data, &value) != nil || knownLanguage != "" && knownLanguage != value.Language {
			return codeFailure(codeProtocol("invalid code context response"), request, attempted)
		}
		response.Kind, response.Context = "context", &value
		resultError = value.State == "failed"
	case "list":
		var value struct {
			SessionID string                `json:"session_id"`
			Contexts  []sandbox.CodeContext `json:"contexts"`
		}
		if decodeStrict(data, &value) != nil || value.SessionID != request.session {
			return codeFailure(codeProtocol("invalid code context list"), request, false)
		}
		response.Kind, response.Contexts = "contexts", value.Contexts
	case "execution":
		var value sandbox.CodeExecutionPage
		if decodeStrict(data, &value) != nil || value.ContextID != request.context || value.Generation != request.generation {
			return codeFailure(codeProtocol("invalid code execution binding"), request, false)
		}
		response.Kind, response.Execution = "execution", &value
		resultError = value.EventsEvicted || value.Status == "failed" || value.Status == "timed_out" || value.Status == "cancelled"
		for _, event := range value.Events {
			resultError = resultError || event.Event.Type == "error"
		}
	case "execute", "cancel":
		var value struct {
			SessionID   string `json:"session_id"`
			ExecutionID string `json:"execution_id"`
			Accepted    bool   `json:"accepted"`
		}
		if decodeStrict(data, &value) != nil || value.SessionID != request.session || value.ExecutionID != c.ExecutionID || !value.Accepted {
			return codeFailure(codeProtocol("invalid code acceptance"), request, attempted)
		}
		response.Kind = "accepted"
	case "remove":
		var value struct {
			SessionID string `json:"session_id"`
			ContextID string `json:"context_id"`
			Removed   bool   `json:"removed"`
		}
		if decodeStrict(data, &value) != nil || value.SessionID != request.session || value.ContextID != c.ContextID || !value.Removed {
			return codeFailure(codeProtocol("invalid code removal acceptance"), request, true)
		}
		response.Kind = "removed"
	}
	if response.ValidateForSession(request.session, c) != nil {
		return codeFailure(codeProtocol("invalid typed code response"), request, attempted)
	}
	// Known identities and journals survive MCP cancellation or lost output.
	// Preserve RawMessage for both text and structured content, including numbers.
	return outcome{Data: data, IsError: resultError}
}
