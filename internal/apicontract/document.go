package apicontract

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type route struct {
	pattern, handler, operation string
	request, response           any
	status                      int
	query                       []any
}

func query(name string, schema object, required bool) any {
	return object{"name": name, "in": "query", "required": required, "schema": schema}
}

func routes() []route {
	cursor := []any{query("after", integer(0, 256), false)}
	generation := query("generation", integer(1, 1<<53-1), true)
	return []route{
		{"GET /healthz", "health", "health", nil, sandbox.StatusResponse{}, 200, nil},
		{"GET /readyz", "ready", "readiness", nil, sandbox.StatusResponse{}, 200, nil},
		{"GET /metrics", "prometheus", "prometheusMetrics", nil, nil, 200, nil},
		{"GET /v1/doctor", "doctor", "hostDoctor", nil, sandbox.DoctorReport{}, 200, nil},
		{"GET /v1/capabilities", "capabilities", "capabilities", nil, sandbox.CapabilityReport{}, 200,
			[]any{query("backend", stringSchema(), false), query("artifact_manifest_sha256", digestSchema(), false)}},
		{"GET /v2/templates", "templates", "templateCatalog", nil, sandbox.TemplateCatalogReport{}, 200, nil},
		{"POST /v1/jobs", "run", "runLegacyJob", sandbox.RunRequest{}, sandbox.RunResult{}, 200, nil},
		{"POST /v2/jobs", "runV2", "runJob", sandbox.RunRequest{}, sandbox.RunResult{}, 200, nil},
		{"POST /v2/net/fetch", "networkFetch", "networkFetch", sandbox.NetworkFetchRequest{}, sandbox.NetworkFetchResult{}, 200, nil},
		{"POST /v2/sessions/{id}/ml/invocations", "invokeSessionInference", "invokeInference", sandbox.InferenceInvokeRequest{}, sandbox.InferenceInvokeResult{}, 200, nil},
		{"GET /v2/ml/bills/{task}", "getInferenceBill", "inferenceBill", nil, sandbox.InferenceBill{}, 200, nil},
		{"POST /v2/sessions", "createSession", "createSession", sandbox.SessionCreateRequest{}, sandbox.SessionInfo{}, 201, nil},
		{"GET /v2/sessions", "listSessions", "listSessions", nil, sandbox.SessionListPage{}, 200,
			[]any{query("limit", object{"type": "integer", "minimum": 1, "maximum": 100, "default": 20}, false), query("order", object{"type": "string", "enum": []string{"asc", "desc"}, "default": "desc"}, false), query("cursor", object{"type": "string", "maxLength": 128, "description": "Opaque base64url cursor; preserve order and tenant between pages."}, false)}},
		{"POST /v2/sessions/{id}/timeout", "setSessionTimeout", "setSessionTimeout", sandbox.SessionTimeoutRequest{}, sandbox.SessionInfo{}, 200, nil},
		{"GET /v2/sessions/{id}", "getSession", "getSession", nil, sandbox.SessionInfo{}, 200, nil},
		{"POST /v2/sessions/{id}/commands", "runSessionCommand", "runSessionCommand", sandbox.SessionCommandRequest{}, sandbox.SessionCommandResult{}, 200, nil},
		{"POST /v2/sessions/{id}/commands/start", "startSessionCommand", "startSessionCommand", sandbox.SessionCommandRequest{}, sandbox.SessionCommandInfo{}, 202, nil},
		{"GET /v2/sessions/{id}/commands", "listSessionCommands", "listSessionCommands", nil, sandbox.SessionCommandsResponse{}, 200, nil},
		{"GET /v2/sessions/{id}/commands/{command}", "pollSessionCommand", "pollSessionCommand", nil, sandbox.SessionCommandPage{}, 200, cursor},
		{"DELETE /v2/sessions/{id}/commands/{command}", "cancelSessionCommand", "cancelSessionCommand", nil, sandbox.CommandCancelResponse{}, 200, nil},
		{"GET /v2/sessions/{id}/commands/{command}/events", "streamSessionCommand", "streamSessionCommand", nil, nil, 200,
			[]any{query("after", integer(0, 256), false), query("timeout_ms", integer(0, 86400000), false)}},
		{"POST /v2/sessions/{id}/commands/{command}/stdin", "submitCommandInput", "submitCommandInput", sandbox.SessionCommandInputRequest{}, sandbox.SessionCommandInputReceipt{}, 202, nil},
		{"GET /v2/sessions/{id}/commands/{command}/stdin/{sequence}", "pollCommandInput", "pollCommandInput", nil, sandbox.SessionCommandInputReceipt{}, 200, nil},
		{"POST /v2/sessions/{id}/files", "sessionFile", "sessionFile", sandbox.SessionFileRequest{}, sandbox.SessionFileResult{}, 200, nil},
		{"POST /v2/sessions/{id}/artifacts", "createSessionArtifact", "createSessionArtifact", sandbox.SessionArtifactCreateRequest{}, sandbox.SessionArtifactInfo{}, 201, nil},
		{"POST /v2/sessions/{id}/artifacts/{artifact}/read", "readSessionArtifact", "readSessionArtifact", sandbox.SessionArtifactReadRequest{}, sandbox.SessionArtifactChunk{}, 200, nil},
		{"DELETE /v2/sessions/{id}/artifacts/{artifact}", "deleteSessionArtifact", "deleteSessionArtifact", nil, nil, 204, nil},
		{"GET /v2/sessions/{id}/capabilities", "sessionCapabilities", "sessionCapabilities", nil, sandbox.SessionCapabilityReport{}, 200, nil},
		{"POST /v2/sessions/{id}/watches", "startSessionWatch", "startSessionWatch", sandbox.SessionWatchRequest{}, sandbox.SessionWatchInfo{}, 201, nil},
		{"POST /v2/sessions/{id}/ports/{port}/connections/{connection}", "openPortTunnel", "openPortTunnel", sandbox.SessionPortLimits{}, nil, 101, nil},
		{"GET /v2/sessions/{id}/ports/{port}/connections/{connection}", "getPortConnection", "getPortConnection", nil, sandbox.PortConnectionResponse{}, 200, nil},
		{"DELETE /v2/sessions/{id}/ports/{port}/connections/{connection}", "cancelPortConnection", "cancelPortConnection", nil, sandbox.PortConnectionResponse{}, 202, nil},
		{"POST /v2/sessions/{id}/ports/{port}/previews/{preview}", "createPreview", "createPreview", sandbox.PreviewCreateRequest{}, sandbox.PreviewGrantInfo{}, 201, nil},
		{"GET /v2/sessions/{id}/previews/{preview}", "getPreview", "getPreview", nil, sandbox.PreviewGrantInfo{}, 200, nil},
		{"DELETE /v2/sessions/{id}/previews/{preview}", "revokePreview", "revokePreview", nil, sandbox.PreviewGrantInfo{}, 200, nil},
		{"POST /v2/sessions/{id}/contexts", "createCodeContext", "createCodeContext", sandbox.CodeContextCreateRequest{}, sandbox.CodeContext{}, 201, nil},
		{"POST /v2/sessions/{id}/contexts/default", "defaultCodeContext", "defaultCodeContext", sandbox.CodeContextDefaultRequest{}, sandbox.CodeContext{}, 200, nil},
		{"GET /v2/sessions/{id}/contexts", "listCodeContexts", "listCodeContexts", nil, sandbox.CodeContextsResponse{}, 200, nil},
		{"GET /v2/sessions/{id}/contexts/{context}", "getCodeContext", "getCodeContext", nil, sandbox.CodeContext{}, 200, nil},
		{"POST /v2/sessions/{id}/contexts/{context}/restart", "restartCodeContext", "restartCodeContext", sandbox.CodeContextRestartRequest{}, sandbox.CodeContext{}, 202, nil},
		{"DELETE /v2/sessions/{id}/contexts/{context}", "removeCodeContext", "removeCodeContext", nil, sandbox.CodeContextRemovedResponse{}, 202, []any{generation}},
		{"POST /v2/sessions/{id}/code-executions", "submitCodeExecution", "submitCodeExecution", sandbox.CodeExecutionRequest{}, sandbox.CodeExecutionPage{}, 202, nil},
		{"GET /v2/sessions/{id}/code-executions/{execution}", "getCodeExecution", "getCodeExecution", nil, sandbox.CodeExecutionPage{}, 200, cursor},
		{"DELETE /v2/sessions/{id}/code-executions/{execution}", "cancelCodeExecution", "cancelCodeExecution", nil, sandbox.CodeExecutionAcceptedResponse{}, 202,
			[]any{query("context_id", identifier(), true), generation}},
		{"GET /v2/sessions/{id}/watches", "listSessionWatches", "listSessionWatches", nil, sandbox.SessionWatchesResponse{}, 200, nil},
		{"GET /v2/sessions/{id}/watches/{watch}", "pollSessionWatch", "pollSessionWatch", nil, sandbox.SessionWatchPage{}, 200, []any{query("after", integer(0, 1<<31-1), false)}},
		{"DELETE /v2/sessions/{id}/watches/{watch}", "stopSessionWatch", "stopSessionWatch", nil, sandbox.WatchStopResponse{}, 200, nil},
		{"DELETE /v2/sessions/{id}", "deleteSession", "deleteSession", nil, nil, 204, nil},
	}
}

// SourceRoutes reads only actual register calls. Contract maintenance cannot
// silently remove a route or point an operation at a different handler.
func SourceRoutes(source string) (map[string]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	var invalid error
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, ok := call.Fun.(*ast.Ident)
		if !ok || callee.Name != "register" {
			return true
		}
		if len(call.Args) != 2 {
			invalid = fmt.Errorf("unsupported route registration")
			return false
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			invalid = fmt.Errorf("route pattern must be an explicit string")
			return false
		}
		pattern, unquoteErr := strconv.Unquote(literal.Value)
		handler, ok := call.Args[1].(*ast.SelectorExpr)
		if unquoteErr != nil || !ok {
			invalid = fmt.Errorf("route handler must be an explicit API method")
			return false
		}
		if _, duplicate := result[pattern]; duplicate {
			invalid = fmt.Errorf("duplicate route %s", pattern)
		}
		result[pattern] = handler.Sel.Name
		return false
	})
	if invalid != nil || len(result) == 0 {
		return nil, fmt.Errorf("read route registrations: %v", invalid)
	}
	return result, nil
}

// Generate checks the real router and returns deterministic standalone JSON.
func Generate(root string) ([]byte, error) { return generateSafely(root) }

func generate(root string) ([]byte, error) {
	source, err := SourceRoutes(filepath.Join(root, "internal/sandbox/http.go"))
	if err != nil {
		return nil, err
	}
	definitions := routes()
	if len(source) != len(definitions) {
		return nil, fmt.Errorf("route denominator changed: source=%d contract=%d", len(source), len(definitions))
	}
	b := newSchemaBuilder()
	paths, operations := object{}, map[string]bool{}
	for _, route := range definitions {
		if source[route.pattern] != route.handler {
			return nil, fmt.Errorf("route/handler missing or changed: %s => %s", route.pattern, route.handler)
		}
		if operations[route.operation] {
			return nil, fmt.Errorf("duplicate operationId %s", route.operation)
		}
		operations[route.operation] = true
		method, path, _ := strings.Cut(route.pattern, " ")
		operation := object{"operationId": route.operation, "summary": route.operation,
			"x-go-handler": route.handler, "x-capabilities-required": "Actual signed template, tenant policy, live service state and limits must permit the operation."}
		params := append([]any{}, route.query...)
		for _, match := range regexp.MustCompile(`\{([^}]+)\}`).FindAllStringSubmatch(path, -1) {
			var schema object
			switch match[1] {
			case "port":
				schema = object{"type": "integer", "minimum": 1, "maximum": 65535, "description": "Canonical decimal without a leading zero; port 3128 is reserved and denied."}
			case "sequence":
				schema = integer(1, 256)
			default:
				schema = identifier()
			}
			params = append(params, object{"name": match[1], "in": "path", "required": true, "schema": schema})
		}
		if len(params) > 0 {
			operation["parameters"] = params
		}
		if route.request != nil {
			schema := b.ref(route.request, true)
			if route.operation == "runJob" {
				base := b.components["RunRequestInput"].(object)
				data, _ := json.Marshal(base)
				var explicit object
				_ = json.Unmarshal(data, &explicit)
				require(explicit, "entrypoint", "backend", "artifact_manifest_sha256")
				p := explicit["properties"].(map[string]any)
				p["entrypoint"], p["backend"], p["artifact_manifest_sha256"] = object{"type": "string", "minLength": 1}, object{"type": "string", "minLength": 1}, digestSchema()
				b.components["RunRequestV2Input"] = explicit
				schema = object{"$ref": "#/components/schemas/RunRequestV2Input"}
			}
			operation["requestBody"] = object{"required": true, "content": object{"application/json": object{"schema": schema}}}
			operation["x-max-request-bytes"] = 1 << 20
		}
		failure := b.ref(sandbox.APIErrorResponse{}, false)
		if strings.HasPrefix(path, "/v1/") || !strings.HasPrefix(path, "/v2/") {
			failure = object{"anyOf": []any{b.ref(sandbox.LegacyAPIErrorResponse{}, false), failure}}
		}
		if route.operation == "invokeInference" || route.operation == "inferenceBill" {
			failure = object{"anyOf": []any{b.ref(sandbox.APIErrorResponse{}, false), b.ref(sandbox.InferenceAPIErrorResponse{}, false)}}
			// anyOf is intentional: an inference error without an invocation ID
			// also satisfies the common error; oneOf would reject that response.
			if route.operation == "invokeInference" {
				operation["x-max-request-bytes"] = (256 << 10) + 8192
			}
		}
		response := object{"description": "Successful operation; inspect task/connection state separately from HTTP status."}
		if route.response != nil {
			response["content"] = object{"application/json": object{"schema": b.ref(route.response, false)}}
		}
		responses := object{strconv.Itoa(route.status): response,
			"default": object{"description": "Application rejection/error; no automatic replay of a mutation. TLS/HTTP parsing errors are outside this envelope.", "content": object{"application/json": object{"schema": failure}}},
			"405":     object{"description": "Method not allowed after authentication.", "headers": object{"Allow": object{"required": true, "schema": stringSchema()}}, "content": object{"application/json": object{"schema": failure}}}}
		if route.operation == "readiness" {
			responses["503"] = object{"description": "Host not ready, or server stopping.", "content": object{"application/json": object{"schema": object{"anyOf": []any{b.ref(sandbox.StatusResponse{}, false), b.ref(sandbox.LegacyAPIErrorResponse{}, false)}}}}}
		}
		if route.operation == "hostDoctor" {
			responses["503"] = object{"description": "Doctor report not ready, or API unavailable.", "content": object{"application/json": object{"schema": object{"anyOf": []any{b.ref(sandbox.DoctorReport{}, false), b.ref(sandbox.LegacyAPIErrorResponse{}, false)}}}}}
		}
		if route.operation == "health" || route.operation == "readiness" {
			operation["security"] = []any{object{"mutualTLS": []any{}}}
		}
		if route.operation == "prometheusMetrics" {
			response["content"] = object{"text/plain": object{"schema": stringSchema()}}
		}
		if route.operation == "streamSessionCommand" {
			response["content"] = object{"text/event-stream": object{"schema": stringSchema()}}
			operation["x-sse-events"] = object{"output": b.ref(sandbox.SessionOutputFrame{}, false), "result": b.ref(sandbox.SessionCommandPage{}, false), "timeout": b.ref(sandbox.SessionCommandTimeoutFrame{}, false)}
			operation["description"] = "SSE id/event/data frames; data follows the per-event schemas. Keepalive comments carry no JSON. Observation timeout/disconnect does not cancel the command; query the original ID. Once streaming starts, errors close the stream instead of appending a JSON HTTP error."
		}
		if route.operation == "openPortTunnel" {
			operation["x-max-request-bytes"] = 4096
			operation["parameters"] = append(params,
				object{"name": "Connection", "in": "header", "required": true, "schema": object{"type": "string", "description": "Must contain the upgrade token."}},
				object{"name": "Upgrade", "in": "header", "required": true, "schema": object{"type": "string", "const": "osv-port/1"}},
				object{"name": "Content-Length", "in": "header", "required": true, "schema": integer(1, 4096)})
			operation["description"] = "HTTP/1.1 Upgrade only; HTTP/2 returns 426. After 101 use the native framed binary protocol; do not parse a JSON HTTP response or replay bytes on reconnect."
			operation["x-port-tunnel"] = object{"upgrade": "osv-port/1", "header_bytes": 5, "length_encoding": "uint32-big-endian", "frames": object{
				"1": object{"name": "DATA", "min_bytes": 1, "max_bytes": 16384, "direction": "both"},
				"2": object{"name": "EOF", "bytes": 0, "direction": "both"},
				"3": object{"name": "CANCEL", "bytes": 0, "direction": "client-to-server"},
				"4": object{"name": "FINISHED", "min_bytes": 1, "max_bytes": 4096, "direction": "server-to-client", "json_schema": b.ref(sandbox.SessionPortInfo{}, false)}}}
			response["headers"] = object{"Connection": object{"schema": object{"type": "string", "const": "Upgrade"}}, "Upgrade": object{"schema": object{"type": "string", "const": "osv-port/1"}},
				"X-OSV-Session-ID": object{"schema": identifier()}, "X-OSV-Connection-ID": object{"schema": identifier()}, "X-OSV-Port": object{"schema": integer(1, 65535)}}
		}
		if route.operation == "createPreview" {
			operation["x-max-request-bytes"] = 4096
		}
		if route.operation == "listSessions" {
			operation["x-reject-unknown-or-repeated-query"] = true
		}
		operation["responses"] = responses
		entry, ok := paths[path].(object)
		if !ok {
			entry = object{}
			paths[path] = entry
		}
		entry[strings.ToLower(method)] = operation
	}
	document := object{"openapi": "3.1.1", "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
		"info":    object{"title": "OSv Sandbox control API", "version": "2.0.0", "description": "Complete registered control-plane HTTP wire surface, including legacy v1. Production requires mutual TLS and a tenant bearer token. This document is not a capability grant: consult authenticated template/session capabilities and current tenant policy. Unsupported functions remain explicit errors. gRPC is not implemented by this document."},
		"servers": []any{object{"url": "/"}}, "security": []any{object{"mutualTLS": []any{}, "bearerAuth": []any{}}},
		"paths": paths, "components": object{"schemas": b.components, "securitySchemes": object{"mutualTLS": object{"type": "mutualTLS"}, "bearerAuth": object{"type": "http", "scheme": "bearer"}}},
		"x-source-route-count": len(definitions), "x-preview-origin": "A separate TLS/HTTP1 browser origin transparently proxies authenticated application HTTP/WebSocket. Upstream application bodies/statuses are not control API schemas. See preview-v1 protocol.",
		"x-runtime-validation": "JSON schemas describe the wire contract. Byte quotas, canonical/confined paths, signed features, tenant policy, readiness, current lifetimes and resource limits remain mandatory server checks. GET routes also accept HEAD without a response body; framework canonical redirects remain standard HTTP."}
	return json.MarshalIndent(document, "", "  ")
}

// RoutePatterns is a stable inventory for tooling/tests, not a runtime router.
func RoutePatterns() []string {
	patterns := make([]string, 0, len(routes()))
	for _, route := range routes() {
		patterns = append(patterns, route.pattern)
	}
	sort.Strings(patterns)
	return patterns
}
