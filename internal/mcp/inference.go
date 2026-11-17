package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var inferenceOperations = map[string]bool{"sandbox.ml.invoke": true, "sandbox.ml.bill": true}
var inferenceAlias = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func inferenceCapable(cap sandbox.CapabilityReport) bool {
	return cap.ArtifactAuthenticated && digestPattern.MatchString(cap.ArtifactManifestSHA256) &&
		(cap.Backend == "firecracker-linux" || cap.Backend == "firecracker-osv") && (cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v7" || cap.Backend == "firecracker-linux" && cap.ArtifactManifestProtocol == "osv-sandbox-artifacts/v8") &&
		cap.Features.Sessions && cap.Features.RemoteInference && cap.Features.NetworkEgress && cap.RemoteInferencePolicy != nil &&
		cap.RemoteInferencePolicy.Validate() == nil && slices.Contains(cap.Methods, "POST /v2/sessions/{id}/ml/invocations")
}

func inferenceToolsFor(cap sandbox.CapabilityReport) []tool {
	var tools []tool
	if cap.Features.InferenceBilling {
		tools = append(tools, toolDefinition("sandbox.ml.bill", "Read this tenant's persistent task bill, including after the session closes or inference permission ends. Amounts are exact decimal strings; uncertain calls keep their reservation. Does not replay a model.", true,
			map[string]any{"task_id": handleSchema()}, "task_id"))
	}
	if inferenceCapable(cap) {
		aliases := []string{}
		for _, endpoint := range cap.RemoteInferencePolicy.Endpoints {
			aliases = append(aliases, endpoint.Name)
		}
		definition := toolDefinition("sandbox.ml.invoke", "Invoke one configured model alias through the existing session's controlled egress. Supply a known invocation_id before submission. No automatic retry after cancellation, transport loss or an error: query sandbox.ml.bill by task/session ID. No URL, credential or caller-supplied price.", false,
			map[string]any{"session_id": handleSchema(), "invocation_id": handleSchema(), "endpoint": map[string]any{"type": "string", "enum": aliases},
				"payload": map[string]any{}, "timeout_ms": integerSchema(0, cap.RemoteInferencePolicy.TimeoutMS)}, "session_id", "invocation_id", "endpoint", "payload")
		definition.Annotations["openWorldHint"] = true
		tools = append(tools, definition)
	}
	return tools
}

type inferenceToolRequest struct {
	Session string          `json:"session_id,omitempty"`
	Task    string          `json:"task_id,omitempty"`
	ID      string          `json:"invocation_id,omitempty"`
	Alias   string          `json:"endpoint,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Timeout *int            `json:"timeout_ms,omitempty"`
}

func parseInferenceTool(name string, args json.RawMessage) (inferenceToolRequest, error) {
	var value inferenceToolRequest
	fields, ok := object(args)
	if !inferenceOperations[name] || !ok || decodeStrict(args, &value) != nil {
		return value, codeProtocol("invalid inference arguments")
	}
	if name == "sandbox.ml.bill" {
		if len(fields) != 1 || !handlePattern.MatchString(value.Task) {
			return value, codeProtocol("invalid inference task")
		}
		return value, nil
	}
	allowed := map[string]bool{"session_id": true, "invocation_id": true, "endpoint": true, "payload": true, "timeout_ms": true}
	for key, raw := range fields {
		if !allowed[key] || key != "payload" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return value, codeProtocol("invalid inference field")
		}
	}
	if !handlePattern.MatchString(value.Session) || !handlePattern.MatchString(value.ID) || !inferenceAlias.MatchString(value.Alias) ||
		len(value.Payload) == 0 || len(value.Payload) > 256<<10 || !json.Valid(value.Payload) ||
		value.Timeout != nil && (*value.Timeout < 0 || *value.Timeout > 30000) {
		return value, codeProtocol("invalid inference identity or payload")
	}
	return value, nil
}

func inferenceFailure(err error, request inferenceToolRequest, attempted bool) outcome {
	base := failure(err)
	var problem *codeToolProblem
	if errors.As(err, &problem) {
		base = toolFailure(problem.code, problem.message)
	}
	var value map[string]json.RawMessage
	_ = json.Unmarshal(base.Data, &value)
	if request.Task != "" {
		value["task_id"] = rawObject(request.Task)
	} else {
		value["task_id"] = rawObject(request.Session)
		value["invocation_id"] = rawObject(request.ID)
		value["delivery_unknown"] = rawObject(attempted)
	}
	return outcome{Data: rawObject(value), IsError: true}
}

func (s *Server) callInferenceTool(parent context.Context, name string, args json.RawMessage) outcome {
	request, err := parseInferenceTool(name, args)
	if err != nil {
		return invalidArgs()
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	if name == "sandbox.ml.bill" {
		data, err := s.api.call(ctx, "GET", "/v2/ml/bills/"+request.Task, nil)
		if err != nil {
			return inferenceFailure(err, request, false)
		}
		var bill sandbox.InferenceBill
		if decodeStrict(data, &bill) != nil || bill.ValidateForTask(request.Task) != nil {
			return inferenceFailure(codeProtocol("invalid inference bill"), request, false)
		}
		return outcome{Data: data}
	}
	cap, err := s.api.ownerCapabilities(ctx, request.Session)
	if err != nil {
		return inferenceFailure(err, request, false)
	}
	if !inferenceCapable(cap) {
		return inferenceFailure(&apiFailure{Status: 403, Code: "inference_disabled"}, request, false)
	}
	policy := cap.RemoteInferencePolicy
	if !slices.ContainsFunc(policy.Endpoints, func(entry sandbox.InferenceEndpointCapability) bool { return entry.Name == request.Alias }) {
		return inferenceFailure(&apiFailure{Status: 403, Code: "inference_endpoint"}, request, false)
	}
	invocation := sandbox.InferenceInvokeRequest{ID: request.ID, Endpoint: request.Alias, Payload: request.Payload}
	if request.Timeout != nil {
		invocation.TimeoutMS = *request.Timeout
	}
	if len(request.Payload) > policy.MaxRequestBytes || invocation.TimeoutMS > policy.TimeoutMS {
		return inferenceFailure(&apiFailure{Status: 400, Code: "inference_request"}, request, false)
	}
	data, err := s.api.call(ctx, "POST", "/v2/sessions/"+request.Session+"/ml/invocations", invocation)
	if err != nil {
		return inferenceFailure(err, request, true)
	}
	var result sandbox.InferenceInvokeResult
	if decodeStrict(data, &result) != nil || result.ValidateForTask(request.Session, request.ID, request.Alias) != nil {
		return inferenceFailure(codeProtocol("invalid inference result binding or meter"), request, true)
	}
	return outcome{Data: data}
}
