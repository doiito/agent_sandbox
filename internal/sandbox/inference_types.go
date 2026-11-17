package sandbox

import (
	"encoding/json"
	"unicode/utf8"
)

// InferenceInvokeRequest never accepts a URL, credential, price, or task owner.
// The launcher supplies the binding separately after checking VM ownership.
type InferenceInvokeRequest struct {
	ID        string          `json:"id"`
	Endpoint  string          `json:"endpoint"`
	Payload   json.RawMessage `json:"payload"`
	TimeoutMS int             `json:"timeout_ms,omitempty"`
}

func (r InferenceInvokeRequest) Validate() error {
	if !canonicalJobID(r.ID) || !inferenceEndpointName.MatchString(r.Endpoint) || len(r.Payload) < 1 || len(r.Payload) > egressRequestLimit ||
		!utf8.Valid(r.Payload) || !json.Valid(r.Payload) || r.TimeoutMS < 0 || r.TimeoutMS > 30000 {
		return inferenceError(400, "inference_request")
	}
	return nil
}

type InferenceInvokeResult struct {
	Protocol   string                     `json:"protocol"`
	TaskID     string                     `json:"task_id"`
	Invocation InferenceInvocationReceipt `json:"invocation"`
	Data       json.RawMessage            `json:"data"`
}

// InferenceError exposes a stable code and the caller's known invocation ID.
// Provider error bodies, credentials, and internal paths are never included.
type InferenceError struct {
	Status       int    `json:"-"`
	Code         string `json:"code"`
	InvocationID string `json:"invocation_id,omitempty"`
}

func (e *InferenceError) Error() string { return "inference " + e.Code }
func inferenceError(status int, code string) error {
	return &InferenceError{Status: status, Code: code}
}

type InferenceEndpointCapability struct {
	Name  string         `json:"name"`
	Price InferencePrice `json:"price"`
}
type InferenceCapabilities struct {
	Protocol         string                        `json:"protocol"`
	Endpoints        []InferenceEndpointCapability `json:"endpoints"`
	MaxRequestBytes  int                           `json:"max_request_bytes"`
	MaxResponseBytes int                           `json:"max_response_bytes"`
	TimeoutMS        int                           `json:"timeout_ms"`
	MaxInvocations   int                           `json:"max_invocations"`
	BudgetUnits      *InferenceUnits               `json:"budget_units,omitempty"`
}

func (r *inferenceRules) capabilities() InferenceCapabilities {
	result := InferenceCapabilities{Protocol: "osv-sandbox-inference-capabilities/v1",
		Endpoints: []InferenceEndpointCapability{}, MaxRequestBytes: r.request, MaxResponseBytes: r.response,
		TimeoutMS: r.timeoutMS, MaxInvocations: r.policy.MaxInvocations, BudgetUnits: inferenceBudget(r.policy.BudgetUnits, nil)}
	for _, endpoint := range r.policy.Endpoints {
		result.Endpoints = append(result.Endpoints, InferenceEndpointCapability{Name: endpoint.Name, Price: endpoint.Price})
	}
	return result
}

type InferenceAuditMeter struct {
	State         string         `json:"state"`
	ReservedUnits InferenceUnits `json:"reserved_units"`
	SettledUnits  InferenceUnits `json:"settled_units"`
	HeldUnits     InferenceUnits `json:"held_units"`
}
