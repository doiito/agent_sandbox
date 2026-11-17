package sandbox

import (
	"encoding/json"
	"unicode/utf8"
)

// ValidateForTask checks a received bill without relying on an active session.
func (bill InferenceBill) ValidateForTask(taskID string) error {
	if !canonicalJobID(taskID) || bill.TaskID != taskID {
		return inferenceError(503, "inference_protocol")
	}
	return validateInferenceBill(bill, inferenceBinding{Tenant: bill.Tenant, TaskID: taskID, VMID: bill.VMID, LeaseID: bill.LeaseID})
}

// ValidateForTask binds a successful model result to the caller's known IDs.
// Data can contain escaped JSON after transport; its receipt meters provider
// bytes, not the size of that encoded envelope.
func (result InferenceInvokeResult) ValidateForTask(taskID, invocationID, endpoint string) error {
	v := result.Invocation
	if !canonicalJobID(taskID) || result.TaskID != taskID || result.Protocol != "osv-sandbox-inference-invoke/v1" ||
		!canonicalJobID(invocationID) || v.ID != invocationID || v.Endpoint != endpoint || !inferenceEndpointName.MatchString(endpoint) ||
		!canonicalJobID(v.Epoch) || v.State != "succeeded" || !v.Dispatched || v.HTTPStatus < 200 || v.HTTPStatus > 299 || v.Code != "" ||
		v.InputBytes > egressRequestLimit || v.MaxOutputBytes < 1 || v.MaxOutputBytes > egressResponseLimit || v.OutputBytes > v.MaxOutputBytes ||
		v.StartedAt.IsZero() || v.FinishedAt == nil || v.FinishedAt.Before(v.StartedAt) || v.DurationMS > 300000 ||
		len(result.Data) > 2*egressResponseLimit || !utf8.Valid(result.Data) || !json.Valid(result.Data) {
		return inferenceError(503, "inference_protocol")
	}
	reserved, err := v.Price.cost(v.InputBytes, v.MaxOutputBytes)
	if err != nil || reserved != v.ReservedUnits {
		return inferenceError(503, "inference_protocol")
	}
	settled, err := v.Price.cost(v.InputBytes, v.OutputBytes)
	if err != nil || settled != v.SettledUnits || settled > reserved {
		return inferenceError(503, "inference_protocol")
	}
	return nil
}

func (policy InferenceCapabilities) Validate() error {
	if policy.Protocol != "osv-sandbox-inference-capabilities/v1" || len(policy.Endpoints) < 1 || len(policy.Endpoints) > 32 ||
		policy.MaxRequestBytes < 1 || policy.MaxRequestBytes > egressRequestLimit || policy.MaxResponseBytes < 1 || policy.MaxResponseBytes > egressResponseLimit ||
		policy.TimeoutMS < 100 || policy.TimeoutMS > 30000 || policy.MaxInvocations < 1 || policy.MaxInvocations > 256 {
		return inferenceError(503, "inference_protocol")
	}
	seen := make(map[string]bool)
	for _, entry := range policy.Endpoints {
		if !inferenceEndpointName.MatchString(entry.Name) || seen[entry.Name] {
			return inferenceError(503, "inference_protocol")
		}
		seen[entry.Name] = true
		if _, err := entry.Price.cost(uint64(policy.MaxRequestBytes), uint64(policy.MaxResponseBytes)); err != nil {
			return inferenceError(503, "inference_protocol")
		}
	}
	return nil
}
