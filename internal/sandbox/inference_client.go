package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type inferenceServiceState struct {
	Protocol     string                 `json:"protocol"`
	Billing      bool                   `json:"billing"`
	Policy       *InferenceCapabilities `json:"policy,omitempty"`
	PolicySHA256 string                 `json:"policy_sha256,omitempty"`
}

func inferenceTenantPolicyDigest(tenant *tenantRuntime) string {
	if tenant == nil || tenant.inference == nil || tenant.egress == nil {
		return ""
	}
	data, err := json.Marshal(struct {
		Egress    EgressPolicy    `json:"egress"`
		Inference InferencePolicy `json:"inference"`
	}{tenant.egress.policy, tenant.inference.policy})
	if err != nil {
		return ""
	}
	return inferenceDigest(data)
}

func (c *EgressClient) inferenceState(ctx context.Context, authorization string) (inferenceServiceState, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	status, data, err := c.exchange(ctx, "GET", "/v1/inference/state", authorization, nil)
	var state inferenceServiceState
	if err != nil || status != 200 || decodeInferenceJSON(data, &state) != nil || state.Protocol != "osv-sandbox-inference-state/v1" ||
		(state.Policy == nil) != (state.PolicySHA256 == "") || state.Policy != nil && (!state.Billing || !validSHA256Hex(state.PolicySHA256)) {
		return inferenceServiceState{}, inferenceError(503, "inference_unavailable")
	}
	return state, nil
}

func (c *EgressClient) inferenceBill(ctx context.Context, authorization, taskID string) (InferenceBill, error) {
	var bill InferenceBill
	if !canonicalJobID(taskID) {
		return bill, inferenceError(404, "inference_not_found")
	}
	status, data, err := c.exchange(ctx, "GET", "/v1/inference/bills/"+taskID, authorization, nil)
	if err != nil {
		return bill, inferenceError(503, "inference_unavailable")
	}
	if status != 200 {
		var failure struct {
			Protocol string         `json:"protocol"`
			Error    InferenceError `json:"error"`
		}
		if decodeInferenceJSON(data, &failure) != nil || failure.Protocol != "osv-sandbox-inference-error/v1" || !safeEgressCode(failure.Error.Code) {
			return bill, inferenceError(503, "inference_protocol")
		}
		failure.Error.Status = status
		return bill, &failure.Error
	}
	if decodeInferenceJSON(data, &bill) != nil || bill.TaskID != taskID || validateInferenceBill(bill, inferenceBinding{Tenant: bill.Tenant, TaskID: bill.TaskID, VMID: bill.VMID, LeaseID: bill.LeaseID}) != nil {
		return InferenceBill{}, inferenceError(503, "inference_protocol")
	}
	return bill, nil
}

func apiInferenceFailure(err error, id string) *InferenceError {
	var typed *InferenceError
	if errors.As(err, &typed) {
		return inferenceFailure(typed, id)
	}
	if errors.Is(err, ErrSessionClosed) {
		return inferenceFailure(inferenceError(404, "inference_not_found"), id)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return inferenceFailure(inferenceError(504, "inference_timeout"), id)
	}
	if errors.Is(err, context.Canceled) {
		return inferenceFailure(inferenceError(499, "inference_cancelled"), id)
	}
	return inferenceFailure(inferenceError(503, "inference_unavailable"), id)
}
