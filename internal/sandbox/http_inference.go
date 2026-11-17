package sandbox

import (
	"net/http"
	"reflect"
)

const inferenceInvokeMethod = "POST /v2/sessions/{id}/ml/invocations"
const inferenceBillMethod = "GET /v2/ml/bills/{task}"

func disableRemoteInference(report *CapabilityReport) {
	report.Features.RemoteInference = false
	report.RemoteInferencePolicy = nil
	if len(report.Methods) == 0 {
		return
	}
	methods := make([]string, 0, len(report.Methods))
	for _, method := range report.Methods {
		if method != inferenceInvokeMethod {
			methods = append(methods, method)
		}
	}
	report.Methods = methods
}

func signedInferenceCapability(report CapabilityReport) bool {
	return report.Features.RemoteInference && report.ArtifactAuthenticated && inferenceManifestProtocol(report.Backend, report.ArtifactManifestProtocol) &&
		validSHA256Hex(report.ArtifactManifestSHA256) && (report.Backend == "firecracker-linux" || report.Backend == "firecracker-osv")
}

func applyInferenceCapability(report *CapabilityReport, tenant *tenantRuntime, state inferenceServiceState, proxy bool) {
	// Active sessions reuse their bound capability report. Refresh these methods
	// without duplicating entries or retaining billing after a service failure.
	methods := make([]string, 0, len(report.Methods)+2)
	for _, method := range report.Methods {
		if method != inferenceInvokeMethod && method != inferenceBillMethod {
			methods = append(methods, method)
		}
	}
	report.Methods = methods
	report.Features.InferenceBilling = state.Billing
	if state.Billing {
		report.Methods = append(report.Methods, inferenceBillMethod)
	}
	if !signedInferenceCapability(*report) || !report.Features.NetworkEgress || !proxy || tenant == nil || tenant.inference == nil ||
		state.Policy == nil || state.PolicySHA256 != inferenceTenantPolicyDigest(tenant) || !reflect.DeepEqual(*state.Policy, tenant.inference.capabilities()) {
		disableRemoteInference(report)
		return
	}
	copy := *state.Policy
	copy.Endpoints = append([]InferenceEndpointCapability{}, state.Policy.Endpoints...)
	copy.BudgetUnits = inferenceBudget(state.Policy.BudgetUnits, nil)
	report.RemoteInferencePolicy = &copy
	if report.Features.Sessions {
		report.Methods = append(report.Methods, inferenceInvokeMethod)
	}
}

func writeAPIInferenceError(w http.ResponseWriter, err error, id string) {
	failure := apiInferenceFailure(err, id)
	value := InferenceAPIErrorResponse{Code: failure.Code, Error: failure.Error(), InvocationID: failure.InvocationID}
	writeInferenceJSON(w, failure.Status, value)
}

func (a *API) invokeSessionInference(w http.ResponseWriter, r *http.Request) {
	session := a.lookupSession(r)
	if session == nil {
		writeAPIInferenceError(w, inferenceError(404, "inference_not_found"), "")
		return
	}
	var request InferenceInvokeRequest
	if err := readInferenceRequest(r, egressRequestLimit+8192, &request); err != nil {
		writeAPIInferenceError(w, err, "")
		return
	}
	if err := request.Validate(); err != nil {
		writeAPIInferenceError(w, err, request.ID)
		return
	}
	if !signedInferenceCapability(session.capability) || session.info.Network != "proxy" || session.tenant.inference == nil || a.egress == nil {
		writeAPIInferenceError(w, inferenceError(403, "inference_disabled"), request.ID)
		return
	}
	if !session.tenant.allowsTemplate(session.info.Backend, session.info.ArtifactManifestSHA256) {
		writeAPIInferenceError(w, inferenceError(403, "inference_disabled"), request.ID)
		return
	}
	state, err := a.egress.inferenceState(r.Context(), r.Header.Get("Authorization"))
	if err != nil || state.Policy == nil || state.PolicySHA256 != inferenceTenantPolicyDigest(session.tenant) || !reflect.DeepEqual(*state.Policy, session.tenant.inference.capabilities()) {
		writeAPIInferenceError(w, inferenceError(503, "inference_policy_unavailable"), request.ID)
		return
	}
	if _, err := session.tenant.inference.permit(request.Endpoint); err != nil {
		writeAPIInferenceError(w, inferenceError(403, "inference_endpoint"), request.ID)
		return
	}
	if err := session.tenant.consumeRequestToken(); err != nil {
		writeAPIInferenceError(w, inferenceError(429, "inference_rate_limit"), request.ID)
		return
	}
	result, err := session.handle.InvokeInference(r.Context(), request)
	if err != nil {
		writeAPIInferenceError(w, err, request.ID)
		return
	}
	if result.TaskID != session.info.ID {
		writeAPIInferenceError(w, inferenceError(503, "inference_protocol"), request.ID)
		return
	}
	writeInferenceJSON(w, 200, result)
}

func (a *API) getInferenceBill(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFromRequest(r)
	if a.egress == nil {
		writeAPIInferenceError(w, inferenceError(503, "inference_unavailable"), "")
		return
	}
	if err := tenant.consumeRequestToken(); err != nil {
		writeAPIInferenceError(w, inferenceError(429, "inference_rate_limit"), "")
		return
	}
	bill, err := a.egress.inferenceBill(r.Context(), r.Header.Get("Authorization"), r.PathValue("task"))
	if err != nil {
		writeAPIInferenceError(w, err, "")
		return
	}
	if bill.Tenant != tenant.policy.ID {
		writeAPIInferenceError(w, inferenceError(503, "inference_protocol"), "")
		return
	}
	writeInferenceJSON(w, 200, bill)
}
