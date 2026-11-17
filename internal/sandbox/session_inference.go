package sandbox

import (
	"context"
	"time"
)

func (s *Session) invokeInference(ctx context.Context, request InferenceInvokeRequest, tenantID string) (InferenceInvokeResult, error) {
	if err := request.Validate(); err != nil {
		return InferenceInvokeResult{}, err
	}
	if s.manager == nil || s.instance == nil || s.manager.manifest == nil || !s.manager.hasRemoteInferenceFeature() {
		return InferenceInvokeResult{}, inferenceError(501, "inference_unsupported")
	}
	owned, err := s.manager.ownedSession(s.info.ID, tenantID)
	if err != nil || owned != s {
		return InferenceInvokeResult{}, ErrSessionClosed
	}
	info := s.Info()
	if info.State != "running" || info.Network != "proxy" || info.Backend != s.manager.config.Backend || info.ArtifactManifestSHA256 != s.manager.manifest.digestSHA256 {
		return InferenceInvokeResult{}, inferenceError(403, "inference_disabled")
	}
	var tenant *tenantRuntime
	if s.manager.inferenceAuth != nil {
		for _, candidate := range s.manager.inferenceAuth.tenants {
			if candidate.policy.ID == tenantID {
				tenant = candidate
				break
			}
		}
	}
	if tenant == nil || tenant.inference == nil || !tenant.allowsTemplate(info.Backend, info.ArtifactManifestSHA256) {
		return InferenceInvokeResult{}, inferenceError(403, "inference_disabled")
	}
	if _, err := tenant.inference.permit(request.Endpoint); err != nil {
		return InferenceInvokeResult{}, inferenceError(403, "inference_endpoint")
	}
	policy := inferenceTenantPolicyDigest(tenant)
	if policy == "" {
		return InferenceInvokeResult{}, inferenceError(503, "inference_policy_unavailable")
	}
	binding := inferenceBinding{Tenant: tenantID, TaskID: info.ID, VMID: s.instance.id, LeaseID: info.ID}
	s.instance.bootMu.Lock()
	proxy := s.instance.proxy
	bound := proxy != nil && proxy.inference != nil && *proxy.inference == binding && proxy.inferencePolicySHA256 == policy
	s.instance.bootMu.Unlock()
	if !bound {
		return InferenceInvokeResult{}, inferenceError(403, "inference_disabled")
	}
	s.lifecycleMu.Lock()
	hard := s.hardDeadline
	s.lifecycleMu.Unlock()
	if !hard.IsZero() && !time.Now().Before(hard) {
		return InferenceInvokeResult{}, ErrSessionClosed
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSession := context.AfterFunc(s.ctx, cancel)
	defer stopSession()
	stopVM := context.AfterFunc(s.instance.ctx, cancel)
	defer stopVM()
	return newInferenceRootClient(s.manager.config.EgressSocket).invoke(call, binding, request, policy)
}
