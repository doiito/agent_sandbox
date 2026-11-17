package sandbox

import "strings"

func (a *API) previewCapability(report *CapabilityReport, tenant *tenantRuntime) {
	report.Features.PortPreview = false
	report.Limits.PreviewGrants, report.Limits.PreviewGrantIDs, report.Limits.PreviewTTLMS, report.Limits.PreviewRequests, report.Limits.PreviewRequestBytes = 0, 0, 0, 0, 0
	methods := []string{}
	for _, method := range report.Methods {
		if !strings.Contains(method, "/previews/") {
			methods = append(methods, method)
		}
	}
	report.Methods = methods
	if report.PortForwardPolicy != nil {
		report.PortForwardPolicy.Preview = false
	}
	if a.preview == nil || !report.Features.PortForward || !report.ArtifactAuthenticated || !validSHA256Hex(report.ArtifactManifestSHA256) || report.Backend != "firecracker-linux" || !portManifestProtocol(report.ArtifactManifestProtocol) || tenant == nil || tenant.policy.Ports == nil || !tenant.policy.Ports.Preview || report.PortForwardPolicy == nil {
		return
	}
	a.preview.mu.Lock()
	closed := a.preview.closed
	a.preview.mu.Unlock()
	if closed {
		return
	}
	report.Features.PortPreview = true
	report.PortForwardPolicy.Preview = true
	report.Limits.PreviewGrants, report.Limits.PreviewGrantIDs, report.Limits.PreviewTTLMS = previewSessionLimit, previewHistoryLimit, 300000
	report.Limits.PreviewRequests, report.Limits.PreviewRequestBytes = previewRequestLimit, previewRequestBytes
	report.Methods = append(report.Methods, "POST /v2/sessions/{id}/ports/{port}/previews/{preview}", "GET /v2/sessions/{id}/previews/{preview}", "DELETE /v2/sessions/{id}/previews/{preview}")
}
