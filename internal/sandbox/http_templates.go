package sandbox

import (
	"errors"
	"net/http"
)

func writeTemplateLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTemplateMismatch) || errors.Is(err, ErrInvalidSelector) {
		writeSessionError(w, err)
		return
	}
	writeJobError(w, http.StatusServiceUnavailable, "unavailable", "template capabilities unavailable", true)
}

// Resolve egress policy once per catalog request, preserving per-template
// signed proxy support while host fetch remains independent of a guest VM.
func (a *API) apiCapabilityFilter(r *http.Request) func(*CapabilityReport) {
	tenant := tenantFromRequest(r)
	var policy *EgressPolicy
	proxy := false
	var inference inferenceServiceState
	if a.egress != nil && tenant != nil {
		inference, _ = a.egress.inferenceState(r.Context(), r.Header.Get("Authorization"))
	}
	if a.egress != nil && tenant != nil && tenant.egress != nil {
		p, enabled, err := a.egress.policyState(r.Context(), r.Header.Get("Authorization"))
		if err == nil && matchingEgressPolicy(p, &tenant.egress.policy) {
			policy = p
			proxy = enabled
		}
	}
	return func(report *CapabilityReport) {
		a.previewCapability(report, tenant)
		report.Features.NetworkEgress = report.Features.NetworkEgress && proxy
		report.Features.NetworkFetch = policy != nil
		report.NetworkFetchPolicy = policy
		applyInferenceCapability(report, tenant, inference, proxy)
		if policy != nil {
			report.Methods = append(report.Methods, "POST /v2/net/fetch")
		}
	}
}

func (a *API) templates(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFromRequest(r)
	if tenant == nil {
		writeJobError(w, 401, "unauthorized", "unauthorized", true)
		return
	}
	report, err := templateCatalogFor(a.runner)
	if err != nil {
		writeJobError(w, 503, "unavailable", "template catalog unavailable", true)
		return
	}
	filter := a.apiCapabilityFilter(r)
	entries := make([]TemplateReport, 0, len(report.Templates))
	for _, entry := range report.Templates {
		cap := &entry.Capabilities
		if !tenant.allowsTemplate(cap.Backend, cap.ArtifactManifestSHA256) {
			continue
		}
		cap.restrictEntrypoints(tenant)
		if len(cap.AllowedEntrypoints) == 0 {
			continue
		}
		filter(cap)
		entries = append(entries, entry)
	}
	report.Templates = entries
	// A hidden default must not reveal a private template name.
	visible := false
	for _, entry := range entries {
		visible = visible || entry.ID == report.DefaultTemplateID
	}
	if !visible {
		report.DefaultTemplateID = ""
	}
	writeJSON(w, http.StatusOK, report)
}
