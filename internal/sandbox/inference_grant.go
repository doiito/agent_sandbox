package sandbox

// This grant is private to the root proxy. The immutable policy digest is not
// part of a guest-selected identity or the persistent physical/task binding.
type guestInferenceGrant struct {
	Binding      inferenceBinding
	PolicySHA256 string
}

func (g guestInferenceGrant) validFor(tenant, vmID, leaseID string) bool {
	return g.Binding.valid() && g.Binding.Tenant == tenant && g.Binding.VMID == vmID &&
		g.Binding.LeaseID == leaseID && validSHA256Hex(g.PolicySHA256)
}

func (m *Manager) inferencePolicyDigest(tenantID string) string {
	if m.inferenceAuth != nil {
		for _, tenant := range m.inferenceAuth.tenants {
			if tenant.policy.ID == tenantID {
				return inferenceTenantPolicyDigest(tenant)
			}
		}
	}
	return ""
}
