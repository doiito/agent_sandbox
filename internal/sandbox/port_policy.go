package sandbox

import (
	"errors"
	"strings"
	"sync"
)

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

func (r *CapabilityReport) restrictPorts(tenant *tenantRuntime) {
	if !r.Features.PortForward {
		return
	}
	r.PortForwardPolicy = nil
	var policy *PortPolicy
	if tenant != nil {
		policy = tenant.policy.Ports
	}
	if policy != nil {
		copy, err := policy.validatedCopy()
		if err == nil {
			effective := []PortRange{}
			for _, span := range copy.AllowedPorts {
				if span.From <= 3128 && span.To >= 3128 {
					if span.From < 3128 {
						effective = append(effective, PortRange{span.From, 3127})
					}
					if span.To > 3128 {
						effective = append(effective, PortRange{3129, span.To})
					}
				} else {
					effective = append(effective, span)
				}
			}
			copy.AllowedPorts = effective
			// Preview is a separate, not-yet-accepted capability.
			copy.Preview = false
			if len(effective) > 0 {
				r.PortForwardPolicy = copy
				r.Limits.PortTenantConnections = copy.MaxConcurrent
				return
			}
		}
	}
	r.Features.PortForward = false
	r.Limits.PortConnections, r.Limits.PortConnectionIDs, r.Limits.PortFrameBytes, r.Limits.PortMaxBytes, r.Limits.PortTimeoutMS, r.Limits.PortTenantConnections = 0, 0, 0, 0, 0, 0
	methods := []string{}
	for _, method := range r.Methods {
		if !strings.Contains(method, "/ports/") {
			methods = append(methods, method)
		}
	}
	r.Methods = methods
}

type PortPolicy struct {
	AllowedPorts  []PortRange `json:"allowed_ports"`
	MaxConcurrent int         `json:"max_concurrent"`
	Preview       bool        `json:"preview"`
}

func (p PortPolicy) validatedCopy() (*PortPolicy, error) {
	if len(p.AllowedPorts) > 16 || p.MaxConcurrent < 1 || p.MaxConcurrent > 128 {
		return nil, errors.New("invalid port policy limits")
	}
	var previous uint16
	for _, r := range p.AllowedPorts {
		if r.From == 0 || r.To < r.From || r.From <= previous {
			return nil, errors.New("allowed_ports must contain ordered, disjoint nonzero port ranges")
		}
		previous = r.To
	}
	copy := p
	copy.AllowedPorts = append([]PortRange{}, p.AllowedPorts...)
	return &copy, nil
}

func (p *PortPolicy) allows(port uint16) bool {
	// Never publish the built-in outbound proxy as an inbound/public service.
	if p == nil || port == 0 || port == 3128 {
		return false
	}
	for _, r := range p.AllowedPorts {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

func (a *Authenticator) portTenant(id string) *tenantRuntime {
	if a != nil {
		for _, t := range a.tenants {
			if t.policy.ID == id {
				return t
			}
		}
	}
	return nil
}

func (t *tenantRuntime) acquirePort(port uint16) (func(), error) {
	if t == nil || !t.policy.Ports.allows(port) || t.portSem == nil {
		return nil, &PortRequestError{Code: "denied"}
	}
	select {
	case t.portSem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-t.portSem }) }, nil
	default:
		return nil, &PortRequestError{Code: "quota"}
	}
}
