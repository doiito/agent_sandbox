package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

var templateIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func (a *apiClient) discovery(ctx context.Context) (sandbox.CapabilityReport, *sandbox.TemplateCatalogReport, error) {
	cap, capErr := a.capabilities(ctx)
	if capErr == nil && !slices.Contains(cap.Methods, "GET /v2/templates") {
		return cap, nil, nil
	}
	raw, err := a.call(ctx, "GET", "/v2/templates", nil)
	if err != nil {
		if capErr != nil {
			err = capErr
		}
		return cap, nil, err
	}
	var catalog sandbox.TemplateCatalogReport
	if json.Unmarshal(raw, &catalog) != nil || catalog.Protocol != "osv-sandbox-template-catalog/v1" || len(catalog.Templates) > 16 {
		return cap, nil, errors.New("sandbox API template catalog is invalid")
	}
	ids, selectors := map[string]bool{}, map[sandbox.TemplateSelector]bool{}
	for _, entry := range catalog.Templates {
		one := entry.Capabilities
		key := sandbox.TemplateSelector{Backend: one.Backend, ArtifactManifestSHA256: one.ArtifactManifestSHA256}
		if !templateIDPattern.MatchString(entry.ID) || ids[entry.ID] || selectors[key] || one.Protocol != "osv-sandbox-capabilities/v1" || !one.ArtifactAuthenticated || one.Backend == "" || !digestPattern.MatchString(one.ArtifactManifestSHA256) || one.AllowedEntrypoints == nil {
			return cap, nil, errors.New("sandbox API template identity is invalid")
		}
		ids[entry.ID], selectors[key] = true, true
	}
	if catalog.DefaultTemplateID != "" && !ids[catalog.DefaultTemplateID] {
		return cap, nil, errors.New("sandbox API catalog default is not visible")
	}
	if capErr != nil {
		cap = sandbox.CapabilityReport{Protocol: "osv-sandbox-capabilities/v1", AllowedEntrypoints: []string{}, Methods: []string{"GET /v2/templates"}}
	}
	// Fetch policy belongs to the tenant, independently of the default VM.
	if !cap.ArtifactAuthenticated {
		for _, entry := range catalog.Templates {
			if entry.Capabilities.Features.NetworkFetch {
				cap.Features.NetworkFetch = true
				cap.NetworkFetchPolicy = entry.Capabilities.NetworkFetchPolicy
				break
			}
		}
	}
	return cap, &catalog, nil
}

func schemaStrings(schema map[string]any) []string {
	if value, ok := schema["const"].(string); ok {
		return []string{value}
	}
	if values, ok := schema["enum"].([]string); ok {
		return values
	}
	return nil
}

func mergeToolSchema(target *tool, source tool) {
	a := target.InputSchema["properties"].(map[string]any)
	b := source.InputSchema["properties"].(map[string]any)
	for name, value := range b {
		old, exists := a[name]
		if !exists {
			a[name] = value
			continue
		}
		left, lok := old.(map[string]any)
		right, rok := value.(map[string]any)
		if !lok || !rok {
			continue
		}
		values := append([]string{}, schemaStrings(left)...)
		if len(values) > 0 && len(schemaStrings(right)) > 0 {
			for _, item := range schemaStrings(right) {
				if !slices.Contains(values, item) {
					values = append(values, item)
				}
			}
			delete(left, "const")
			left["enum"] = values
		}
		for _, key := range []string{"maximum", "maxLength", "maxItems"} {
			if x, ok := left[key].(int); ok {
				if y, ok := right[key].(int); ok && y > x {
					left[key] = y
				}
			}
		}
		if x, ok := left["minimum"].(int); ok {
			if y, ok := right["minimum"].(int); ok && y < x {
				left["minimum"] = y
			}
		}
	}
}

func catalogToolsFor(defaultCap sandbox.CapabilityReport, catalog *sandbox.TemplateCatalogReport) []tool {
	base := toolsFor(sandbox.CapabilityReport{})
	byName := map[string]*tool{}
	for i := range base {
		byName[base[i].Name] = &base[i]
	}
	// Start without default execution tools: an expired default may remain
	// configured, while only available catalog entries can publish operations.
	for _, entry := range catalog.Templates {
		if !entry.Available {
			// These tools require an already owned VM and do not admit a new one.
			if !artifactCapable(entry.Capabilities) && !codeCapable(entry.Capabilities) && !portCapable(entry.Capabilities) && !inferenceCapable(entry.Capabilities) && !entry.Capabilities.Features.InferenceBilling {
				continue
			}
			for _, definition := range toolsFor(entry.Capabilities) {
				if !artifactOperations[definition.Name] && !strings.HasPrefix(definition.Name, "sandbox.code.") && !strings.HasPrefix(definition.Name, "sandbox.ports.") && !strings.HasPrefix(definition.Name, "sandbox.preview.") && !inferenceOperations[definition.Name] && definition.Name != "sandbox.session.get" && definition.Name != "sandbox.session.close" {
					continue
				}
				if existing := byName[definition.Name]; existing != nil {
					mergeToolSchema(existing, definition)
				} else {
					value := definition
					byName[definition.Name] = &value
				}
			}
			continue
		}
		for _, definition := range toolsFor(entry.Capabilities) {
			if existing := byName[definition.Name]; existing != nil {
				mergeToolSchema(existing, definition)
			} else {
				value := definition
				byName[definition.Name] = &value
			}
		}
	}
	if defaultCap.Features.NetworkFetch && defaultCap.NetworkFetchPolicy != nil {
		for _, definition := range toolsFor(defaultCap) {
			if definition.Name == "sandbox.net.fetch" {
				value := definition
				byName[definition.Name] = &value
			}
		}
	}
	// Bill history is independent of template availability and active sessions.
	if defaultCap.Features.InferenceBilling {
		for _, definition := range inferenceToolsFor(defaultCap) {
			if definition.Name == "sandbox.ml.bill" {
				value := definition
				byName[definition.Name] = &value
			}
		}
	}
	backends, digests := []string{}, []string{}
	for _, entry := range catalog.Templates {
		if entry.Available {
			if !slices.Contains(backends, entry.Capabilities.Backend) {
				backends = append(backends, entry.Capabilities.Backend)
			}
			digests = append(digests, entry.Capabilities.ArtifactManifestSHA256)
		}
	}
	capProps := byName["sandbox.capabilities"].InputSchema["properties"].(map[string]any)
	if len(backends) > 0 {
		capProps["backend"] = map[string]any{"type": "string", "enum": backends}
		capProps["artifact_manifest_sha256"] = map[string]any{"type": "string", "enum": digests}
	}
	if !defaultCap.ArtifactAuthenticated {
		if definition := byName["sandbox.exec"]; definition != nil {
			definition.InputSchema["anyOf"] = []any{map[string]any{"required": []string{"backend", "artifact_manifest_sha256"}}, map[string]any{"required": []string{"session_id"}}}
		}
		if definition := byName["sandbox.session.create"]; definition != nil {
			definition.InputSchema["required"] = []string{"backend", "artifact_manifest_sha256"}
		}
	}
	result := make([]tool, 0, len(byName))
	for _, definition := range byName {
		result = append(result, *definition)
	}
	return sortedTools(result)
}

func (s *Server) selectedToolCapability(ctx context.Context, name string, args json.RawMessage, cap sandbox.CapabilityReport, catalog *sandbox.TemplateCatalogReport) (sandbox.CapabilityReport, error) {
	if name != "sandbox.exec" && name != "sandbox.session.create" && name != "sandbox.capabilities" && name != "sandbox.commands.start" && !strings.HasPrefix(name, "sandbox.watch.") {
		return cap, nil
	}
	var selection struct {
		Backend   string `json:"backend"`
		Digest    string `json:"artifact_manifest_sha256"`
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(args, &selection) != nil {
		return cap, errors.New("invalid tool arguments")
	}
	if (selection.Backend == "") != (selection.Digest == "") || selection.Digest != "" && !digestPattern.MatchString(selection.Digest) {
		return cap, errors.New("incomplete signed template selector")
	}
	if selection.SessionID != "" && (name == "sandbox.exec" || name == "sandbox.commands.start" || strings.HasPrefix(name, "sandbox.watch.")) && (len(catalog.Templates) > 1 || !cap.ArtifactAuthenticated || !cap.Features.Sessions || strings.HasPrefix(name, "sandbox.watch.")) {
		path, err := sessionPath(selection.SessionID)
		if err != nil {
			return cap, err
		}
		raw, err := s.api.call(ctx, "GET", path, nil)
		if err != nil {
			return cap, err
		}
		var info sandbox.SessionInfo
		if json.Unmarshal(raw, &info) != nil || info.ID != selection.SessionID || info.Backend == "" || !digestPattern.MatchString(info.ArtifactManifestSHA256) {
			return cap, errors.New("session has invalid template identity")
		}
		if selection.Backend != "" && (selection.Backend != info.Backend || selection.Digest != info.ArtifactManifestSHA256) {
			return cap, errors.New("session belongs to a different signed template")
		}
		selection.Backend, selection.Digest = info.Backend, info.ArtifactManifestSHA256
	}
	if selection.Backend != "" {
		return s.api.capabilitiesFor(ctx, selection.Backend, selection.Digest)
	}
	return cap, nil
}
