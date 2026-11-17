package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func TestCatalogTemplateBOMLinksSeparateGuestInventoryByDigest(t *testing.T) {
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"protocol":"osv-sandbox-artifacts/v2","backend":"firecracker-osv"}`)
	child := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", Components: []component{{Type: "file", Name: "osv-rootfs"}}}
	data, _ := json.Marshal(child)
	for name, value := range map[string][]byte{"manifest.json": manifest, "sbom.cdx.json": data} {
		if err := os.WriteFile(filepath.Join(artifacts, name), value, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := catalogTemplateComponent("python-science=" + dir)
	if err != nil || c.BOMRef != "urn:osv:template:python-science" || len(c.Components) != 0 || len(c.ExternalReferences) != 1 || c.Hashes[0].Content != testDigest(string(manifest)) || c.ExternalReferences[0].Hashes[0].Content != testDigest(string(data)) {
		t.Fatal("additional guest BOM was merged into or detached from the Linux image", c, err)
	}
	if c.ExternalReferences[0].Type != "bom" || c.ExternalReferences[0].URL != "../templates/python-science/artifacts/sbom.cdx.json" {
		t.Fatal("BOM reference does not resolve inside the release")
	}
	if _, err := catalogTemplateComponent("../bad=" + dir); err == nil {
		t.Fatal("unsafe catalog id accepted")
	}
	if err := os.WriteFile(filepath.Join(artifacts, "manifest.json"), []byte(`{"protocol":"osv-sandbox-artifacts/v3","backend":"firecracker-linux"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := catalogTemplateComponent("python-science=" + dir); err == nil {
		t.Fatal("wrong template profile accepted")
	}
}

func TestLinuxCodeTemplateBOMBindsV5ProfileImageAndRuntime(t *testing.T) {
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	imageSHA, inventorySHA := testDigest("code-image"), testDigest("runtime-inventory")
	manifest := sandbox.SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v5", Backend: "firecracker-linux",
		AgentFeatures: []string{"code-contexts-v1", "workspace-watch-v1"},
		Image:         sandbox.Artifact{SHA256: imageSHA},
		CodeRuntime: &sandbox.SignedCodeRuntime{Architecture: "arm64", KernelProtocol: "osv-code-kernel/v2",
			PythonVersion: "3.12.16", NodeVersion: "22.23.4", TypeScriptVersion: "5.9.3", PrewarmLanguage: "python",
			RuntimeInventorySHA256: inventorySHA, MinimumCPUFeatures: []string{"asimd"},
			KernelScriptsSHA256: map[string]string{"python.py": testDigest("py"), "node.cjs": testDigest("js")}},
	}
	child := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", Components: []component{{
		Type: "file", Name: "linux-agent-rootfs", Hashes: []hash{{Algorithm: "SHA-256", Content: imageSHA}},
		Properties: []property{{Name: "osv:runtime-inventory-sha256", Value: inventorySHA}},
	}}}
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifacts, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", manifest)
	write("sbom.cdx.json", child)
	entry, err := catalogTemplateComponent("linux-code=" + dir)
	if err != nil || entry.Version != "signed-manifest-v5" || entry.BOMRef != "urn:osv:template:linux-code" || len(entry.Components) != 0 {
		t.Fatal("Linux v5 template BOM cannot be referenced separately", entry, err)
	}
	for _, change := range []string{"image", "inventory", "cpu", "runtime", "protocol", "feature"} {
		t.Run(change, func(t *testing.T) {
			// Decode fresh copies so each case mutates only one binding.
			data, _ := json.Marshal(manifest)
			var changed sandbox.SignedArtifactManifest
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "image":
				changed.Image.SHA256 = testDigest("different-image")
			case "inventory":
				changed.CodeRuntime.RuntimeInventorySHA256 = testDigest("different-runtime")
			case "cpu":
				changed.CodeRuntime.MinimumCPUFeatures = []string{"sse4_1"}
			case "runtime":
				changed.CodeRuntime = nil
			case "protocol":
				changed.Protocol = "osv-sandbox-artifacts/v4"
			case "feature":
				changed.AgentFeatures = []string{"workspace-watch-v1"}
			}
			write("manifest.json", changed)
			if _, err := catalogTemplateComponent("linux-code=" + dir); err == nil {
				t.Fatal("mismatched code template accepted")
			}
		})
	}
}

func TestLinuxV6TemplateBOMBindsCodeAndPortOnlyImages(t *testing.T) {
	for _, code := range []bool{false, true} {
		t.Run(map[bool]string{false: "ports", true: "code_ports"}[code], func(t *testing.T) {
			dir := t.TempDir()
			artifacts := filepath.Join(dir, "artifacts")
			if err := os.Mkdir(artifacts, 0o700); err != nil {
				t.Fatal(err)
			}
			image, inventory := testDigest("image"), testDigest("inventory")
			m := sandbox.SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v6", Backend: "firecracker-linux", AgentFeatures: []string{"port-forward-v1"}, Image: sandbox.Artifact{SHA256: image}}
			if code {
				m.AgentFeatures = []string{"code-contexts-v1", "port-forward-v1"}
				m.CodeRuntime = &sandbox.SignedCodeRuntime{Architecture: "amd64", KernelProtocol: "osv-code-kernel/v2", PythonVersion: "3.12.16", NodeVersion: "22.23.4", TypeScriptVersion: "5.9.3", PrewarmLanguage: "python", RuntimeInventorySHA256: inventory, KernelScriptsSHA256: map[string]string{"python.py": testDigest("py"), "node.cjs": testDigest("js")}, MinimumCPUFeatures: []string{"sse4_1"}}
			}
			child := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", Components: []component{{Type: "file", Name: "linux-agent-rootfs", Hashes: []hash{{Algorithm: "SHA-256", Content: image}}, Properties: []property{{Name: "osv:runtime-inventory-sha256", Value: inventory}}}}}
			write := func(name string, value any) {
				data, _ := json.Marshal(value)
				if err := os.WriteFile(filepath.Join(artifacts, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("manifest.json", m)
			write("sbom.cdx.json", child)
			c, err := catalogTemplateComponent("linux-native=" + dir)
			if err != nil || c.Version != "signed-manifest-v6" {
				t.Fatal(c, err)
			}
			child.Components[0].Hashes[0].Content = testDigest("wrong")
			write("sbom.cdx.json", child)
			if _, err := catalogTemplateComponent("linux-native=" + dir); err == nil {
				t.Fatal("v6 wrong image BOM accepted")
			}
		})
	}
}
