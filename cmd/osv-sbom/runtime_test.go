package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDigest(data string) string {
	value := sha256.Sum256([]byte(data))
	return hex.EncodeToString(value[:])
}

func runtimeFixture(t *testing.T) (bom, runtimeInputDocument, string, string) {
	t.Helper()
	directory := t.TempDir()
	inventoryPath := filepath.Join(directory, "inventory.json")
	provenanceHash := testDigest("actual component provenance")
	inventory := `{"protocol":"osv-python-science-runtime/v2","files":[{"path":"/runtime-components.json","sha256":"` + provenanceHash + `"}]}`
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0600); err != nil {
		t.Fatal(err)
	}
	input := runtimeInputDocument{Protocol: "osv-runtime-sbom-input/v1", RootfsSHA256: testDigest("image"),
		InventorySHA256: testDigest(inventory), ProvenanceSHA256: provenanceHash, FilesCount: 3, FileCoverageComplete: true,
		StaticComponentAudit: "partial", ImageBaseFiles: []runtimeInventoryFile{{Path: "/etc/fstab", SHA256: testDigest("fstab")}},
		Components: []component{{Type: "library", BOMRef: "runtime:example", Name: "example", Components: []component{
			{Type: "file", BOMRef: "runtime:file:/runtime-components.json", Name: "/runtime-components.json", Hashes: []hash{{Algorithm: "SHA-256", Content: provenanceHash}}},
			{Type: "file", BOMRef: "runtime:file:/runtime-inventory.json", Name: "/runtime-inventory.json", Hashes: []hash{{Algorithm: "SHA-256", Content: testDigest(inventory)}}},
			{Type: "file", BOMRef: "runtime:file:/etc/fstab", Name: "/etc/fstab", Hashes: []hash{{Algorithm: "SHA-256", Content: testDigest("fstab")}}},
		}}}, Dependencies: []dependency{{Ref: rootfsReference, DependsOn: []string{kernelReference, "runtime:example"}}}}
	document := bom{Components: []component{{Type: "file", Name: "osv-rootfs", Hashes: []hash{{Algorithm: "SHA-256", Content: input.RootfsSHA256}}},
		{Type: "file", Name: "osv-kernel"}, {Type: "file", Name: "osv-sandboxd"}}}
	return document, input, filepath.Join(directory, "input.json"), inventoryPath
}

func mergeFixture(t *testing.T, document *bom, input runtimeInputDocument, path, inventory string) error {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return mergeRuntime(document, path, inventory)
}

func TestRuntimeSBOMBindsImageInventoryAndPreservesOuterArtifacts(t *testing.T) {
	document, input, path, inventory := runtimeFixture(t)
	if err := mergeFixture(t, &document, input, path, inventory); err != nil {
		t.Fatal(err)
	}
	if len(document.Components) != 3 || document.Components[0].Name != "osv-rootfs" || len(document.Components[0].Components) != 1 {
		t.Fatal("runtime packages must be nested below the authenticated rootfs")
	}
	if document.Components[0].Hashes[0].Content != testDigest("image") || document.Compositions[0].Aggregate != "incomplete" {
		t.Fatal("outer digest or unresolved composition changed")
	}
}

func TestRuntimeSBOMRejectsFalseCoverageAndCrossArtifactClaims(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*runtimeInputDocument)
		message string
	}{
		{"wrong image", func(i *runtimeInputDocument) { i.RootfsSHA256 = testDigest("other") }, "different rootfs"},
		{"wrong inventory", func(i *runtimeInputDocument) { i.InventorySHA256 = testDigest("other") }, "different sealed inventory"},
		{"wrong component file", func(i *runtimeInputDocument) { i.Components[0].Components[0].Hashes[0].Content = testDigest("other") }, "differs from sealed"},
		{"missing file", func(i *runtimeInputDocument) { i.Components[0].Components = i.Components[0].Components[:2] }, "coverage count"},
		{"duplicate reference", func(i *runtimeInputDocument) { i.Components = append(i.Components, i.Components[0]) }, "duplicate component reference"},
		{"duplicate file path", func(i *runtimeInputDocument) {
			c := i.Components[0].Components[0]
			c.BOMRef = "runtime:file:alias"
			i.Components[0].Components = append(i.Components[0].Components, c)
		}, "duplicate runtime file path"},
		{"wrong provenance", func(i *runtimeInputDocument) { i.ProvenanceSHA256 = testDigest("other") }, "embedded inventory"},
		{"unscanned safe claim", func(i *runtimeInputDocument) { i.VulnerabilityScanComplete = true }, "without scan evidence"},
		{"unresolved complete claim", func(i *runtimeInputDocument) {
			i.VersionCoverageComplete = true
			i.UnresolvedVersions = []string{"runtime:example"}
		}, "contradicts unresolved"},
		{"unknown dependency", func(i *runtimeInputDocument) {
			i.Dependencies[0].DependsOn = append(i.Dependencies[0].DependsOn, "runtime:absent")
		}, "unknown dependency target"},
		{"host dependency", func(i *runtimeInputDocument) {
			i.Dependencies[0].DependsOn = append(i.Dependencies[0].DependsOn, "urn:osv:artifact:osv-sandboxd")
		}, "target a host"},
		{"host rewrite", func(i *runtimeInputDocument) {
			i.Dependencies = append(i.Dependencies, dependency{Ref: "urn:osv:artifact:osv-sandboxd"})
		}, "redefine an outer"},
		{"no image inspection", func(i *runtimeInputDocument) { i.ImageBaseFiles = nil }, "independently inspected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document, input, path, inventory := runtimeFixture(t)
			tc.mutate(&input)
			if err := mergeFixture(t, &document, input, path, inventory); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("wanted %q, got %v", tc.message, err)
			}
		})
	}
}
