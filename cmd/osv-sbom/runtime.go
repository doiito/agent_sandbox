package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const rootfsReference = "urn:osv:artifact:osv-rootfs"
const kernelReference = "urn:osv:artifact:osv-kernel"

type runtimeInputDocument struct {
	Protocol                  string                 `json:"protocol"`
	RootfsSHA256              string                 `json:"rootfs_sha256"`
	InventorySHA256           string                 `json:"inventory_sha256"`
	ProvenanceSHA256          string                 `json:"provenance_sha256"`
	FilesCount                int                    `json:"files_count"`
	Components                []component            `json:"components"`
	Dependencies              []dependency           `json:"dependencies"`
	UnresolvedVersions        []string               `json:"unresolved_versions"`
	FileCoverageComplete      bool                   `json:"file_coverage_complete"`
	VersionCoverageComplete   bool                   `json:"version_coverage_complete"`
	StaticComponentAudit      string                 `json:"static_component_audit"`
	VulnerabilityScanComplete bool                   `json:"vulnerability_scan_complete"`
	ImageBaseFiles            []runtimeInventoryFile `json:"image_base_files"`
}

type runtimeInventoryFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Symlink string `json:"symlink,omitempty"`
}

func mergeRuntime(document *bom, inputPath, inventoryPath string) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return errors.New("runtime input exceeds 16 MiB")
	}
	var input runtimeInputDocument
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	if input.Protocol != "osv-runtime-sbom-input/v1" || !input.FileCoverageComplete || input.FilesCount <= 0 {
		return errors.New("unsupported or incomplete runtime file inventory")
	}
	if input.VulnerabilityScanComplete {
		return errors.New("runtime component input cannot assert a vulnerability scan without scan evidence")
	}
	rootIndex := -1
	refs := make(map[string]struct{})
	for index := range document.Components {
		entry := &document.Components[index]
		entry.BOMRef = "urn:osv:artifact:" + entry.Name
		refs[entry.BOMRef] = struct{}{}
		if entry.Name == "osv-rootfs" {
			rootIndex = index
		}
	}
	if rootIndex < 0 {
		return errors.New("OSv rootfs component missing")
	}
	root := &document.Components[rootIndex]
	if len(root.Hashes) != 1 || root.Hashes[0].Content != input.RootfsSHA256 {
		return errors.New("runtime components refer to a different rootfs image")
	}
	inventory, err := os.ReadFile(inventoryPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(inventory)
	if hex.EncodeToString(digest[:]) != input.InventorySHA256 {
		return errors.New("runtime components refer to a different sealed inventory")
	}
	var inventoryDocument struct {
		Protocol string                 `json:"protocol"`
		Files    []runtimeInventoryFile `json:"files"`
	}
	if err := json.Unmarshal(inventory, &inventoryDocument); err != nil {
		return err
	}
	if inventoryDocument.Protocol != "osv-python-science-runtime/v2" || len(inventoryDocument.Files) == 0 {
		return errors.New("runtime component input requires a nonempty v2 sealed inventory")
	}
	expectedFiles := make(map[string]runtimeInventoryFile)
	for _, entry := range inventoryDocument.Files {
		if entry.Path == "" {
			return errors.New("empty inventory file path")
		}
		if _, exists := expectedFiles[entry.Path]; exists {
			return errors.New("duplicate inventory file path")
		}
		expectedFiles[entry.Path] = entry
	}
	expectedFiles["/runtime-inventory.json"] = runtimeInventoryFile{Path: "/runtime-inventory.json", SHA256: input.InventorySHA256}
	if len(input.ImageBaseFiles) == 0 {
		return errors.New("runtime input lacks independently inspected image base files")
	}
	for _, entry := range input.ImageBaseFiles {
		if entry.Path == "" {
			return errors.New("empty image base file path")
		}
		if _, exists := expectedFiles[entry.Path]; exists {
			return errors.New("duplicate image base file path")
		}
		expectedFiles[entry.Path] = entry
	}
	if len(expectedFiles) != input.FilesCount {
		return errors.New("runtime inventory file count mismatch")
	}
	files := 0
	matchedInventory := false
	matchedProvenance := false
	seenFilePaths := make(map[string]struct{})
	runtimeRefs := make(map[string]struct{})
	var visit func(component, int) error
	visit = func(entry component, depth int) error {
		if depth > 8 || entry.Name == "" || entry.BOMRef == "" {
			return errors.New("missing runtime component identity or excessive nesting")
		}
		if !strings.HasPrefix(entry.BOMRef, "runtime:") && !strings.HasPrefix(entry.BOMRef, "pkg:") {
			return errors.New("runtime component uses a reserved outer reference")
		}
		if _, exists := refs[entry.BOMRef]; exists {
			return fmt.Errorf("duplicate component reference %q", entry.BOMRef)
		}
		refs[entry.BOMRef] = struct{}{}
		runtimeRefs[entry.BOMRef] = struct{}{}
		if entry.Type == "file" {
			// Package-level project source descriptors are not filesystem leaves.
			if strings.HasPrefix(entry.BOMRef, "runtime:file:") {
				files++
				wanted, exists := expectedFiles[entry.Name]
				if !exists {
					return errors.New("runtime file is absent from image inventory")
				}
				if _, duplicate := seenFilePaths[entry.Name]; duplicate {
					return errors.New("duplicate runtime file path")
				}
				seenFilePaths[entry.Name] = struct{}{}
				if len(entry.Hashes) != 1 {
					link := false
					for _, property := range entry.Properties {
						if property.Name == "osv:symlink-target" && property.Value != "" && property.Value == wanted.Symlink && wanted.SHA256 == "" {
							link = true
						}
					}
					if len(entry.Hashes) != 0 || !link {
						return errors.New("runtime file lacks a unique digest or symlink target")
					}
				} else if entry.Hashes[0].Algorithm != "SHA-256" || len(entry.Hashes[0].Content) != 64 {
					return errors.New("invalid runtime file SHA-256")
				} else if _, err := hex.DecodeString(entry.Hashes[0].Content); err != nil {
					return err
				} else if entry.Hashes[0].Content != wanted.SHA256 || wanted.Symlink != "" {
					return errors.New("runtime file differs from sealed image inventory")
				}
				if entry.Name == "/runtime-inventory.json" {
					matchedInventory = len(entry.Hashes) == 1 && entry.Hashes[0].Content == input.InventorySHA256
				}
				if entry.Name == "/runtime-components.json" {
					matchedProvenance = len(entry.Hashes) == 1 && entry.Hashes[0].Content == input.ProvenanceSHA256
				}
			}
		}
		for _, child := range entry.Components {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, entry := range input.Components {
		if err := visit(entry, 0); err != nil {
			return err
		}
	}
	if files != input.FilesCount || !matchedInventory || !matchedProvenance {
		return errors.New("runtime file coverage count or embedded inventory digest mismatch")
	}
	seen := make(map[string]struct{})
	for _, edge := range input.Dependencies {
		if _, exists := refs[edge.Ref]; !exists {
			return fmt.Errorf("unknown dependency source %q", edge.Ref)
		}
		if _, exists := runtimeRefs[edge.Ref]; !exists && edge.Ref != rootfsReference {
			return errors.New("runtime dependency cannot redefine an outer host component")
		}
		if _, duplicate := seen[edge.Ref]; duplicate {
			return errors.New("duplicate dependency source")
		}
		seen[edge.Ref] = struct{}{}
		targets := make(map[string]struct{})
		for _, target := range edge.DependsOn {
			if _, exists := refs[target]; !exists {
				return fmt.Errorf("unknown dependency target %q", target)
			}
			if _, exists := runtimeRefs[target]; !exists && target != kernelReference {
				return errors.New("runtime dependency cannot target a host component")
			}
			if _, duplicate := targets[target]; duplicate {
				return errors.New("duplicate dependency target")
			}
			targets[target] = struct{}{}
		}
	}
	if _, exists := seen[rootfsReference]; !exists {
		return errors.New("rootfs dependency assembly missing")
	}
	for _, ref := range input.UnresolvedVersions {
		if _, exists := refs[ref]; !exists {
			return errors.New("unresolved version references an absent component")
		}
	}
	if input.VersionCoverageComplete && (len(input.UnresolvedVersions) != 0 || input.StaticComponentAudit != "complete") {
		return errors.New("runtime component version coverage contradicts unresolved evidence")
	}
	root.Components = input.Components
	root.Properties = append(root.Properties, property{Name: "osv:runtime-inventory-sha256", Value: input.InventorySHA256},
		property{Name: "osv:runtime-component-provenance-sha256", Value: input.ProvenanceSHA256})
	document.Dependencies = input.Dependencies
	coverage := "incomplete"
	if input.VersionCoverageComplete {
		coverage = "complete"
	}
	document.Compositions = []composition{{Aggregate: coverage, Assemblies: []string{rootfsReference}}}
	document.Metadata.Properties = append(document.Metadata.Properties,
		property{Name: "osv:runtime-file-coverage", Value: "complete"},
		property{Name: "osv:component-version-coverage", Value: coverage},
		property{Name: "osv:vulnerability-scan", Value: "not performed"})
	return nil
}
