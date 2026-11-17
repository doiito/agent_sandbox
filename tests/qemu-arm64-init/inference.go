package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

// Exercise the production signature/image/BOM verifier against the installed
// actual ARM package. Older rollback fixtures have no v7 template.
func inferenceTemplateProbe(root string) bool {
	directory := filepath.Join(root, "templates/linux-code/artifacts")
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if os.IsNotExist(err) {
		return true
	}
	var manifest sandbox.SignedArtifactManifest
	if err != nil || json.Unmarshal(data, &manifest) != nil {
		fmt.Println("FAIL bundled-inference-v7: cannot read profile")
		return false
	}
	if manifest.Protocol != "osv-sandbox-artifacts/v7" {
		return true
	}
	if manifest.GuestInference == nil || manifest.GuestInference.Architecture != "arm64" {
		fmt.Println("FAIL bundled-inference-v7: wrong architecture or SDK")
		return false
	}
	config := sandbox.Config{
		ArtifactRoot: directory, Backend: "firecracker-linux",
		Kernel: manifest.Kernel, Image: manifest.Image,
		HypervisorPath: filepath.Join(root, "bin/firecracker"),
		Jailer:         &sandbox.JailerConfig{Path: filepath.Join(root, "bin/jailer")},
		ArtifactManifest: &sandbox.ArtifactManifestConfig{Path: "manifest.json", SignaturePath: "manifest.json.sig",
			PublicKeyPath: "/artifact.public", SBOMPath: "sbom.cdx.json"},
	}
	resolved, err := sandbox.ResolveArtifacts(directory, config.Kernel, config.Image)
	if err == nil {
		err = sandbox.VerifyArtifactManifest(config, resolved)
	}
	if err != nil {
		fmt.Println("FAIL bundled-inference-v7:", err)
		return false
	}
	fmt.Println("PASS bundled-inference-v7")
	return true
}
