package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	root := flag.String("artifact-root", "", "directory containing the signed artifacts")
	kernel := flag.String("kernel", "", "kernel path relative to artifact root")
	kernelSHA256 := flag.String("kernel-sha256", "", "trusted expected kernel SHA-256")
	image := flag.String("image", "", "image path relative to artifact root")
	imageSHA256 := flag.String("image-sha256", "", "trusted expected image SHA-256")
	backend := flag.String("backend", "", "trusted expected backend")
	firecracker := flag.String("firecracker", "", "Firecracker binary to verify")
	jailer := flag.String("jailer", "", "jailer binary to verify")
	manifest := flag.String("manifest", "", "manifest path relative to artifact root")
	signature := flag.String("signature", "", "signature path relative to artifact root")
	sbom := flag.String("sbom", "", "SBOM path relative to artifact root")
	publicKey := flag.String("public-key", "", "trusted Ed25519 public key obtained separately")
	var entrypoints []string
	flag.Func("entrypoint", "trusted allowed OSv module path; repeat for each module", func(path string) error {
		entrypoints = append(entrypoints, path)
		return nil
	})
	flag.Parse()
	for name, value := range map[string]string{
		"artifact-root": *root, "kernel": *kernel, "kernel-sha256": *kernelSHA256,
		"image": *image, "image-sha256": *imageSHA256, "backend": *backend,
		"firecracker": *firecracker, "jailer": *jailer, "manifest": *manifest,
		"signature": *signature, "sbom": *sbom, "public-key": *publicKey,
	} {
		if value == "" {
			fail("-%s is required", name)
		}
	}
	config := sandbox.Config{
		ArtifactRoot: *root, Backend: *backend, HypervisorPath: *firecracker,
		Kernel: sandbox.Artifact{Path: *kernel, SHA256: *kernelSHA256},
		Image:  sandbox.Artifact{Path: *image, SHA256: *imageSHA256, Format: "raw"},
		Jailer: &sandbox.JailerConfig{Path: *jailer}, AllowedEntrypoints: entrypoints,
		ArtifactManifest: &sandbox.ArtifactManifestConfig{
			Path: *manifest, SignaturePath: *signature,
			PublicKeyPath: *publicKey, SBOMPath: *sbom,
		},
	}
	resolved, err := sandbox.ResolveArtifacts(config.ArtifactRoot, config.Kernel, config.Image)
	if err != nil {
		fail("resolve trusted artifacts: %v", err)
	}
	if err := sandbox.VerifyArtifactManifest(config, resolved); err != nil {
		fail("verify signed artifact manifest: %v", err)
	}
	fmt.Printf("verified signed artifacts backend=%s kernel=%s image=%s entrypoints=%d\n",
		config.Backend, config.Kernel.SHA256, config.Image.SHA256, len(entrypoints))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
