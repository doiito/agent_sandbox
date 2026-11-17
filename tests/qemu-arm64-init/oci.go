package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Exercise the actual installed ARM CLI against its own signed base artifacts.
// Old rollback packages and the small protocol fixture predate this tool.
func ociTemplateProbe(root string) bool {
	tool := filepath.Join(root, "bin/osv-template-oci")
	if _, err := os.Stat(tool); os.IsNotExist(err) {
		return true
	}
	fail := func(err error) bool { fmt.Println("FAIL bundled-template-oci:", err); return false }
	work, err := os.MkdirTemp("/tmp", "oci-installed-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(work)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	options := []string{"-architecture", "arm64", "-backend", "firecracker-linux", "-public-key", "/artifact.public",
		"-firecracker", filepath.Join(root, "bin/firecracker"), "-jailer", filepath.Join(root, "bin/jailer")}
	invoke := func(args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, tool, append(args, options...)...)
		data, err := command.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("installed OCI CLI: %w (%s)", err, data)
		}
		return data, nil
	}
	source, layout, imported := filepath.Join(root, "artifacts"), filepath.Join(work, "layout"), filepath.Join(work, "imported")
	data, err := invoke("export", "-source", source, "-destination", layout)
	if err != nil {
		return fail(err)
	}
	var descriptor struct {
		Digest string `json:"digest"`
	}
	if json.Unmarshal(data, &descriptor) != nil || len(descriptor.Digest) != 71 {
		return fail(fmt.Errorf("invalid descriptor"))
	}
	if _, err := invoke("import", "-source", layout, "-digest", descriptor.Digest, "-destination", imported); err != nil {
		return fail(err)
	}
	for _, name := range []string{"manifest.json", "manifest.json.sig", "sbom.cdx.json", "kernel", "rootfs.ext4"} {
		a, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return fail(err)
		}
		b, err := os.ReadFile(filepath.Join(imported, name))
		if err != nil || !bytes.Equal(a, b) {
			return fail(fmt.Errorf("changed signed artifact %s", name))
		}
	}
	// Verify the host management tool is recorded in the signed root BOM.
	bom, err := os.ReadFile(filepath.Join(source, "sbom.cdx.json"))
	if err != nil {
		return fail(err)
	}
	var document struct {
		Components []struct {
			Name   string `json:"name"`
			Hashes []struct {
				Algorithm string `json:"alg"`
				Content   string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
	}
	if json.Unmarshal(bom, &document) != nil {
		return fail(fmt.Errorf("invalid root BOM"))
	}
	program, err := os.ReadFile(tool)
	if err != nil {
		return fail(err)
	}
	sum := sha256.Sum256(program)
	found := false
	for _, component := range document.Components {
		if component.Name == "osv-template-oci" {
			for _, hash := range component.Hashes {
				found = found || (hash.Algorithm == "SHA-256" && hash.Content == hex.EncodeToString(sum[:]))
			}
		}
	}
	if !found {
		return fail(fmt.Errorf("installed CLI not bound in signed root BOM"))
	}
	if _, err := invoke("import", "-source", layout, "-digest", descriptor.Digest, "-destination", imported); err == nil {
		return fail(fmt.Errorf("existing destination overwritten"))
	}
	fmt.Println("PASS bundled-template-oci")
	return true
}
