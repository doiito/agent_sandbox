package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func catalogTemplateComponent(spec string) (component, error) {
	id, directory, ok := strings.Cut(spec, "=")
	if !ok || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`).MatchString(id) || directory == "" {
		return component{}, errors.New("expected safe template ID=DIRECTORY")
	}
	var manifest sandbox.SignedArtifactManifest
	data, err := os.ReadFile(filepath.Join(directory, "artifacts/manifest.json"))
	if err != nil {
		return component{}, err
	}
	if json.Unmarshal(data, &manifest) != nil {
		return component{}, errors.New("invalid additional template manifest")
	}
	linux := (manifest.Protocol == "osv-sandbox-artifacts/v5" || manifest.Protocol == "osv-sandbox-artifacts/v6" || manifest.Protocol == "osv-sandbox-artifacts/v7" || manifest.Protocol == "osv-sandbox-artifacts/v8") && manifest.Backend == "firecracker-linux"
	code := linux && manifest.CodeRuntime != nil
	if linux {
		if err := manifest.ValidateProfile("firecracker-linux", nil); err != nil {
			return component{}, err
		}
	} else if (manifest.Protocol != "osv-sandbox-artifacts/v2" && manifest.Protocol != "osv-sandbox-artifacts/v7") || manifest.Backend != "firecracker-osv" {
		return component{}, errors.New("additional template must be a supported signed OSv or Linux profile")
	} else if manifest.Protocol == "osv-sandbox-artifacts/v7" {
		if err := manifest.ValidateProfile("firecracker-osv", manifest.Entrypoints); err != nil {
			return component{}, err
		}
	}
	var child bom
	data, err = os.ReadFile(filepath.Join(directory, "artifacts/sbom.cdx.json"))
	if err != nil {
		return component{}, err
	}
	if json.Unmarshal(data, &child) != nil || child.BOMFormat != "CycloneDX" || child.SpecVersion != "1.5" || len(child.Components) == 0 {
		return component{}, errors.New("missing child template BOM")
	}
	if manifest.GuestInference != nil {
		if err := manifest.ValidateGuestInferenceSBOM(data); err != nil {
			return component{}, err
		}
	}
	if linux {
		imageMatched, matched := false, !code
		for _, entry := range child.Components {
			if entry.Name != "linux-agent-rootfs" || len(entry.Hashes) != 1 || entry.Hashes[0].Algorithm != "SHA-256" || entry.Hashes[0].Content != manifest.Image.SHA256 {
				continue
			}
			imageMatched = true
			if !code {
				continue
			}
			for _, property := range entry.Properties {
				matched = matched || property.Name == "osv:runtime-inventory-sha256" && property.Value == manifest.CodeRuntime.RuntimeInventorySHA256
			}
		}
		if !imageMatched || !matched {
			return component{}, errors.New("Linux code child BOM differs from signed image or runtime inventory")
		}
	}
	c := fileComponent("signed-template-"+id, filepath.Join(directory, "artifacts/manifest.json"))
	c.Type = "application"
	c.BOMRef = "urn:osv:template:" + id
	c.Version = "signed-manifest-" + strings.TrimPrefix(manifest.Protocol, "osv-sandbox-artifacts/")
	childFile := fileComponent("child-bom", filepath.Join(directory, "artifacts/sbom.cdx.json"))
	c.ExternalReferences = []externalReference{{Type: "bom", URL: "../templates/" + id + "/artifacts/sbom.cdx.json", Hashes: childFile.Hashes}}
	c.Properties = []property{{Name: "osv:template:id", Value: id}, {Name: "osv:template:backend", Value: manifest.Backend}, {Name: "osv:template:runtime-bom", Value: "separate signed image and component inventory"}}
	return c, nil
}
