package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
)

const guestInferenceProfileProtocol = "osv-sandbox-guest-inference/v1"

func validateV7Features(features, required, optional []string) error {
	allowed, seen := map[string]bool{}, map[string]bool{}
	for _, feature := range append(append([]string{}, required...), optional...) {
		allowed[feature] = true
	}
	previous := ""
	for _, feature := range features {
		if !allowed[feature] || feature <= previous {
			return errors.New("unsupported, unsorted or duplicate signed v7 feature")
		}
		seen[feature], previous = true, feature
	}
	for _, feature := range required {
		if !seen[feature] {
			return fmt.Errorf("signed v7 requires %s", feature)
		}
	}
	return nil
}

// SignedGuestInference describes files actually sealed into the signed image.
// It contains no tenant policy, model URL, task identity or credentials.
type SignedGuestInference struct {
	Protocol     string            `json:"protocol"`
	Architecture string            `json:"architecture"`
	Transport    string            `json:"transport"`
	FilesSHA256  map[string]string `json:"files_sha256"`
}

func guestInferencePaths(backend string) []string {
	base := "/opt/python/lib/python3.12/site-packages/"
	paths := []string{base + "remote_infer/__init__.py", base + "remote_infer/_contract.py",
		base + "remote_infer/_transport.py", base + "sandbox.py"}
	if backend == "firecracker-linux" {
		paths = append(paths, "/opt/osv/remote-infer.cjs", "/opt/osv/inference-contract.cjs")
	}
	return paths
}

func (p *SignedGuestInference) validate(backend string) error {
	if p == nil || p.Protocol != guestInferenceProfileProtocol {
		return errors.New("missing or unsupported signed guest inference profile")
	}
	switch backend {
	case "firecracker-linux":
		if p.Transport != "linux-loopback-v1" || p.Architecture != "amd64" && p.Architecture != "arm64" {
			return errors.New("invalid Linux guest inference architecture/transport")
		}
	case "firecracker-osv":
		if p.Transport != "osv-vsock-cabi-v1" || p.Architecture != "amd64" {
			return errors.New("invalid OSv guest inference architecture/transport")
		}
	default:
		return errors.New("unsupported guest inference backend")
	}
	paths := guestInferencePaths(backend)
	if len(p.FilesSHA256) != len(paths) {
		return errors.New("incomplete or unexpected signed guest SDK files")
	}
	for _, path := range paths {
		if !validSHA256Hex(p.FilesSHA256[path]) {
			return fmt.Errorf("missing or invalid signed guest SDK digest: %s", path)
		}
	}
	return nil
}

// ValidateGuestInferenceSBOM checks the trusted publisher's file facts under
// the matching image component. Image construction independently extracts the
// filesystem before producing these facts. Runtime needs no filesystem tools.
func (m SignedArtifactManifest) ValidateGuestInferenceSBOM(data []byte) error {
	if m.Protocol != "osv-sandbox-artifacts/v7" && !(m.Protocol == "osv-sandbox-artifacts/v8" && m.Backend == "firecracker-linux") {
		return errors.New("guest inference BOM requires signed v7 or Linux v8")
	}
	if err := m.GuestInference.validate(m.Backend); err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("guest inference BOM exceeds size limit")
	}
	type hash struct {
		Algorithm string `json:"alg"`
		Content   string `json:"content"`
	}
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type component struct {
		Type       string            `json:"type"`
		Name       string            `json:"name"`
		Hashes     []hash            `json:"hashes"`
		Properties []property        `json:"properties"`
		Components []json.RawMessage `json:"components"`
	}
	var document struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if json.Unmarshal(data, &document) != nil || document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.5" {
		return errors.New("invalid guest inference BOM")
	}
	rootName := "linux-agent-rootfs"
	if m.Backend == "firecracker-osv" {
		rootName = "osv-rootfs"
	}
	var image *component
	for _, raw := range document.Components {
		var candidate component
		if json.Unmarshal(raw, &candidate) != nil {
			return errors.New("invalid image BOM component")
		}
		if candidate.Name == rootName {
			if image != nil {
				return errors.New("duplicate image BOM component")
			}
			image = &candidate
		}
	}
	if image == nil || image.Type != "file" || len(image.Hashes) != 1 || image.Hashes[0].Algorithm != "SHA-256" || image.Hashes[0].Content != m.Image.SHA256 {
		return errors.New("guest SDK BOM image differs from signed image")
	}
	seen, count := map[string]bool{}, 0
	var visit func(json.RawMessage, int) error
	visit = func(raw json.RawMessage, depth int) error {
		count++
		if depth > 16 || count > 100000 {
			return errors.New("guest SDK BOM nesting/count exceeds limit")
		}
		var entry component
		if json.Unmarshal(raw, &entry) != nil {
			return errors.New("invalid guest SDK BOM entry")
		}
		if wanted, ok := m.GuestInference.FilesSHA256[entry.Name]; ok {
			if seen[entry.Name] || entry.Type != "file" || len(entry.Components) != 0 || len(entry.Hashes) != 1 ||
				entry.Hashes[0].Algorithm != "SHA-256" || entry.Hashes[0].Content != wanted {
				return errors.New("guest SDK BOM file missing, duplicate or inconsistent")
			}
			for _, p := range entry.Properties {
				if p.Name == "osv:symlink-target" {
					return errors.New("guest SDK file must not be a symlink")
				}
			}
			seen[entry.Name] = true
		}
		for _, child := range entry.Components {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range image.Components {
		if err := visit(child, 0); err != nil {
			return err
		}
	}
	if len(seen) != len(m.GuestInference.FilesSHA256) {
		return errors.New("signed guest SDK files absent from image BOM")
	}
	return nil
}
