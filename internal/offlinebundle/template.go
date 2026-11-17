package offlinebundle

import "strings"

// Templates carry only signed guest data and provenance, never host launch
// hooks, credentials or arbitrary executable locations.
func allowedTemplateFile(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) < 3 || parts[0] != "templates" || len(parts[1]) == 0 || len(parts[1]) > 32 {
		return false
	}
	for _, ch := range parts[1] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	if len(parts) == 3 {
		return parts[2] == "template.json"
	}
	if len(parts) != 4 {
		return false
	}
	if parts[2] == "artifacts" {
		switch parts[3] {
		case "kernel", "rootfs.ext4", "kernel.elf", "rootfs.raw", "osv-job-agent.so", "python3.12.so", "manifest.json", "manifest.json.sig", "sbom.cdx.json", "runtime-inventory.json", "runtime-sbom-input.json":
			return true
		}
	}
	if parts[2] == "docs" {
		switch parts[3] {
		case "image-build-provenance.json", "kernel-LICENSE.txt", "runtime-licenses.tar.gz", "runtime-components.json",
			"image-inventory.json", "runtime-inventory.json", "source-lock.json", "code-runtime.json", "guest-inference.json", "runtime-license-paths.json", "readonly-input-profile.json":
			return true
		}
	}
	return false
}
