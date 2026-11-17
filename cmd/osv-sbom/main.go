package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/doiito/agent_sandbox/internal/releasebuild"
	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type component struct {
	ExternalReferences []externalReference `json:"externalReferences,omitempty"`
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Hashes             []hash              `json:"hashes,omitempty"`
	Properties         []property          `json:"properties,omitempty"`
	Licenses           []licenseChoice     `json:"licenses,omitempty"`
	Components         []component         `json:"components,omitempty"`
}

type externalReference struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Hashes []hash `json:"hashes,omitempty"`
}

type licenseChoice struct {
	License    *licenseText `json:"license,omitempty"`
	Expression string       `json:"expression,omitempty"`
}

type licenseText struct {
	Name string        `json:"name,omitempty"`
	ID   string        `json:"id,omitempty"`
	Text *attachedText `json:"text,omitempty"`
}

type attachedText struct {
	ContentType string `json:"contentType"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type composition struct {
	Aggregate  string   `json:"aggregate"`
	Assemblies []string `json:"assemblies"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type bom struct {
	BOMFormat    string        `json:"bomFormat"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber"`
	Version      int           `json:"version"`
	Metadata     metadata      `json:"metadata"`
	Components   []component   `json:"components"`
	Dependencies []dependency  `json:"dependencies,omitempty"`
	Compositions []composition `json:"compositions,omitempty"`
}

type metadata struct {
	Timestamp  string     `json:"timestamp"`
	Component  component  `json:"component"`
	Properties []property `json:"properties,omitempty"`
}

type cargoMetadata struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  string `json:"source"`
	} `json:"packages"`
}

func main() {
	output := flag.String("output", "sbom.cdx.json", "CycloneDX output")
	profile := flag.String("profile", "linux", "guest profile: linux or osv")
	bashBinary := flag.String("bash", "", "static GNU Bash binary packaged inside Linux rootfs")
	bashSourceLock := flag.String("bash-source-lock", "", "GNU Bash source lock")
	osvUpstreamCommit := flag.String("osv-upstream-commit", "", "fixed OSv upstream commit for the OSv profile")
	var modules []string
	var templates []string
	flag.Func("template-bom", "additional signed template ID=DIRECTORY; repeat for each catalog template", func(spec string) error { templates = append(templates, spec); return nil })
	flag.Func("module", "OSv module GUEST_PATH=BUILD_FILE; repeat for each module", func(spec string) error {
		modules = append(modules, spec)
		return nil
	})
	cargoManifest := flag.String("cargo-manifest", "linux-guest/Cargo.toml", "guest Cargo.toml")
	kernel := flag.String("kernel", "", "kernel artifact")
	rootfs := flag.String("rootfs", "", "rootfs artifact")
	agent := flag.String("agent", "", "guest agent binary")
	supervisor := flag.String("workload-supervisor", "", "static private Linux workload supervisor")
	api := flag.String("api", "", "unprivileged API binary")
	apiGoLicenses := flag.String("api-go-licenses", "", "write notices for vendored Go modules linked into the API binary")
	launcher := flag.String("launcher", "", "privileged launcher binary")
	mcp := flag.String("mcp", "", "optional static MCP stdio gateway binary")
	egress := flag.String("egress", "", "optional static authenticated egress worker binary")
	templateOCI := flag.String("template-oci", "", "optional static signed-template OCI management binary for the root Linux release BOM")
	guestHTTP := flag.String("guest-http", "", "optional static HTTP/TLS client inside Linux rootfs")
	egressRoots := flag.String("egress-roots", "", "offline public CA bundle")
	egressRootsProvenance := flag.String("egress-roots-provenance", "", "public CA source lock")
	egressRootsLicense := flag.String("egress-roots-license", "", "public CA license")
	firecracker := flag.String("firecracker", "", "Firecracker executable")
	jailer := flag.String("jailer", "", "jailer executable")
	clientSDK := flag.String("client-sdk", "", "optional Python client source file for Linux release SBOM")
	clientNodeJS := flag.String("client-node-js", "", "optional Node.js client source file for Linux release SBOM")
	clientNodeTypes := flag.String("client-node-types", "", "optional Node.js client type declaration for Linux release SBOM")
	allocatorPolicy := flag.String("allocator-policy", "", "Linux musl allocator source policy")
	allocatorArchive := flag.String("allocator-archive", "", "actual statically linked mimalloc C archive")
	allocatorProvenance := flag.String("allocator-provenance", "", "Linux musl allocator build provenance")
	runtimeInput := flag.String("runtime-components", "", "hash-bound OSv runtime SBOM input")
	runtimeInventory := flag.String("runtime-inventory", "", "sealed OSv runtime file inventory")
	flag.Parse()
	for name, value := range map[string]string{"kernel": *kernel, "rootfs": *rootfs, "agent": *agent, "api": *api, "launcher": *launcher, "firecracker": *firecracker, "jailer": *jailer} {
		if value == "" {
			fatalf("-%s is required", name)
		}
	}
	apiComponent := fileComponent("osv-sandboxd", *api)
	var components []component
	if *apiGoLicenses != "" {
		modules, err := apiGoModules(*api, "vendor", *apiGoLicenses)
		if err != nil {
			fatalf("API Go modules: %v", err)
		}
		apiComponent.Components = modules
		components = append(components, fileComponent("osv-sandboxd-go-module-licenses", *apiGoLicenses))
	}
	components = append(components, fileComponent("firecracker", *firecracker), fileComponent("jailer", *jailer),
		apiComponent, fileComponent("osv-sandbox-launcher", *launcher))
	if *mcp != "" {
		components = append(components, fileComponent("osv-sandbox-mcp", *mcp))
	}
	if *egress != "" {
		components = append(components, fileComponent("osv-sandbox-egress", *egress))
	}
	if *templateOCI != "" {
		if *profile != "linux" {
			fatalf("template OCI management tool belongs to the root Linux release BOM")
		}
		components = append(components, fileComponent("osv-template-oci", *templateOCI))
	}
	if *egressRoots != "" || *egressRootsProvenance != "" || *egressRootsLicense != "" {
		if *egressRoots == "" || *egressRootsProvenance == "" || *egressRootsLicense == "" {
			fatalf("egress roots, provenance and license must be provided together")
		}
		components = append(components, egressRootsComponents(*egressRoots, *egressRootsProvenance, *egressRootsLicense)...)
	}
	switch *profile {
	case "linux":
		if *guestHTTP != "" {
			components = append(components, fileComponent("osv-http-guest-client", *guestHTTP))
		}
		if (*bashBinary == "") != (*bashSourceLock == "") {
			fatalf("Bash binary and source lock must be provided together")
		}
		if *bashBinary != "" {
			var lock struct {
				Version string `json:"version"`
				URL     string `json:"url"`
				SHA256  string `json:"sha256"`
			}
			data, err := os.ReadFile(*bashSourceLock)
			if err != nil {
				fatalf("read Bash source lock: %v", err)
			}
			if json.Unmarshal(data, &lock) != nil || lock.Version != "5.3" || len(lock.SHA256) != 64 {
				fatalf("invalid Bash source lock")
			}
			c := fileComponent("GNU Bash", *bashBinary)
			c.Version = lock.Version
			c.Licenses = []licenseChoice{{Expression: "GPL-3.0-or-later"}}
			c.Properties = append(c.Properties, property{Name: "source:url", Value: lock.URL}, property{Name: "source:sha256", Value: lock.SHA256})
			components = append(components, c, fileComponent("bash-source-lock", *bashSourceLock))
		}
		if *runtimeInput != "" || *runtimeInventory != "" {
			fatalf("Linux SBOM cannot declare OSv runtime components")
		}
		if *osvUpstreamCommit != "" || len(modules) != 0 {
			fatalf("Linux SBOM cannot declare OSv source or modules")
		}
		components = append(components, fileComponent("linux-kernel", *kernel),
			fileComponent("linux-agent-rootfs", *rootfs), fileComponent("firecracker-linux-agent", *agent),
			component{Type: "library", Name: "busybox-static", Version: "Debian 12 package"})
		if *clientSDK != "" {
			components = append(components, fileComponent("osv-python-client", *clientSDK))
		}
		if (*clientNodeJS == "") != (*clientNodeTypes == "") {
			fatalf("Node client source and types must be provided together")
		}
		if *clientNodeJS != "" {
			components = append(components, fileComponent("osv-node-client", *clientNodeJS),
				fileComponent("osv-node-client-types", *clientNodeTypes))
		}
		allocatorInputs := *allocatorPolicy != "" || *allocatorArchive != "" || *allocatorProvenance != "" || *supervisor != ""
		if allocatorInputs {
			if *allocatorPolicy == "" || *allocatorArchive == "" || *allocatorProvenance == "" {
				fatalf("allocator policy, archive and provenance must be provided together")
			}
			components = append(components, mimallocComponents(*allocatorPolicy, *allocatorArchive, *allocatorProvenance, *supervisor)...)
		}
		command := exec.Command("cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--manifest-path", *cargoManifest)
		data, err := command.Output()
		if err != nil {
			fatalf("cargo metadata: %v", err)
		}
		var cargo cargoMetadata
		if err := json.Unmarshal(data, &cargo); err != nil {
			fatalf("decode cargo metadata: %v", err)
		}
		for _, pkg := range cargo.Packages {
			components = append(components, component{Type: "library", Name: pkg.Name, Version: pkg.Version, PURL: "pkg:cargo/" + pkg.Name + "@" + pkg.Version})
		}
	case "osv":
		if *guestHTTP != "" {
			fatalf("OSv SBOM cannot declare a Linux HTTP client")
		}
		if *bashBinary != "" || *bashSourceLock != "" {
			fatalf("OSv SBOM cannot declare the Linux Bash runtime")
		}
		if *allocatorPolicy != "" || *allocatorArchive != "" || *allocatorProvenance != "" || *supervisor != "" {
			fatalf("OSv SBOM cannot declare the Linux musl allocator")
		}
		if *clientSDK != "" || *clientNodeJS != "" || *clientNodeTypes != "" {
			fatalf("OSv SBOM profile cannot include the Linux release client")
		}
		if len(*osvUpstreamCommit) != 40 || len(modules) == 0 {
			fatalf("OSv SBOM requires a 40-character upstream commit and at least one module")
		}
		for _, ch := range *osvUpstreamCommit {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				fatalf("OSv upstream commit must be lowercase hexadecimal")
			}
		}
		components = append(components, fileComponent("osv-kernel", *kernel),
			fileComponent("osv-rootfs", *rootfs), fileComponent("osv-job-agent", *agent),
			component{Type: "library", Name: "OSv", Version: *osvUpstreamCommit})
		seen := make(map[string]struct{}, len(modules))
		for _, spec := range modules {
			guestPath, buildFile, ok := strings.Cut(spec, "=")
			if !ok || !sandbox.ValidOSvModulePath(guestPath) || buildFile == "" {
				fatalf("OSv module must be GUEST_PATH=BUILD_FILE with a canonical .so guest path")
			}
			if _, exists := seen[guestPath]; exists {
				fatalf("duplicate OSv module path %s", guestPath)
			}
			seen[guestPath] = struct{}{}
			components = append(components, fileComponent("osv-module"+guestPath, buildFile))
		}
	default:
		fatalf("unsupported guest profile %q", *profile)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	created, fixed, err := releasebuild.Timestamp(os.Getenv("SOURCE_DATE_EPOCH"), time.Now())
	if err != nil {
		fatalf("build time: %v", err)
	}
	document := bom{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata:   metadata{Timestamp: created.Format(time.RFC3339), Component: component{Type: "application", Name: "osv-agent-sandbox", Version: "production"}},
		Components: components,
	}
	if len(templates) > 0 {
		if *profile != "linux" {
			fatalf("additional template BOMs belong to the Linux service release")
		}
		seen := map[string]bool{}
		for _, spec := range templates {
			entry, err := catalogTemplateComponent(spec)
			if err != nil {
				fatalf("template BOM: %v", err)
			}
			if seen[entry.BOMRef] {
				fatalf("duplicate template BOM")
			}
			seen[entry.BOMRef] = true
			document.Components = append(document.Components, entry)
		}
	}
	if *runtimeInput != "" || *runtimeInventory != "" {
		if *runtimeInput == "" || *runtimeInventory == "" {
			fatalf("runtime component input and inventory must be provided together")
		}
		if err := mergeRuntime(&document, *runtimeInput, *runtimeInventory); err != nil {
			fatalf("runtime SBOM input: %v", err)
		}
	}
	encoded, err := encodeBOM(document, fixed)
	if err != nil {
		fatalf("encode SBOM: %v", err)
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0o644); err != nil {
		fatalf("write SBOM: %v", err)
	}
	fmt.Printf("sbom=%s\n", *output)
}

func mimallocComponents(policyPath, archivePath, provenancePath, supervisorPath string) []component {
	var policy struct {
		Protocol string `json:"protocol"`
		Binding  struct {
			Version int    `json:"c_version"`
			SHA256  string `json:"sha256"`
		} `json:"c_binding"`
		Policy struct {
			Secure   int  `json:"secure"`
			NoTHP    bool `json:"no_thp"`
			Override bool `json:"c_malloc_override"`
		} `json:"policy"`
	}
	var provenance struct {
		Protocol      string `json:"protocol"`
		Version       int    `json:"c_version"`
		Secure        int    `json:"secure_level"`
		ArchiveSHA256 string `json:"libmimalloc_archive_sha256"`
		Components    map[string]struct {
			Allocator string `json:"allocator"`
			SHA256    string `json:"sha256"`
		} `json:"components"`
	}
	for path, output := range map[string]any{policyPath: &policy, provenancePath: &provenance} {
		data, err := os.ReadFile(path)
		if err != nil {
			fatalf("allocator input: %v", err)
		}
		if err := json.Unmarshal(data, output); err != nil {
			fatalf("allocator input: %v", err)
		}
	}
	archive := fileComponent("mimalloc-c-static", archivePath)
	if policy.Protocol != "osv-musl-allocator-sources/v1" || policy.Binding.Version != 30302 ||
		len(policy.Binding.SHA256) != 64 || policy.Policy.Secure != 4 || !policy.Policy.NoTHP || policy.Policy.Override ||
		(provenance.Protocol != "osv-musl-guest-build/v1" && provenance.Protocol != "osv-musl-guest-build/v2") ||
		provenance.Version != 30302 || provenance.Secure != 4 ||
		provenance.ArchiveSHA256 != archive.Hashes[0].Content {
		fatalf("allocator policy/provenance does not match hardened C 3.3.2 linker input")
	}
	archive.Type = "library"
	archive.Version = "3.3.2"
	archive.Properties = []property{
		{Name: "osv:linkage", Value: "static Rust global allocator; C malloc override disabled"},
		{Name: "osv:secure-level", Value: "4"},
		{Name: "osv:source-cargo-archive-sha256", Value: policy.Binding.SHA256},
	}
	result := []component{archive, fileComponent("mimalloc-source-policy", policyPath),
		fileComponent("musl-guest-build-provenance", provenancePath)}
	if provenance.Protocol == "osv-musl-guest-build/v2" {
		if supervisorPath == "" {
			fatalf("v2 guest provenance requires the standalone workload supervisor")
		}
		helper := fileComponent("osv-workload-supervisor", supervisorPath)
		expected := provenance.Components["osv-workload-supervisor"]
		if expected.Allocator != "system" || expected.SHA256 != helper.Hashes[0].Content {
			fatalf("workload supervisor allocator or artifact differs from provenance")
		}
		helper.Properties = []property{{Name: "osv:allocator", Value: "system"}, {Name: "osv:linkage", Value: "static musl"}}
		result = append(result, helper)
	} else if supervisorPath != "" {
		fatalf("standalone workload supervisor requires v2 guest provenance")
	}
	return result
}

func fileComponent(name, path string) component {
	file, err := os.Open(path)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		fatalf("hash %s: %v", path, err)
	}
	return component{Type: "file", Name: name, Version: filepath.Base(path), Hashes: []hash{{Algorithm: "SHA-256", Content: hex.EncodeToString(digest.Sum(nil))}}}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

// encodeBOM derives the fixed-build identifier after all final components merge.
func encodeBOM(document bom, fixed bool) ([]byte, error) {
	document.SerialNumber = ""
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	document.SerialNumber, err = releasebuild.Serial(canonical, fixed)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(document, "", "  ")
}
