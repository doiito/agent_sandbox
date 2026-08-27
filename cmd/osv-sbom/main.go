package main

import (
	"crypto/rand"
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
	"time"
)

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Hashes  []hash `json:"hashes,omitempty"`
}

type hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Component component `json:"component"`
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
	cargoManifest := flag.String("cargo-manifest", "linux-guest/Cargo.toml", "guest Cargo.toml")
	kernel := flag.String("kernel", "", "kernel artifact")
	rootfs := flag.String("rootfs", "", "rootfs artifact")
	agent := flag.String("agent", "", "guest agent binary")
	api := flag.String("api", "", "unprivileged API binary")
	launcher := flag.String("launcher", "", "privileged launcher binary")
	firecracker := flag.String("firecracker", "", "Firecracker executable")
	jailer := flag.String("jailer", "", "jailer executable")
	flag.Parse()
	for name, value := range map[string]string{"kernel": *kernel, "rootfs": *rootfs, "agent": *agent, "api": *api, "launcher": *launcher, "firecracker": *firecracker, "jailer": *jailer} {
		if value == "" {
			fatalf("-%s is required", name)
		}
	}
	components := []component{
		fileComponent("linux-kernel", *kernel), fileComponent("linux-agent-rootfs", *rootfs),
		fileComponent("firecracker-linux-agent", *agent), fileComponent("firecracker", *firecracker),
		fileComponent("jailer", *jailer), fileComponent("osv-sandboxd", *api),
		fileComponent("osv-sandbox-launcher", *launcher),
		{Type: "library", Name: "busybox-static", Version: "Debian 12 package"},
	}
	command := exec.Command("cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", *cargoManifest)
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
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		fatalf("serial: %v", err)
	}
	serialNumber := fmt.Sprintf("%x-%x-%x-%x-%x", serial[0:4], serial[4:6], serial[6:8], serial[8:10], serial[10:16])
	document := bom{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + serialNumber, Version: 1,
		Metadata:   metadata{Timestamp: time.Now().UTC().Format(time.RFC3339), Component: component{Type: "application", Name: "osv-agent-sandbox", Version: "production"}},
		Components: components,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatalf("encode SBOM: %v", err)
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0o644); err != nil {
		fatalf("write SBOM: %v", err)
	}
	fmt.Printf("sbom=%s\n", *output)
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
