package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/doiito/agent_sandbox/internal/releasebuild"
	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() {
	generatePrefix := flag.String("generate-key-prefix", "", "generate base64 Ed25519 .private and .public files")
	artifactRoot := flag.String("artifact-root", "", "trusted artifact root")
	kernel := flag.String("kernel", "", "kernel path relative to artifact root")
	image := flag.String("image", "", "rootfs path relative to artifact root")
	firecracker := flag.String("firecracker", "", "Firecracker executable")
	jailer := flag.String("jailer", "", "matching jailer executable")
	sbom := flag.String("sbom", "", "SBOM path relative to artifact root")
	privateKeyPath := flag.String("private-key", "", "base64 Ed25519 private key")
	output := flag.String("output", "", "manifest output path; signature uses .sig suffix")
	validFor := flag.Duration("valid-for", 30*24*time.Hour, "manifest validity duration")
	backend := flag.String("backend", "firecracker-linux", "signed backend: firecracker-linux or firecracker-osv")
	osvUpstreamCommit := flag.String("osv-upstream-commit", "", "fixed 40-character OSv upstream commit for the OSv profile")
	osvROFSCache := flag.String("osv-rofs-cache", "", "signed OSv ROFS cache policy: empty (legacy) or disabled")
	codeRuntime := flag.String("code-runtime", "", "JSON signed code runtime profile for Linux v5/v6/v7")
	guestInference := flag.String("guest-inference", "", "JSON signed guest SDK file/transport profile; requires explicit remote-infer-v1 and v7")
	var entrypoints []string
	var agentFeatures []string
	flag.Func("entrypoint", "signed OSv module path; repeat for each module", func(path string) error {
		entrypoints = append(entrypoints, path)
		return nil
	})
	flag.Func("agent-feature", "signed agent feature: OSv environment/stdin/pristine-v1/input-files-v1 or Linux vsock-proxy-v1/workspace-watch-v1/code-contexts-v1/port-forward-v1", func(feature string) error {
		agentFeatures = append(agentFeatures, feature)
		return nil
	})
	flag.Parse()
	if *generatePrefix != "" {
		generateKey(*generatePrefix)
		return
	}
	if *artifactRoot == "" || *kernel == "" || *image == "" || *firecracker == "" || *jailer == "" || *sbom == "" || *privateKeyPath == "" || *output == "" || *validFor < time.Hour {
		fatalf("all signing flags are required and valid-for must be at least one hour")
	}
	kernelPath := inside(*artifactRoot, *kernel)
	imagePath := inside(*artifactRoot, *image)
	createdAt, _, err := releasebuild.Timestamp(os.Getenv("SOURCE_DATE_EPOCH"), time.Now())
	if err != nil {
		fatalf("build time: %v", err)
	}
	manifest := sandbox.SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v1", CreatedAt: createdAt, ExpiresAt: createdAt.Add(*validFor),
		Kernel:     sandbox.Artifact{Path: *kernel, SHA256: hash(kernelPath)},
		Image:      sandbox.Artifact{Path: *image, SHA256: hash(imagePath), Format: "raw"},
		KernelSize: size(kernelPath), ImageSize: size(imagePath),
		FirecrackerSHA256: hash(*firecracker), JailerSHA256: hash(*jailer),
		SBOMSHA256: hash(inside(*artifactRoot, *sbom)), SBOMSize: size(inside(*artifactRoot, *sbom)),
	}
	if *backend == "firecracker-osv" {
		manifest.Protocol = "osv-sandbox-artifacts/v2"
		manifest.Backend = *backend
		manifest.OSvUpstreamCommit = *osvUpstreamCommit
		manifest.OSvROFSCache = *osvROFSCache
		sort.Strings(entrypoints)
		sort.Strings(agentFeatures)
		manifest.Entrypoints = entrypoints
		manifest.AgentFeatures = agentFeatures
	} else if *backend == "firecracker-linux" && len(agentFeatures) != 0 {
		manifest.Protocol, manifest.Backend = "osv-sandbox-artifacts/v3", *backend
		sort.Strings(agentFeatures)
		if slices.Contains(agentFeatures, "workspace-watch-v1") {
			manifest.Protocol = "osv-sandbox-artifacts/v4"
		}
		if slices.Contains(agentFeatures, "code-contexts-v1") {
			manifest.Protocol = "osv-sandbox-artifacts/v5"
		}
		if slices.Contains(agentFeatures, "port-forward-v1") {
			manifest.Protocol = "osv-sandbox-artifacts/v6"
		}
		manifest.AgentFeatures = agentFeatures
		manifest.OSvUpstreamCommit, manifest.OSvROFSCache = *osvUpstreamCommit, *osvROFSCache
		manifest.Entrypoints = entrypoints
	} else if *backend != "firecracker-linux" || *osvUpstreamCommit != "" || *osvROFSCache != "" || len(entrypoints) != 0 {
		fatalf("Linux v1 cannot declare OSv module paths or upstream commit")
	}
	if *codeRuntime != "" {
		data, err := os.ReadFile(*codeRuntime)
		if err != nil || len(data) > 16384 {
			fatalf("invalid code runtime profile file")
		}
		var profile sandbox.SignedCodeRuntime
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF {
			fatalf("invalid code runtime profile JSON")
		}
		manifest.CodeRuntime = &profile
	}
	if *guestInference != "" {
		data, err := os.ReadFile(*guestInference)
		if err != nil || len(data) > 16384 {
			fatalf("invalid guest inference profile file")
		}
		var profile sandbox.SignedGuestInference
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF {
			fatalf("invalid guest inference profile JSON")
		}
		manifest.GuestInference = &profile
		manifest.Protocol = "osv-sandbox-artifacts/v7"
	}
	if slices.Contains(agentFeatures, "workspace-artifacts-v1") {
		manifest.Protocol = "osv-sandbox-artifacts/v8"
	}
	if err := manifest.ValidateProfile(*backend, entrypoints); err != nil {
		fatalf("invalid signed artifact profile: %v", err)
	}
	if manifest.GuestInference != nil {
		path := inside(*artifactRoot, *sbom)
		if size(path) > 64<<20 {
			fatalf("v7 BOM exceeds size limit")
		}
		data, err := os.ReadFile(path)
		if err != nil || manifest.ValidateGuestInferenceSBOM(data) != nil {
			fatalf("v7 BOM differs from signed guest SDK/image profile")
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fatalf("encode manifest: %v", err)
	}
	data = append(data, '\n')
	encodedPrivate, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fatalf("read private key: %v", err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(string(bytesTrimSpace(encodedPrivate)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		fatalf("private key is not a base64 Ed25519 private key")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), data)
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fatalf("write manifest: %v", err)
	}
	encodedSignature := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	if err := os.WriteFile(*output+".sig", encodedSignature, 0o644); err != nil {
		fatalf("write signature: %v", err)
	}
	fmt.Printf("manifest=%s\nsignature=%s\n", *output, *output+".sig")
}

func generateKey(prefix string) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}
	if err := os.WriteFile(prefix+".private", []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(prefix+".public", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		fatalf("write public key: %v", err)
	}
	fmt.Printf("private=%s\npublic=%s\n", prefix+".private", prefix+".public")
}

func inside(root, name string) string {
	if filepath.IsAbs(name) {
		fatalf("artifact paths must be relative")
	}
	root, _ = filepath.Abs(root)
	path, _ := filepath.Abs(filepath.Join(root, name))
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator) {
		fatalf("artifact path escapes root")
	}
	return path
}

func hash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func size(path string) int64 {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		fatalf("artifact %s is not a regular file", path)
	}
	return info.Size()
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
