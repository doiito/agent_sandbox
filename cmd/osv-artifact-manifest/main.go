package main

import (
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
	"time"

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
	createdAt := time.Now().UTC().Truncate(time.Second)
	manifest := sandbox.SignedArtifactManifest{
		Protocol: "osv-sandbox-artifacts/v1", CreatedAt: createdAt, ExpiresAt: createdAt.Add(*validFor),
		Kernel:     sandbox.Artifact{Path: *kernel, SHA256: hash(kernelPath)},
		Image:      sandbox.Artifact{Path: *image, SHA256: hash(imagePath), Format: "raw"},
		KernelSize: size(kernelPath), ImageSize: size(imagePath),
		FirecrackerSHA256: hash(*firecracker), JailerSHA256: hash(*jailer),
		SBOMSHA256: hash(inside(*artifactRoot, *sbom)), SBOMSize: size(inside(*artifactRoot, *sbom)),
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
