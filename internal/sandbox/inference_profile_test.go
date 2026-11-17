package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func inferenceV7Manifest(backend string) SignedArtifactManifest {
	m := SignedArtifactManifest{Protocol: "osv-sandbox-artifacts/v7", Backend: backend,
		GuestInference: inferenceTestGuestProfile(backend), Image: Artifact{SHA256: strings.Repeat("b", 64)}}
	if backend == "firecracker-linux" {
		m.CodeRuntime = testCodeProfile()
		m.AgentFeatures = []string{"code-contexts-v1", "remote-infer-v1", "vsock-proxy-v1"}
	} else {
		m.AgentFeatures = []string{"environment", "pristine-v1", "remote-infer-v1", "stdin", "vsock-proxy-v1"}
		m.Entrypoints = []string{"/python3.12.so"}
		m.OSvUpstreamCommit, m.OSvROFSCache = strings.Repeat("a", 40), "disabled"
	}
	return m
}

func TestInferenceV7SignatureLoaderRechecksSDKAndImageBOM(t *testing.T) {
	for _, backend := range []string{"firecracker-linux", "firecracker-osv"} {
		t.Run(backend, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"kernel", "image", "firecracker", "jailer"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicPath := filepath.Join(root, "public")
			_ = os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(public)), 0600)
			digest := func(name string) string {
				value, err := fileSHA256(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			m := inferenceV7Manifest(backend)
			m.CreatedAt = time.Now().UTC()
			m.ExpiresAt = m.CreatedAt.Add(time.Hour)
			m.Kernel = Artifact{Path: "kernel", SHA256: digest("kernel")}
			m.Image = Artifact{Path: "image", SHA256: digest("image"), Format: "raw"}
			m.KernelSize, m.ImageSize = 6, 5
			m.FirecrackerSHA256, m.JailerSHA256 = digest("firecracker"), digest("jailer")
			bom := inferenceV7BOM(m)
			if backend == "firecracker-osv" {
				for _, name := range []string{"osv-kernel", "firecracker", "jailer", "osv-job-agent", "osv-sandboxd", "osv-sandbox-launcher", "osv-module/python3.12.so"} {
					hash := strings.Repeat("a", 64)
					switch name {
					case "osv-kernel":
						hash = m.Kernel.SHA256
					case "firecracker":
						hash = m.FirecrackerSHA256
					case "jailer":
						hash = m.JailerSHA256
					}
					bom["components"] = append(bom["components"].([]any), map[string]any{"type": "file", "name": name, "hashes": []any{map[string]any{"alg": "SHA-256", "content": hash}}})
				}
				bom["components"] = append(bom["components"].([]any), map[string]any{"name": "OSv", "version": m.OSvUpstreamCommit})
			}
			data, _ := json.Marshal(bom)
			_ = os.WriteFile(filepath.Join(root, "sbom"), data, 0600)
			m.SBOMSHA256, m.SBOMSize = digest("sbom"), int64(len(data))
			config := Config{Backend: backend, ArtifactRoot: root, Kernel: m.Kernel, Image: m.Image, AllowedEntrypoints: m.Entrypoints,
				HypervisorPath: filepath.Join(root, "firecracker"), Jailer: &JailerConfig{Path: filepath.Join(root, "jailer")},
				ArtifactManifest: &ArtifactManifestConfig{Path: "manifest", SignaturePath: "signature", PublicKeyPath: publicPath, SBOMPath: "sbom"}}
			resolved := ResolvedArtifacts{KernelPath: filepath.Join(root, "kernel"), ImagePath: filepath.Join(root, "image"), Format: "raw"}
			write := func(sign bool) {
				data, _ := json.Marshal(m)
				_ = os.WriteFile(filepath.Join(root, "manifest"), data, 0600)
				if sign {
					_ = os.WriteFile(filepath.Join(root, "signature"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, data))), 0600)
				}
			}
			write(true)
			if _, err := verifyArtifactManifest(config, resolved); err != nil {
				t.Fatal("valid v7 signature/BOM", err)
			}
			m.GuestInference.FilesSHA256[guestInferencePaths(backend)[0]] = strings.Repeat("c", 64)
			write(false)
			if _, err := verifyArtifactManifest(config, resolved); err == nil {
				t.Fatal("unsigned SDK mutation accepted")
			}
			write(true)
			if _, err := verifyArtifactManifest(config, resolved); err == nil {
				t.Fatal("re-signed SDK metadata inconsistent with signed image BOM accepted")
			}
		})
	}
}

func TestInferenceV7ProfileBindsCompleteSDKAndPreservesOldRules(t *testing.T) {
	for _, backend := range []string{"firecracker-linux", "firecracker-osv"} {
		t.Run(backend, func(t *testing.T) {
			m := inferenceV7Manifest(backend)
			if err := m.ValidateProfile(backend, m.Entrypoints); err != nil {
				t.Fatal(err)
			}
			if backend == "firecracker-linux" {
				m.AgentFeatures = append(m.AgentFeatures, "workspace-watch-v1", "port-forward-v1")
				slices.Sort(m.AgentFeatures)
				if err := m.ValidateProfile(backend, nil); err != nil {
					t.Fatal("v7 lost optional watch/ports", err)
				}
				m.CodeRuntime.Architecture = "arm64"
				m.CodeRuntime.MinimumCPUFeatures = []string{"asimd"}
				m.GuestInference.Architecture = "arm64"
				if err := m.ValidateProfile(backend, nil); err != nil {
					t.Fatal("ARM v7 profile", err)
				}
			}
			for name, mutate := range map[string]func(*SignedArtifactManifest){
				"missing-profile": func(m *SignedArtifactManifest) { m.GuestInference = nil },
				"missing-file":    func(m *SignedArtifactManifest) { delete(m.GuestInference.FilesSHA256, guestInferencePaths(backend)[0]) },
				"caller-path": func(m *SignedArtifactManifest) {
					m.GuestInference.FilesSHA256["/tmp/remote_infer.py"] = strings.Repeat("a", 64)
				},
				"noncanonical-hash": func(m *SignedArtifactManifest) {
					m.GuestInference.FilesSHA256[guestInferencePaths(backend)[0]] = strings.Repeat("A", 64)
				},
				"wrong-transport": func(m *SignedArtifactManifest) { m.GuestInference.Transport = "caller-proxy" },
				"missing-proxy": func(m *SignedArtifactManifest) {
					m.AgentFeatures = slices.DeleteFunc(m.AgentFeatures, func(f string) bool { return f == "vsock-proxy-v1" })
				},
				"missing-inference": func(m *SignedArtifactManifest) {
					m.AgentFeatures = slices.DeleteFunc(m.AgentFeatures, func(f string) bool { return f == "remote-infer-v1" })
				},
				"duplicate-feature": func(m *SignedArtifactManifest) { m.AgentFeatures = append(m.AgentFeatures, m.AgentFeatures[0]) },
				"backend-switch":    func(m *SignedArtifactManifest) { m.Backend = "qemu" },
				"unknown-profile":   func(m *SignedArtifactManifest) { m.GuestInference.Protocol = "osv-sandbox-guest-inference/v2" },
			} {
				t.Run(name, func(t *testing.T) {
					copy := inferenceV7Manifest(backend)
					mutate(&copy)
					if copy.ValidateProfile(backend, copy.Entrypoints) == nil {
						t.Fatal("invalid v7 accepted")
					}
				})
			}
			for _, old := range []string{"v1", "v2", "v3", "v4", "v5", "v6"} {
				copy := inferenceV7Manifest(backend)
				copy.Protocol = "osv-sandbox-artifacts/" + old
				if copy.ValidateProfile(backend, copy.Entrypoints) == nil {
					t.Fatal("old protocol accepted SDK contract", old)
				}
			}
		})
	}
	for _, name := range []string{"missing-code", "architecture-mismatch", "osv-with-code", "osv-without-python", "osv-wrong-cache", "osv-ARM"} {
		t.Run(name, func(t *testing.T) {
			backend := "firecracker-linux"
			if strings.HasPrefix(name, "osv-") {
				backend = "firecracker-osv"
			}
			m := inferenceV7Manifest(backend)
			switch name {
			case "missing-code":
				m.CodeRuntime = nil
			case "architecture-mismatch":
				m.GuestInference.Architecture = "arm64"
			case "osv-with-code":
				m.CodeRuntime = testCodeProfile()
			case "osv-without-python":
				m.Entrypoints = []string{"/other.so"}
			case "osv-wrong-cache":
				m.OSvROFSCache = "enabled"
			case "osv-ARM":
				m.GuestInference.Architecture = "arm64"
			}
			if m.ValidateProfile(backend, m.Entrypoints) == nil {
				t.Fatal("incoherent v7 accepted")
			}
		})
	}
}

func inferenceV7BOM(m SignedArtifactManifest) map[string]any {
	files := []any{}
	for _, path := range guestInferencePaths(m.Backend) {
		files = append(files, map[string]any{"type": "file", "name": path, "hashes": []any{map[string]any{"alg": "SHA-256", "content": m.GuestInference.FilesSHA256[path]}}})
	}
	name := "linux-agent-rootfs"
	if m.Backend == "firecracker-osv" {
		name = "osv-rootfs"
	}
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []any{map[string]any{"type": "file", "name": name, "hashes": []any{map[string]any{"alg": "SHA-256", "content": m.Image.SHA256}}, "components": []any{map[string]any{"type": "library", "name": "guest SDK", "components": files}}}}}
}

func TestInferenceV7BOMRequiresFilesUnderMatchingImage(t *testing.T) {
	for _, backend := range []string{"firecracker-linux", "firecracker-osv"} {
		for _, mode := range []string{"valid", "wrong-image", "missing-file", "wrong-file", "duplicate-file", "symlink", "outside-image"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				m := inferenceV7Manifest(backend)
				bom := inferenceV7BOM(m)
				roots := bom["components"].([]any)
				image := roots[0].(map[string]any)
				group := image["components"].([]any)[0].(map[string]any)
				files := group["components"].([]any)
				switch mode {
				case "wrong-image":
					image["hashes"] = []any{map[string]any{"alg": "SHA-256", "content": strings.Repeat("c", 64)}}
				case "missing-file":
					group["components"] = files[1:]
				case "wrong-file":
					files[0].(map[string]any)["hashes"] = []any{map[string]any{"alg": "SHA-256", "content": strings.Repeat("c", 64)}}
				case "duplicate-file":
					group["components"] = append(files, files[0])
				case "symlink":
					files[0].(map[string]any)["properties"] = []any{map[string]any{"name": "osv:symlink-target", "value": "/tmp/x"}}
				case "outside-image":
					bom["components"] = append(roots, files...)
					image["components"] = []any{}
				}
				data, _ := json.Marshal(bom)
				err := m.ValidateGuestInferenceSBOM(data)
				if (err == nil) != (mode == "valid") {
					t.Fatal("SDK/image/BOM binding", err)
				}
			})
		}
	}
}

func TestInferenceV7CapabilitiesPreserveOptionalFeaturesAndOSvProxyGate(t *testing.T) {
	for _, backend := range []string{"firecracker-linux", "firecracker-osv"} {
		for _, optional := range []bool{false, true} {
			t.Run(backend+map[bool]string{false: "/minimal", true: "/composed"}[optional], func(t *testing.T) {
				manifest := inferenceV7Manifest(backend)
				manifest.digestSHA256 = strings.Repeat("a", 64)
				config := capacityConfig()
				config.Backend = backend
				config.EgressSocket = "/fixture/egress.sock"
				m := &Manager{config: config, manifest: &manifest}
				if backend == "firecracker-linux" {
					if optional {
						manifest.AgentFeatures = append(manifest.AgentFeatures, "workspace-watch-v1", "port-forward-v1")
						slices.Sort(manifest.AgentFeatures)
					}
					m.backend = FirecrackerLinuxBackend{GuestProxy: true, CodeContexts: true, FileWatch: true, PortForward: true}
				} else {
					m.backend = FirecrackerOSvBackend{GuestProxy: true}
				}
				if err := manifest.ValidateProfile(backend, manifest.Entrypoints); err != nil {
					t.Fatal(err)
				}
				report, err := m.Capabilities()
				if err != nil || !report.Features.NetworkEgress || !report.Features.RemoteInference {
					t.Fatal("v7 proxy/inference capability missing", err)
				}
				if backend == "firecracker-linux" && (!report.Features.CodeContexts || report.Features.PortForward != optional || report.Features.FileWatch != optional) {
					t.Fatal("v7 optional features conflated")
				}
				if backend == "firecracker-osv" && report.Features.Sessions {
					t.Fatal("OSv gained unsupported sessions")
				}
				manifest.GuestInference = nil
				if m.hasRemoteInferenceFeature() {
					t.Fatal("v7 feature strings alone granted inference")
				}
				if backend == "firecracker-osv" && m.hasGuestProxyFeature() {
					t.Fatal("OSv got unsigned generic proxy")
				}
			})
		}
	}
}
