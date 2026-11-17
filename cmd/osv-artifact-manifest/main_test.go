package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func TestFixedEpochCLIProducesIdenticalSignedManifest(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"kernel", "image", "firecracker", "jailer", "sbom"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "key.private")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "manifest.json")
	args := []string{"-artifact-root", root, "-kernel", "kernel", "-image", "image", "-firecracker", filepath.Join(root, "firecracker"), "-jailer", filepath.Join(root, "jailer"), "-sbom", "sbom", "-private-key", key, "-output", output}
	encoded, _ := json.Marshal(args)
	epoch := strconv.FormatInt(time.Now().Unix()-60, 10)
	t.Setenv("SOURCE_DATE_EPOCH", epoch)
	var previous, previousSignature []byte
	for attempt := 0; attempt < 2; attempt++ {
		command := exec.Command(executable, "-test.run=^TestSigningProcessHelper$")
		command.Env = append(os.Environ(), "OSV_TEST_SIGN_ARGS="+string(encoded))
		if log, err := command.CombinedOutput(); err != nil {
			t.Fatal(err, string(log))
		}
		body, _ := os.ReadFile(output)
		sig, _ := os.ReadFile(output + ".sig")
		if attempt == 1 && (!bytes.Equal(body, previous) || !bytes.Equal(sig, previousSignature)) {
			t.Fatal("fixed signed manifest differs")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil || !ed25519.Verify(public, body, decoded) {
			t.Fatal("signature invalid", err)
		}
		previous, previousSignature = body, sig
	}
	t.Setenv("SOURCE_DATE_EPOCH", "invalid")
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSigningProcessHelper$")
	command.Env = append(os.Environ(), "OSV_TEST_SIGN_ARGS="+string(encoded))
	if err := command.Run(); err == nil {
		t.Fatal("invalid epoch accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid epoch left manifest")
	}
}

func TestSigningProcessHelper(t *testing.T) {
	text := os.Getenv("OSV_TEST_SIGN_ARGS")
	if text == "" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(text), &args) != nil {
		os.Exit(2)
	}
	os.Args = append([]string{os.Args[0]}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestManifestCLISelectsSignsAndBindsV6WithoutChangingLegacyProfiles(t *testing.T) {
	for _, kind := range []string{"port", "composed", "legacy_shell", "legacy_code", "duplicate", "unknown", "unrequested_runtime"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"kernel", "image", "firecracker", "jailer", "sbom"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(root, "key.private")
			if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "manifest.json")
			args := []string{"-artifact-root", root, "-kernel", "kernel", "-image", "image", "-firecracker", filepath.Join(root, "firecracker"), "-jailer", filepath.Join(root, "jailer"), "-sbom", "sbom", "-private-key", key, "-output", output}
			want := "osv-sandbox-artifacts/v6"
			features := []string{"port-forward-v1"}
			switch kind {
			case "composed":
				features = []string{"workspace-watch-v1", "port-forward-v1", "code-contexts-v1", "vsock-proxy-v1"}
			case "legacy_shell":
				features = []string{"workspace-watch-v1", "vsock-proxy-v1"}
				want = "osv-sandbox-artifacts/v4"
			case "legacy_code":
				features = []string{"code-contexts-v1"}
				want = "osv-sandbox-artifacts/v5"
			case "duplicate":
				features = append(features, "port-forward-v1")
			case "unknown":
				features = append(features, "unknown")
			}
			for _, feature := range features {
				args = append(args, "-agent-feature", feature)
			}
			if kind == "composed" || kind == "legacy_code" || kind == "unrequested_runtime" {
				profile := sandbox.SignedCodeRuntime{Architecture: "amd64", KernelProtocol: "osv-code-kernel/v2", PythonVersion: "3.12.16", NodeVersion: "22.23.4", TypeScriptVersion: "5.9.3", PrewarmLanguage: "python", RuntimeInventorySHA256: strings.Repeat("a", 64), KernelScriptsSHA256: map[string]string{"python.py": strings.Repeat("b", 64), "node.cjs": strings.Repeat("c", 64)}, MinimumCPUFeatures: []string{"sse4_1"}}
				data, _ := json.Marshal(profile)
				path := filepath.Join(root, "runtime.json")
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-code-runtime", path)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(args)
			command := exec.Command(executable, "-test.run=^TestSigningProcessHelper$")
			command.Env = append(os.Environ(), "OSV_TEST_SIGN_ARGS="+string(data))
			log, err := command.CombinedOutput()
			if kind == "duplicate" || kind == "unknown" || kind == "unrequested_runtime" {
				if err == nil {
					t.Fatal("invalid feature input signed")
				}
				return
			}
			if err != nil {
				t.Fatal(err, string(log))
			}
			body, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var manifest sandbox.SignedArtifactManifest
			if json.Unmarshal(body, &manifest) != nil || manifest.Protocol != want || manifest.ValidateProfile("firecracker-linux", nil) != nil {
				t.Fatal(string(body))
			}
			encoded, err := os.ReadFile(output + ".sig")
			if err != nil {
				t.Fatal(err)
			}
			signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil || !ed25519.Verify(public, body, signature) {
				t.Fatal("CLI signature invalid", err)
			}
			manifest.AgentFeatures = append(manifest.AgentFeatures, "unsigned")
			changed, _ := json.Marshal(manifest)
			if ed25519.Verify(public, changed, signature) {
				t.Fatal("modified feature list kept valid signature")
			}
		})
	}
}
