package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSvSignedCachePolicyStagesColdAndPristineBoot(t *testing.T) {
	for _, mode := range []string{"cold", "pristine", "inputs"} {
		pristine := mode != "cold"
		for _, policy := range []string{"", "disabled", "disabled --nopci"} {
			t.Run(policy+"-"+mode, func(t *testing.T) {
				root := t.TempDir()
				kernel, image := filepath.Join(root, "kernel"), filepath.Join(root, "image")
				for _, path := range []string{kernel, image} {
					if err := os.WriteFile(path, []byte("fixture"), 0o444); err != nil {
						t.Fatal(err)
					}
				}
				workdir := filepath.Join(root, "job-rofs-policy")
				if err := os.Mkdir(workdir, 0o700); err != nil {
					t.Fatal(err)
				}
				config := Config{Backend: "firecracker-osv", Jailer: &JailerConfig{}}
				config.ApplyDefaults()
				backend := FirecrackerOSvBackend{Path: "/usr/local/bin/firecracker", Jailer: config.Jailer,
					ROFSCache: policy, Pristine: pristine, ReadonlyInputs: mode == "inputs"}
				request := RunRequest{MemoryMiB: 128, VCPUs: 1}
				if !pristine {
					request.Entrypoint, request.Args = "/task-probe.so", []string{"tenant-argument"}
				}
				_, err := backend.Command(context.Background(), request,
					ResolvedArtifacts{KernelPath: kernel, ImagePath: image, Format: "raw"}, workdir)
				if policy == "disabled --nopci" {
					if err == nil {
						t.Fatal("unsupported boot policy accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(workdir, "jailer/firecracker/job-rofs-policy/root/config.json"))
				if err != nil {
					t.Fatal(err)
				}
				var launch struct {
					Boot struct {
						Args string `json:"boot_args"`
					} `json:"boot-source"`
				}
				if err := json.Unmarshal(data, &launch); err != nil {
					t.Fatal(err)
				}
				expected := "--nopci --console=serial --rootfs=rofs"
				if policy == "disabled" {
					expected += " --disable_rofs_cache"
				}
				expected += " /osv-job-agent.so"
				if pristine {
					if mode == "inputs" {
						expected += " --pristine-inputs-v1"
					} else {
						expected += " --pristine-v1"
					}
				}
				if launch.Boot.Args != expected || strings.Contains(string(data), "tenant-argument") {
					t.Fatalf("unexpected boot policy or tenant payload leak: %s", data)
				}
			})
		}
	}
}
