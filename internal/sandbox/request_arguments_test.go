package sandbox

import (
	"strings"
	"testing"
)

func TestProxyArgumentValidationDoesNotAuthorizeUnconfiguredDeployment(t *testing.T) {
	config := Config{Backend: "firecracker-linux", AllowedEntrypoints: []string{"/bin/sh"}}
	config.ApplyDefaults()
	job := RunRequest{Entrypoint: "/bin/sh", Network: "proxy"}
	job.Normalize(config)
	session := SessionCreateRequest{Backend: config.Backend, ArtifactManifestSHA256: strings.Repeat("a", 64), Network: "proxy"}
	session.Normalize(config)
	for _, tc := range []struct {
		name       string
		arguments  func(Config) error
		deployment func(Config) error
	}{
		{"job", job.ValidateArguments, job.Validate},
		{"session", session.ValidateArguments, session.Validate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.arguments(config); err != nil {
				t.Fatal("valid published proxy arguments rejected", err)
			}
			if err := tc.deployment(config); err == nil {
				t.Fatal("server accepted proxy without egress service")
			}
			configured := config
			configured.EgressSocket = "/run/osv-egress/service.sock"
			if err := tc.deployment(configured); err != nil {
				t.Fatal("configured deployment rejected proxy arguments", err)
			}
		})
	}
	job.MemoryMiB = config.Limits.MaxMemoryMiB + 1
	if job.ValidateArguments(config) == nil {
		t.Fatal("gateway stopped enforcing resource limits")
	}
}
