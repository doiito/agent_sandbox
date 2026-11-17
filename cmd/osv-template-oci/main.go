package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/templateoci"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || (args[0] != "export" && args[0] != "import" && args[0] != "push" && args[0] != "pull") {
		return errors.New("usage: osv-template-oci export|import|push|pull [source/destination] -architecture amd64|arm64 -backend BACKEND -public-key FILE -firecracker FILE -jailer FILE [-digest sha256:HEX] [registry flags]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	source := f.String("source", "", "signed artifact directory for export; OCI layout for import")
	destination := f.String("destination", "", "new output directory; existing paths are rejected")
	digest := f.String("digest", "", "externally pinned OCI manifest SHA256; required for import")
	repository := f.String("repository", "", "explicit registry repository")
	reference := f.String("reference", "", "push tag or identical digest; defaults to digest")
	var registryOptions templateoci.RegistryOptions
	f.StringVar(&registryOptions.URL, "registry-url", "", "HTTPS registry origin")
	f.StringVar(&registryOptions.CAFile, "registry-ca", "", "additional registry CA PEM file")
	f.StringVar(&registryOptions.ClientCertFile, "registry-client-cert", "", "registry mTLS client certificate")
	f.StringVar(&registryOptions.ClientKeyFile, "registry-client-key", "", "private registry mTLS key")
	f.StringVar(&registryOptions.AuthFile, "registry-auth", "", "private JSON Basic credentials or Bearer token")
	f.StringVar(&registryOptions.WorkDir, "work-dir", "", "private push verification workspace parent; defaults to source parent")
	f.BoolVar(&registryOptions.PlainHTTP, "allow-loopback-http", false, "explicitly allow HTTP on loopback IPs for local verification")
	f.DurationVar(&registryOptions.Timeout, "registry-timeout", 30*time.Minute, "per registry request timeout, 1s to 24h")
	var o templateoci.VerifyOptions
	f.StringVar(&o.Architecture, "architecture", "", "explicit expected architecture: amd64 or arm64")
	f.StringVar(&o.Backend, "backend", "", "explicit expected signed backend")
	f.StringVar(&o.PublicKeyPath, "public-key", "", "external base64 Ed25519 trust anchor")
	f.StringVar(&o.FirecrackerPath, "firecracker", "", "trusted matching Firecracker ELF executable")
	f.StringVar(&o.JailerPath, "jailer", "", "trusted matching jailer ELF executable")
	f.Func("entrypoint", "trusted allowed OSv module; repeat for each module", func(value string) error { o.Entrypoints = append(o.Entrypoints, value); return nil })
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	var result templateoci.Descriptor
	var err error
	remote := args[0] == "push" || args[0] == "pull"
	if !remote {
		if *source == "" || *destination == "" {
			return errors.New("source and destination are required")
		}
		if *repository != "" || *reference != "" || registryOptions.URL != "" || registryOptions.AuthFile != "" || registryOptions.CAFile != "" || registryOptions.ClientCertFile != "" || registryOptions.ClientKeyFile != "" || registryOptions.WorkDir != "" || registryOptions.PlainHTTP {
			return errors.New("registry flags are only valid for push/pull")
		}
	}
	if args[0] == "export" {
		if *digest != "" {
			return errors.New("export computes the digest; -digest is only valid for import")
		}
		result, err = templateoci.Export(ctx, *source, *destination, o)
	} else if args[0] == "import" {
		result, err = templateoci.Import(ctx, *source, *digest, *destination, o)
	} else {
		if (args[0] == "push" && (*source == "" || *destination != "")) || (args[0] == "pull" && (*destination == "" || *source != "" || *reference != "")) {
			return errors.New("push requires only source; pull requires only destination and no publication reference")
		}
		registry, createErr := templateoci.NewRegistry(registryOptions)
		if createErr != nil {
			return createErr
		}
		defer registry.Close()
		if args[0] == "push" {
			result, err = registry.Push(ctx, *source, *digest, *repository, *reference, o)
		} else {
			result, err = registry.Pull(ctx, *digest, *repository, *destination, o)
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
