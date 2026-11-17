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

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func main() { os.Exit(runArgs(os.Args[1:], os.Stdout, os.Stderr)) }
func runArgs(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("osv-sandbox-egress", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/osv-sandbox/egress.production.json", "root-managed egress configuration")
	version := flags.Bool("version", false, "print protocol version")
	requireProduction := flags.Bool("require-production", true, "refuse a non-production configuration")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: osv-sandbox-egress [flags] [bill command]")
		fmt.Fprintln(stderr, "Commands: bill-export -tenant ID -task ID -output /absolute/file")
		fmt.Fprintln(stderr, "          bill-verify -archive /absolute/file")
		fmt.Fprintln(stderr, "          bill-retire -archive /absolute/file")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if *version {
		if flags.NArg() != 0 {
			return 2
		}
		_ = json.NewEncoder(stdout).Encode(map[string]string{"name": "osv-sandbox-egress", "protocol": "osv-sandbox-network-fetch/v1"})
		return 0
	}
	var admin *sandbox.InferenceBillAdminRequest
	if flags.NArg() != 0 {
		request, err := parseBillAdmin(flags.Args(), stderr)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		admin = &request
		if admin.Operation == "bill-verify" {
			return runBillAdmin(sandbox.EgressServiceConfig{}, *admin, stdout, stderr)
		}
	}
	config, err := sandbox.LoadEgressConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "egress configuration rejected:", err)
		return 1
	}
	if *requireProduction && !config.Production {
		fmt.Fprintln(stderr, "egress service requires production=true")
		return 1
	}
	if admin != nil {
		return runBillAdmin(config, *admin, stdout, stderr)
	}
	if config.Production && os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "production egress must run as non-root service user")
		return 1
	}
	auth, err := sandbox.LoadAuthenticator(config.AuthPolicyPath)
	if err != nil {
		fmt.Fprintln(stderr, "egress auth policy rejected")
		return 1
	}
	audit, err := sandbox.OpenEgressAudit(config.AuditLogPath)
	if err != nil {
		fmt.Fprintln(stderr, "egress audit initialization failed")
		return 1
	}
	defer audit.Close()
	server, err := sandbox.NewConfiguredEgressServer(auth, audit, config)
	if err != nil {
		fmt.Fprintln(stderr, "egress initialization failed")
		return 1
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err = sandbox.ServeEgress(ctx, config.SocketPath, server); err != nil {
		fmt.Fprintln(stderr, "egress server stopped:", err)
		return 1
	}
	return 0
}

func parseBillAdmin(args []string, stderr io.Writer) (sandbox.InferenceBillAdminRequest, error) {
	if len(args) == 0 {
		return sandbox.InferenceBillAdminRequest{}, fmt.Errorf("missing bill command")
	}
	request := sandbox.InferenceBillAdminRequest{Operation: args[0]}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	tenant := flags.String("tenant", "", "bill tenant ID")
	task := flags.String("task", "", "known logical task ID")
	output := flags.String("output", "", "new absolute archive file path")
	archive := flags.String("archive", "", "existing absolute archive file path")
	if err := flags.Parse(args[1:]); err != nil {
		return request, err
	}
	if flags.NArg() != 0 {
		return request, fmt.Errorf("unexpected bill arguments")
	}
	switch request.Operation {
	case "bill-export":
		if *tenant == "" || *task == "" || *output == "" || *archive != "" {
			return request, fmt.Errorf("bill-export requires -tenant, -task and -output")
		}
		request.Tenant, request.TaskID, request.Path = *tenant, *task, *output
	case "bill-verify", "bill-retire":
		if *archive == "" || *tenant != "" || *task != "" || *output != "" {
			return request, fmt.Errorf("%s requires only -archive", request.Operation)
		}
		request.Path = *archive
	default:
		return request, fmt.Errorf("unknown bill command")
	}
	return request, nil
}

func runBillAdmin(config sandbox.EgressServiceConfig, request sandbox.InferenceBillAdminRequest, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	report, err := sandbox.RunInferenceBillAdmin(ctx, config, request)
	if err != nil {
		fmt.Fprintln(stderr, "bill maintenance failed:", err)
		return 1
	}
	if json.NewEncoder(stdout).Encode(report) != nil {
		return 1
	}
	return 0
}
