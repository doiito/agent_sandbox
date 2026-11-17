package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/doiito/agent_sandbox/internal/mcp"
)

func main() { os.Exit(run()) }
func run() int {
	path := flag.String("config", os.Getenv("OSV_SANDBOX_MCP_CONFIG"), "MCP API credential configuration path")
	version := flag.Bool("version", false, "print implementation and supported protocol versions")
	flag.Parse()
	if *version {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"name": "osv-sandbox-mcp", "version": mcp.Version, "protocol_versions": []string{mcp.ModernVersion, mcp.LegacyVersion}})
		return 0
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "MCP configuration is required (-config or OSV_SANDBOX_MCP_CONFIG)")
		return 2
	}
	config, err := mcp.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	server, err := mcp.NewServer(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Rewrap inherited pipe FDs as pollable files so Close interrupts blocked I/O.
	// Never call Fd() on these wrappers: that would restore blocking mode.
	if syscall.SetNonblock(0, true) != nil || syscall.SetNonblock(1, true) != nil {
		fmt.Fprintln(os.Stderr, "cannot configure MCP stdio")
		return 1
	}
	input := os.NewFile(0, "mcp-stdin")
	output := os.NewFile(1, "mcp-stdout")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err = server.Serve(ctx, input, output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
