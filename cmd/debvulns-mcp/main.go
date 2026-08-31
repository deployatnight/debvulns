// Command debvulns-mcp is the MCP server entry point. It speaks the MCP
// protocol over stdio (JSON-RPC 2.0) and exposes the list_vulnerabilities and
// research_cves tools.
//
// Usage:
//
//	debvulns-mcp
//
// Set DEBSECAN_SUITE to override the auto-detected Debian suite.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/deployatnight/debvulns/internal/exporter"
	"github.com/deployatnight/debvulns/internal/mcp"
	"github.com/deployatnight/debvulns/internal/suite"
)

func main() {
	verbose := flag.Bool("verbose", false, "enable verbose debug logging to stderr")
	flag.BoolVar(verbose, "v", false, "enable verbose debug logging to stderr (shorthand)")
	flag.Parse()

	logger := log.New(os.Stderr, "debvulns-mcp ", log.LstdFlags)
	if !*verbose {
		logger = log.New(devNull{}, "", 0)
	}

	suiteName, err := suite.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to detect Debian suite: %v\n", err)
		os.Exit(1)
	}
	log.Printf("detected suite: %s", suiteName)

	srv := mcp.New("debvulns", exporter.Version, suiteName, true, logger)

	// Cancel initialization on SIGINT/SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Initialize(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server failed to initialize and will not start: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server stopped: %v\n", err)
	}
}

// devNull is a logger sink that discards all output.
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }
