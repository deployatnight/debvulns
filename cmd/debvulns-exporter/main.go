// Command debvulns-exporter is the Prometheus exporter for Debian security
// vulnerabilities. It runs a periodic background scan and serves the latest
// results on /metrics without blocking the scrape.
//
// Usage:
//
//	debvulns-exporter [options]
//
// Options:
//
//	--port PORT              HTTP listen port (default: 9222)
//	--suite SUITE            Debian suite codename; auto-detected by default
//	--refresh-interval SECS  Seconds between full scans (default: 86400)
//	--cache-dir DIR          Directory for warm-start disk cache
//	--no-cache               Disable disk caching; always re-download
//	--vuln-url URL           Override vulnerability data source URL
//	--epss-url URL           Override EPSS data source URL
//	--osv-cache-max-age SECS Max age for OSV results cache (default: 604800)
//	--no-osv                 Disable OSV.dev cross-check for non-Debian packages
//	-v, --verbose            Enable debug-level logging
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deployatnight/debvulns/internal/cache"
	"github.com/deployatnight/debvulns/internal/exporter"
	"github.com/deployatnight/debvulns/internal/refresher"
	"github.com/deployatnight/debvulns/internal/scan"
	"github.com/deployatnight/debvulns/internal/suite"
)

// minRefreshInterval protects upstream data sources from being hammered.
const minRefreshInterval = time.Hour

func main() {
	port := flag.Int("port", 9222, "TCP port to expose /metrics on")
	suiteFlag := flag.String("suite", "", "Debian suite codename (auto-detected by default)")
	refreshInterval := flag.Int("refresh-interval", 86400, "Seconds between full scans (min 3600)")
	cacheDir := flag.String("cache-dir", "/var/cache/debvulns", "Directory for warm-start disk cache")
	noCache := flag.Bool("no-cache", false, "Disable disk caching; always re-download")
	vulnURL := flag.String("vuln-url", "", "Override the Debian Security Tracker vulnerability data URL")
	epssURL := flag.String("epss-url", "", "Override the EPSS CSV data URL")
	osvCacheMaxAge := flag.Int("osv-cache-max-age", 604800, "Max age in seconds for the OSV results cache")
	noOSV := flag.Bool("no-osv", false, "Disable OSV.dev cross-check for non-Debian packages")
	verbose := flag.Bool("verbose", false, "Enable debug-level logging to stderr")
	flag.BoolVar(verbose, "v", false, "Enable debug-level logging to stderr (shorthand)")
	flag.Parse()

	logLevel := log.Default()
	// Basic verbose gating: debug logs are emitted by packages via the
	// scan.Options.Logger when verbose is set; here we just keep the default
	// logger and rely on scan/refresher logging.
	_ = verbose

	if *refreshInterval < int(minRefreshInterval.Seconds()) {
		fmt.Fprintf(os.Stderr,
			"--refresh-interval %d s is below the minimum of %d s.\n",
			*refreshInterval, int(minRefreshInterval.Seconds()))
		os.Exit(1)
	}

	// Detect Debian suite.
	suiteName := *suiteFlag
	if suiteName == "" {
		var err error
		suiteName, err = suite.Detect()
		if err != nil {
			log.Printf("failed to detect Debian suite: %v", err)
			os.Exit(1)
		}
	}

	log.Printf("debvulns-exporter starting — suite=%s port=%d", suiteName, *port)

	dir := *cacheDir
	if *noCache {
		dir = ""
	}

	sharedCache := cache.New()

	opts := scan.Options{
		Suite:           suiteName,
		VulnURL:         *vulnURL,
		EPSSURL:         *epssURL,
		CacheDir:        dir,
		RefreshInterval: time.Duration(*refreshInterval) * time.Second,
		OSVCacheMaxAge:  time.Duration(*osvCacheMaxAge) * time.Second,
		OSVEnabled:      !*noOSV,
		Logger:          logLevel,
	}

	refr := refresher.New(sharedCache, opts, log.Default())
	refr.Start()
	log.Printf("cache-refresh thread started (refresh_interval=%d s)", *refreshInterval)

	// HTTP server on the main thread.
	addr := fmt.Sprintf(":%d", *port)
	server := exporter.New(sharedCache, addr, suiteName)

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	select {
	case sig := <-sigCh:
		log.Printf("received %s — shutting down", sig)
		refr.Stop()
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("HTTP server stopped: %v", err)
		}
		refr.Stop()
	}
}
