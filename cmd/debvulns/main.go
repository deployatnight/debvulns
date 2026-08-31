// Command debvulns is the standalone CLI that scans installed packages for
// known Debian vulnerabilities and prints the result as JSON or CSV.
//
// Usage:
//
//	debvulns [options]
//
// Options:
//
//	-s, --severity {critical,high,medium,low,negligible}  Filter by severity
//	-f, --format {json,csv}                               Output format (default json)
//	    --sort-by {package,cve}                           Sort order
//	    --suite SUITE                                     Debian suite (auto-detected)
//	    --cache-dir DIR                                   Disk cache dir (default /var/cache/debvulns)
//	    --cache-max-age SECS                              Vulnerability/EPSS cache TTL (default 86400)
//	    --osv-cache-max-age SECS                          OSV results cache TTL (default 604800)
//	    --no-cache                                        Bypass disk cache
//	    --vuln-url URL                                    Custom vulnerability data URL/path
//	    --epss-url URL                                    Custom EPSS data URL/path
//	    --no-osv                                          Disable OSV.dev cross-check
//	-v, --verbose                                          Verbose debug logging to stderr
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/deployatnight/debvulns/internal/format"
	"github.com/deployatnight/debvulns/internal/scan"
	"github.com/deployatnight/debvulns/internal/suite"
)

func main() {
	severity := flag.String("severity", "", "filter by severity (critical|high|medium|low|negligible)")
	flag.StringVar(severity, "s", "", "filter by severity (shorthand)")
	formatFlag := flag.String("format", "json", "output format (json|csv)")
	flag.StringVar(formatFlag, "f", "json", "output format (shorthand)")
	sortBy := flag.String("sort-by", "", "sort by (package|cve)")
	suiteFlag := flag.String("suite", "", "Debian suite name (auto-detected by default)")
	cacheDir := flag.String("cache-dir", "/var/cache/debvulns", "directory to cache fetched and parsed data")
	cacheMaxAge := flag.Int("cache-max-age", 86400, "max age in seconds for vuln/EPSS cache")
	osvCacheMaxAge := flag.Int("osv-cache-max-age", 604800, "max age in seconds for OSV results cache")
	noCache := flag.Bool("no-cache", false, "do not use cached data, force downloading and parsing")
	vulnURL := flag.String("vuln-url", "", "custom URL or local path for Debian Security Tracker data")
	epssURL := flag.String("epss-url", "", "custom URL or local path for EPSS scores data")
	noOSV := flag.Bool("no-osv", false, "disable OSV.dev cross-check for non-Debian packages")
	verbose := flag.Bool("verbose", false, "enable verbose debug logging (sent to stderr)")
	flag.BoolVar(verbose, "v", false, "enable verbose debug logging (shorthand)")
	flag.Parse()

	// Validate severity.
	if *severity != "" {
		*severity = strings.ToLower(*severity)
		switch *severity {
		case "critical", "high", "medium", "low", "negligible":
		default:
			fmt.Fprintf(os.Stderr, "invalid --severity %q\n", *severity)
			os.Exit(2)
		}
	}

	// Validate format.
	switch *formatFlag {
	case "json", "csv":
	default:
		fmt.Fprintf(os.Stderr, "invalid --format %q\n", *formatFlag)
		os.Exit(2)
	}

	// Validate sort-by.
	switch *sortBy {
	case "", "package", "cve":
	default:
		fmt.Fprintf(os.Stderr, "invalid --sort-by %q\n", *sortBy)
		os.Exit(2)
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	if !*verbose {
		logger = log.New(io.Discard, "", 0)
	}

	suiteName := *suiteFlag
	if suiteName == "" {
		var err error
		suiteName, err = suite.Detect()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to detect Debian suite: %v\n", err)
			os.Exit(1)
		}
	}

	dir := *cacheDir
	if *noCache {
		dir = ""
	}

	opts := scan.Options{
		Suite:           suiteName,
		VulnURL:         *vulnURL,
		EPSSURL:         *epssURL,
		CacheDir:        dir,
		RefreshInterval: time.Duration(*cacheMaxAge) * time.Second,
		OSVCacheMaxAge:  time.Duration(*osvCacheMaxAge) * time.Second,
		OSVEnabled:      !*noOSV,
		Logger:          logger,
	}

	result, err := scan.Run(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	switch *formatFlag {
	case "json":
		if err := format.WriteJSON(os.Stdout, result.Categorized, *severity, *sortBy); err != nil {
			fmt.Fprintf(os.Stderr, "write JSON: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		if err := format.WriteCSV(os.Stdout, result.Categorized, *severity, *sortBy); err != nil {
			fmt.Fprintf(os.Stderr, "write CSV: %v\n", err)
			os.Exit(1)
		}
	}
}
