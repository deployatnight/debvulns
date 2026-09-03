// Package scan runs the full debvulns vulnerability scan pipeline: fetch the
// Debian Security Tracker feed, download EPSS scores, enumerate installed
// packages, match vulnerabilities, cross-check non-Debian packages against
// OSV.dev, deduplicate and categorise.
//
// Both the standalone CLI and the Prometheus exporter's refresher call Run;
// optional disk caching (warm-start) is handled here so callers stay simple.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/deployatnight/debvulns/internal/debpkg"
	"github.com/deployatnight/debvulns/internal/epss"
	"github.com/deployatnight/debvulns/internal/maxver"
	"github.com/deployatnight/debvulns/internal/osv"
	"github.com/deployatnight/debvulns/internal/version"
	"github.com/deployatnight/debvulns/internal/vuln"
)

// Result is a snapshot produced by one full scan.
type Result struct {
	// Categorized maps a derived severity to the matched, categorised
	// vulnerabilities in that bucket.
	Categorized map[string][]vuln.Vulnerability

	// InstalledPackages is every installed package at scan time.
	InstalledPackages []debpkg.Package

	// ScanTimestamp is when the scan completed.
	ScanTimestamp time.Time

	// ScanDuration is how long the scan took.
	ScanDuration time.Duration

	// ScanOK is true on success, false on failure (may still carry stale
	// data, see Cache semantics).
	ScanOK bool
}

// Options controls one Run invocation.
type Options struct {
	Suite           string        // required
	VulnURL         string        // override debsecan URL; empty = default
	EPSSURL         string        // override EPSS URL; empty = default
	CacheDir        string        // empty = disable disk cache
	RefreshInterval time.Duration // freshness TTL for vuln + EPSS cache
	OSVCacheMaxAge  time.Duration // freshness TTL for the OSV results cache
	OSVEnabled      bool          // cross-check non-Debian packages via OSV.dev
	Logger          *log.Logger   // optional structured logger; nil = discard

	// Max version tracking options
	MaxVersionEnabled bool          // enable max version tracking for release-limited fixes
	MaxVersionTTL     time.Duration // TTL for max version cache (default: 6h)
	MaxVersionURL     string        // optional: custom URL for package lists
}

// Run executes the full scan pipeline and returns a populated Result.
//
// EPSS download failure is tolerated: the scan continues with zero EPSS
// scores and ScanOK stays true (vulnerability data is still complete). A
// vuln-feed fetch failure returns an error.
func Run(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logger
	start := time.Now()

	// 1. Vulnerability feed (disk cache warm-start).
	vulnFeed, err := loadVulnFeed(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("vulnerability feed: %w", err)
	}

	// 2. EPSS data (disk cache warm-start; tolerate failure).
	epssData, epssErr := loadEPSS(ctx, opts)
	if epssErr != nil {
		logf.Printf("EPSS download failed, proceeding without EPSS scores: %v", epssErr)
	}

	// 3. Installed packages.
	installed, err := debpkg.GetInstalled()
	if err != nil {
		return nil, fmt.Errorf("installed packages: %w", err)
	}
	logf.Printf("found %d installed packages", len(installed))

	debianPkgs, nonDebianPkgs := splitByOrigin(installed)
	if len(nonDebianPkgs) > 0 {
		names := make([]string, 0, len(nonDebianPkgs))
		for _, p := range nonDebianPkgs {
			names = append(names, p.Name)
		}
		logf.Printf("skipping %d non-Debian package(s) from Debian feed scan: %v",
			len(nonDebianPkgs), names)
	}

	// 4. Match Debian-origin packages against the feed; enrich with EPSS.
	detected := matchDebian(debianPkgs, vulnFeed, epssData)

	// 5. Deduplicate (cve, package).
	unique := dedup(detected)

	// 5b. OSV cross-check for non-Debian packages.
	if opts.OSVEnabled && len(nonDebianPkgs) > 0 {
		osvResults, osvErr := loadOSV(ctx, opts, nonDebianPkgs, vulnFeed, epssData)
		if osvErr != nil {
			logf.Printf("OSV cross-check failed in refresh pipeline: %v", osvErr)
		}
		for _, entry := range osvResults {
			key := [2]string{entry.CVE, entry.Package}
			if _, ok := unique[key]; ok {
				continue
			}
			unique[key] = osvToVulnerability(entry)
		}
	}

	// 5c. Enrich with max release versions if enabled.
	if opts.MaxVersionEnabled {
		if err := enrichWithMaxVersions(unique, opts); err != nil {
			logf.Printf("max version enrichment failed: %v", err)
		}
	}

	// 6. Categorise.
	categorized := vuln.Categorise(values(unique))

	duration := time.Since(start)
	logf.Printf("scan complete in %.2fs — %d unique (cve, pkg) pairs across %d installed packages",
		duration.Seconds(), len(unique), len(installed))

	return &Result{
		Categorized:       categorized,
		InstalledPackages: installed,
		ScanTimestamp:     time.Now(),
		ScanDuration:      duration,
		ScanOK:            true,
	}, nil
}

// splitByOrigin partitions packages into Debian-origin and non-Debian slices.
func splitByOrigin(pkgs []debpkg.Package) (debian, nonDebian []debpkg.Package) {
	for _, p := range pkgs {
		if p.IsDebianOrigin() {
			debian = append(debian, p)
		} else {
			nonDebian = append(nonDebian, p)
		}
	}
	return debian, nonDebian
}

// matchDebian runs the debsecan matcher over Debian-origin packages and
// enriches each match with its EPSS score/percentile and the installed
// package/version that triggered it.
func matchDebian(debianPkgs []debpkg.Package, feed map[string][]vuln.Vulnerability, epssData epss.Map) []vuln.Vulnerability {
	var detected []vuln.Vulnerability
	for _, pkg := range debianPkgs {
		relevant := feed[pkg.Source]
		if relevant == nil {
			relevant = feed[pkg.Name]
		}
		for _, v := range relevant {
			if !v.IsVulnerable(pkg) {
				continue
			}
			info := epssData.Lookup(v.BugID)
			v.EPSSScore = info.Score
			v.EPSSPercentile = info.Percentile
			v.InstalledPackage = pkg.Name
			iv := pkg.Version
			v.InstalledVersion = &iv
			v.Source = "debian"
			detected = append(detected, v)
		}
	}
	return detected
}

// dedup collapses repeated (cve, package) pairs, keeping the first.
func dedup(vs []vuln.Vulnerability) map[[2]string]vuln.Vulnerability {
	unique := make(map[[2]string]vuln.Vulnerability, len(vs))
	for _, v := range vs {
		key := [2]string{v.BugID, v.InstalledPackage}
		if _, ok := unique[key]; !ok {
			unique[key] = v
		}
	}
	return unique
}

// values returns the map values as a slice.
func values(m map[[2]string]vuln.Vulnerability) []vuln.Vulnerability {
	out := make([]vuln.Vulnerability, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// osvToVulnerability wraps an OSV result in a Vulnerability so the categoriser
// handles it uniformly.
func osvToVulnerability(r osv.Result) vuln.Vulnerability {
	v := vuln.Vulnerability{
		BugID:            r.CVE,
		Package:          r.Package,
		Description:      r.Description,
		IsBinary:         false,
		Urgency:          r.Urgency,
		Remote:           r.Remote, // nil = unknown
		FixAvailable:     r.FixAvailable,
		EPSSScore:        r.EPSSScore,
		EPSSPercentile:   r.EPSSPercentile,
		InstalledPackage: r.Package,
		Source:           r.Source, // "osv.dev"
	}
	return v
}

// ---------------------------------------------------------------------------
// Disk cache helpers
// ---------------------------------------------------------------------------

// isFresh reports whether path exists and is younger than maxAge.
func isFresh(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < maxAge
}

// atomicWriteJSON writes data as JSON to dest atomically via a temp file,
// then renames it into place so readers never see a partial file.
func atomicWriteJSON(dest string, v any) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(dest)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	enc := json.NewEncoder(tmp)
	if err := enc.Encode(v); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		cleanup()
		return err
	}
	return nil
}

// readJSON reads and decodes a JSON file into v.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// vulnCachePath returns the on-disk path for a suite's vulnerability feed.
func (o Options) vulnCachePath() string {
	if o.CacheDir == "" {
		return ""
	}
	return filepath.Join(o.CacheDir, "vulnerabilities_"+o.Suite+".json")
}

func (o Options) epssCachePath() string {
	if o.CacheDir == "" {
		return ""
	}
	return filepath.Join(o.CacheDir, "epss.json")
}

func (o Options) osvCachePath() string {
	if o.CacheDir == "" {
		return ""
	}
	return filepath.Join(o.CacheDir, "osv_results.json")
}

// loadVulnFeed returns the vulnerability feed, using a fresh disk cache when
// available and otherwise fetching + caching the result.
func loadVulnFeed(ctx context.Context, opts Options) (map[string][]vuln.Vulnerability, error) {
	cachePath := opts.vulnCachePath()
	if cachePath != "" && isFresh(cachePath, opts.RefreshInterval) {
		var raw map[string][]vulnEntry
		if err := readJSON(cachePath, &raw); err == nil {
			return deserializeVulnFeed(raw), nil
		}
	}

	feed, err := vuln.FetchData(ctx, opts.Suite, opts.VulnURL)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if werr := atomicWriteJSON(cachePath, serializeVulnFeed(feed)); werr != nil {
			opts.Logger.Printf("failed to write vulnerability cache: %v", werr)
		}
	}
	return feed, nil
}

// loadEPSS returns the EPSS map, using a fresh disk cache when available and
// otherwise downloading + caching. A download failure is returned as an error
// but does not abort the scan.
func loadEPSS(ctx context.Context, opts Options) (epss.Map, error) {
	cachePath := opts.epssCachePath()
	if cachePath != "" && isFresh(cachePath, opts.RefreshInterval) {
		var m epss.Map
		if err := readJSON(cachePath, &m); err == nil {
			return m, nil
		}
	}

	data, err := epss.Download(ctx, opts.EPSSURL)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if werr := atomicWriteJSON(cachePath, data); werr != nil {
			opts.Logger.Printf("failed to write EPSS cache: %v", werr)
		}
	}
	return data, nil
}

// loadOSV returns the OSV cross-check results, using a fresh disk cache when
// available and otherwise querying OSV.dev + caching.
func loadOSV(ctx context.Context, opts Options, nonDebian []debpkg.Package, feed map[string][]vuln.Vulnerability, epssData epss.Map) ([]osv.Result, error) {
	cachePath := opts.osvCachePath()
	if cachePath != "" && isFresh(cachePath, opts.OSVCacheMaxAge) {
		var r []osv.Result
		if err := readJSON(cachePath, &r); err == nil {
			return r, nil
		}
	}

	results, err := osv.CheckNonDebianPackages(ctx, nonDebian, feed, epssData)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if werr := atomicWriteJSON(cachePath, results); werr != nil {
			opts.Logger.Printf("failed to write OSV cache: %v", werr)
		}
	}
	return results, nil
}

// enrichWithMaxVersions enriches vulnerabilities with max release version info.
func enrichWithMaxVersions(unique map[[2]string]vuln.Vulnerability, opts Options) error {
	ttl := opts.MaxVersionTTL
	if ttl == 0 {
		ttl = 6 * time.Hour
	}

	tracker, err := maxver.New(maxver.Options{
		Suite:    opts.Suite,
		CacheDir: opts.CacheDir,
		TTL:      ttl,
	})
	if err != nil {
		return err
	}

	// Enrich each vulnerability with max version info
	for key, v := range unique {
		maxVer := tracker.GetMaxVersion(v.Package)
		if maxVer == "" {
			continue
		}
		v.MaxReleaseVersion = maxVer

		// Determine if fix is available within the release
		fixVer := fixVersion(v)
		if fixVer != "" {
			if maxV, err := version.New(maxVer); err == nil {
				if fixV, err := version.New(fixVer); err == nil {
					v.FixInRelease = !fixV.Greater(maxV)
				}
			}
		}

		unique[key] = v
	}

	return nil
}

// fixVersion returns the fix version from a vulnerability (unstable or other).
func fixVersion(v vuln.Vulnerability) string {
	if v.UnstableVersion != nil && v.UnstableVersion.String() != "" {
		return v.UnstableVersion.String()
	}
	if len(v.OtherVersions) > 0 {
		return v.OtherVersions[0].String()
	}
	return ""
}

// ErrNoScanData is returned when a scan produces no usable data.
var ErrNoScanData = errors.New("no scan data available")
