// Package exporter implements the debvulns Prometheus exporter: an HTTP
// server exposing vulnerability metrics on /metrics plus liveness/readiness
// endpoints, backed by a background cache refresher.
//
// Design (mirrors docs/prometheus_exporter_design.md):
//
//   - A custom prometheus.Collector reads the latest *scan.Result from the
//     shared Cache on every scrape. There is zero I/O on the hot path.
//   - Before the first scan completes, /metrics and /-/ready return 503;
//     /-/healthy always returns 200 so process supervisors can distinguish
//     "starting" from "broken".
//   - All metric series are rebuilt from the snapshot on each scrape, so
//     stale labels never linger.
//
// Metrics (namespace "debvulns_"):
//
//	debvulns_exporter_info{version,suite} = 1
//	debvulns_scan_status
//	debvulns_last_scan_timestamp_seconds
//	debvulns_scan_duration_seconds
//	debvulns_installed_packages_count
//	debvulns_vulnerabilities_total{severity,fix_available,remote}
//	debvulns_vulnerability_info{cve,package,urgency,severity,fix_available,remote}
//	debvulns_package_info{package,installed_version}
//	debvulns_vulnerability_fix_info{cve,package,fix_version}
//	debvulns_vulnerability_epss_score{cve,package}
//	debvulns_vulnerability_epss_percentile{cve,package}
//	debvulns_package_max_version{package,max_version}
//	debvulns_vulnerability_fix_in_release{cve,package,fix_in_release}
package exporter

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/deployatnight/debvulns/internal/cache"
	"github.com/deployatnight/debvulns/internal/vuln"
)

// Version is the exporter version reported via debvulns_exporter_info. It can
// be overridden at build time with -ldflags "-X .../exporter.Version=...".
var Version = "dev"

// Server is the debvulns Prometheus exporter HTTP server.
type Server struct {
	cache *cache.Cache
	suite string
	addr  string

	registry *prometheus.Registry
}

// New creates an exporter Server bound to the given cache, listening on addr
// (":9222" style) and reporting suite in debvulns_exporter_info.
func New(c *cache.Cache, addr, suite string) *Server {
	s := &Server{
		cache:    c,
		suite:    suite,
		addr:     addr,
		registry: prometheus.NewRegistry(),
	}
	s.registry.MustRegister(newCollector(s.cache, s.suite))
	return s
}

// ListenAndServe starts the HTTP server and blocks until it stops.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.withCache(s.handleMetrics))
	mux.HandleFunc("/-/healthy", handleHealthy)
	mux.Handle("/-/ready", s.withCache(s.handleReady))
	mux.HandleFunc("/", handleNotFound)

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

// withCache wraps a handler that requires the cache to be ready (a non-nil
// snapshot). It is used to gate /metrics and /-/ready on first-scan readiness.
func (s *Server) withCache(fn func(http.ResponseWriter, *http.Request, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, s.cache.Get() != nil)
	})
}

// handleMetrics serves the Prometheus exposition format. Returns 503 until
// the first scan has completed.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, ready bool) {
	if !ready {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Not ready — waiting for first scan\n"))
		return
	}
	promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}).ServeHTTP(w, r)
}

// handleReady returns 200 once the first scan succeeded, 503 otherwise.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request, ready bool) {
	if !ready {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Not ready — waiting for first scan\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Ready\n"))
}

// handleHealthy always returns 200 — it indicates only that the process is
// alive.
func handleHealthy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK\n"))
}

// handleNotFound returns 404 for any other path.
func handleNotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found\n"))
}

// ---------------------------------------------------------------------------
// Custom Prometheus collector
// ---------------------------------------------------------------------------

// collector reads the latest *scan.Result from the cache and emits all
// debvulns_* metrics on every scrape.
type collector struct {
	cache *cache.Cache
	suite string

	// Pre-built descriptors for Describe().
	info           *prometheus.Desc
	scanStatus     *prometheus.Desc
	lastScanTs     *prometheus.Desc
	scanDuration   *prometheus.Desc
	pkgCount       *prometheus.Desc
	vulnsTotal     *prometheus.Desc
	vulnInfo       *prometheus.Desc
	pkgInfo        *prometheus.Desc
	vulnFixInfo    *prometheus.Desc
	epssScore      *prometheus.Desc
	epssPercentile *prometheus.Desc
	pkgMaxVersion  *prometheus.Desc
	vulnFixInRel   *prometheus.Desc
}

func newCollector(c *cache.Cache, suite string) *collector {
	return &collector{
		cache: c,
		suite: suite,
		info: prometheus.NewDesc(
			"debvulns_exporter_info",
			"Metadata about the exporter configuration.",
			[]string{"version", "suite"}, nil,
		),
		scanStatus: prometheus.NewDesc(
			"debvulns_scan_status",
			"1 if the last vulnerability scan completed successfully, 0 otherwise.",
			nil, nil,
		),
		lastScanTs: prometheus.NewDesc(
			"debvulns_last_scan_timestamp_seconds",
			"Unix epoch timestamp of when the last scan was executed.",
			nil, nil,
		),
		scanDuration: prometheus.NewDesc(
			"debvulns_scan_duration_seconds",
			"Duration of the last vulnerability scan in seconds.",
			nil, nil,
		),
		pkgCount: prometheus.NewDesc(
			"debvulns_installed_packages_count",
			"Total number of Debian packages currently installed on the host.",
			nil, nil,
		),
		vulnsTotal: prometheus.NewDesc(
			"debvulns_vulnerabilities_total",
			"Aggregate count of vulnerabilities currently affecting the system.",
			[]string{"severity", "fix_available", "remote"}, nil,
		),
		vulnInfo: prometheus.NewDesc(
			"debvulns_vulnerability_info",
			"Core fact metric — one series per active (cve, package) pair.",
			[]string{"cve", "package", "urgency", "severity", "fix_available", "remote"}, nil,
		),
		pkgInfo: prometheus.NewDesc(
			"debvulns_package_info",
			"Installed version for each vulnerable package (one series per package).",
			[]string{"package", "installed_version"}, nil,
		),
		vulnFixInfo: prometheus.NewDesc(
			"debvulns_vulnerability_fix_info",
			"Fix version for each active (cve, package) pair.",
			[]string{"cve", "package", "fix_version"}, nil,
		),
		epssScore: prometheus.NewDesc(
			"debvulns_vulnerability_epss_score",
			"The EPSS probability score for the detected vulnerability.",
			[]string{"cve", "package"}, nil,
		),
		epssPercentile: prometheus.NewDesc(
			"debvulns_vulnerability_epss_percentile",
			"The EPSS percentile rank of the detected vulnerability.",
			[]string{"cve", "package"}, nil,
		),
		pkgMaxVersion: prometheus.NewDesc(
			"debvulns_package_max_version",
			"Maximum available version for each package within the current release.",
			[]string{"package", "max_version"}, nil,
		),
		vulnFixInRel: prometheus.NewDesc(
			"debvulns_vulnerability_fix_in_release",
			"Indicates whether a fix is available within the current release (1=yes, 0=no).",
			[]string{"cve", "package", "fix_in_release"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
	ch <- c.scanStatus
	ch <- c.lastScanTs
	ch <- c.scanDuration
	ch <- c.pkgCount
	ch <- c.vulnsTotal
	ch <- c.vulnInfo
	ch <- c.pkgInfo
	ch <- c.vulnFixInfo
	ch <- c.epssScore
	ch <- c.epssPercentile
	ch <- c.pkgMaxVersion
	ch <- c.vulnFixInRel
}

// Collect implements prometheus.Collector. It is called on every scrape and
// rebuilds every series from the cached snapshot.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	result := c.cache.Get()
	if result == nil {
		// /metrics is gated to 503 when no snapshot exists, but defend
		// anyway: emit a down scan_status so the registry is never empty.
		ch <- prometheus.MustNewConstMetric(c.scanStatus, prometheus.GaugeValue, 0)
		return
	}

	// --- Static / health metrics ---------------------------------------
	ch <- prometheus.MustNewConstMetric(
		c.info, prometheus.GaugeValue, 1, Version, c.suite)

	scanStatus := 0.0
	if result.ScanOK {
		scanStatus = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.scanStatus, prometheus.GaugeValue, scanStatus)

	ch <- prometheus.MustNewConstMetric(
		c.lastScanTs, prometheus.GaugeValue, float64(result.ScanTimestamp.Unix()))

	ch <- prometheus.MustNewConstMetric(
		c.scanDuration, prometheus.GaugeValue, result.ScanDuration.Seconds())

	ch <- prometheus.MustNewConstMetric(
		c.pkgCount, prometheus.GaugeValue, float64(len(result.InstalledPackages)))

	// On a failed scan with no categorised data, emit nothing else.
	if len(result.Categorized) == 0 {
		return
	}

	// --- Aggregated totals ---------------------------------------------
	type aggKey struct {
		severity, fixAvail, remote string
	}
	agg := map[aggKey]float64{}
	for severity, vs := range result.Categorized {
		for _, v := range vs {
			k := aggKey{severity, boolLabel(v.FixAvailable), remoteLabel(v.Remote)}
			agg[k]++
		}
	}
	for k, count := range agg {
		ch <- prometheus.MustNewConstMetric(
			c.vulnsTotal, prometheus.GaugeValue, count,
			k.severity, k.fixAvail, k.remote)
	}

	// --- Per-(cve, package) metrics ------------------------------------
	seenPackages := map[string]struct{}{}
	maxVersionsEmitted := map[string]struct{}{}
	for severity, vs := range result.Categorized {
		for _, v := range vs {
			pkgName := v.InstalledPackage
			if pkgName == "" {
				pkgName = v.Package
			}
			remoteLbl := remoteLabel(v.Remote)
			fixLbl := boolLabel(v.FixAvailable)

			ch <- prometheus.MustNewConstMetric(
				c.vulnInfo, prometheus.GaugeValue, 1,
				v.BugID, pkgName, v.Urgency, severity, fixLbl, remoteLbl)

			ch <- prometheus.MustNewConstMetric(
				c.vulnFixInfo, prometheus.GaugeValue, 1,
				v.BugID, pkgName, fixVersion(v))

			ch <- prometheus.MustNewConstMetric(
				c.epssScore, prometheus.GaugeValue, v.EPSSScore,
				v.BugID, pkgName)

			ch <- prometheus.MustNewConstMetric(
				c.epssPercentile, prometheus.GaugeValue, v.EPSSPercentile,
				v.BugID, pkgName)

			// Emit fix-in-release metric if available
			if v.MaxReleaseVersion != "" {
				fixInRel := "false"
				if v.FixInRelease {
					fixInRel = "true"
				}
				ch <- prometheus.MustNewConstMetric(
					c.vulnFixInRel, prometheus.GaugeValue, 1,
					v.BugID, pkgName, fixInRel)
			}

			// One series per package (not per CVE).
			if _, ok := seenPackages[pkgName]; !ok {
				seenPackages[pkgName] = struct{}{}
				ch <- prometheus.MustNewConstMetric(
					c.pkgInfo, prometheus.GaugeValue, 1,
					pkgName, installedVersion(v))

				// Emit max version for this package (once per package)
				if v.MaxReleaseVersion != "" {
					if _, emitted := maxVersionsEmitted[pkgName]; !emitted {
						maxVersionsEmitted[pkgName] = struct{}{}
						ch <- prometheus.MustNewConstMetric(
							c.pkgMaxVersion, prometheus.GaugeValue, 1,
							pkgName, v.MaxReleaseVersion)
					}
				}
			}
		}
	}
}

// boolLabel returns "true"/"false".
func boolLabel(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// remoteLabel returns "true"/"false"/"unknown" for a tri-state *bool.
func remoteLabel(remote *bool) string {
	if remote == nil {
		return "unknown"
	}
	if *remote {
		return "true"
	}
	return "false"
}

// fixVersion mirrors the Python _fix_version helper: unstable_version, then
// the first other_version, then "".
func fixVersion(v vuln.Vulnerability) string {
	if v.UnstableVersion != nil && v.UnstableVersion.String() != "" {
		return v.UnstableVersion.String()
	}
	if len(v.OtherVersions) > 0 {
		return v.OtherVersions[0].String()
	}
	return ""
}

// installedVersion returns the installed version string, or "".
func installedVersion(v vuln.Vulnerability) string {
	if v.InstalledVersion != nil {
		return v.InstalledVersion.String()
	}
	return ""
}
