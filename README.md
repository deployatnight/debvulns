# debvulns (Go)

A faithful Go rewrite of [`copyninja/debsecan-mcp`](https://github.com/copyninja/debsecan-mcp)
(originally `debvulns` on PyPI): a Debian vulnerability analysis toolkit —
standalone CLI, MCP server, and **Prometheus exporter**. 

The project ships three binaries built from a single Go module:

| Binary               | Purpose                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `debvulns-exporter`  | Long-running Prometheus exporter (HTTP `/metrics` + health endpoints). |
| `debvulns`           | Standalone CLI that scans once and prints JSON or CSV.                  |
| `debvulns-mcp`       | MCP (Model Context Protocol) server over stdio for AI assistants.       |

All three share the same scan pipeline (`internal/scan`), so behaviour and
categorisation are identical across them.

---

## Why a Go rewrite?

The original is Python and depends on `python3-apt` (a libapt C extension) for
optimal package enumeration. This rewrite:

- Ships as a single statically-linked binary per command — no runtime, no
  virtualenv, no `pip install`, no `UV_PYTHON_INSTALL_DIR` workaround for the
  `ProtectHome=true` systemd unit.
- Keeps the **exact same Prometheus metric set, labels, and cardinality
  strategy** as the Python exporter (see [Metrics](#exposed-metrics)), so the
  bundled Grafana dashboard and existing PromQL alert rules work unchanged.
- Implements the dpkg version-comparison algorithm natively (a direct port of
  dpkg's `verrevcmp`), so version matching no longer requires `python3-apt` or
  `python-debian`.

### Behavioural note vs. the Python exporter

On a scan failure *after* the first successful scan, this rewrite keeps the
last good vulnerability snapshot in the cache **and** flips
`debvulns_scan_status` to `0` (advancing `debvulns_last_scan_timestamp_seconds`).
This matches the intent documented in the upstream
`docs/prometheus_exporter_design.md` ("retain last known-good cache and set
`scan_status` 0"), which the Python implementation did not fully realise. Until
the first scan succeeds, `/metrics` and `/-/ready` return `503` (identical to
the Python behaviour).

---

## Building

Requires Go 1.25+ (the `go.mod` toolchain directive auto-provisions a newer
toolchain if needed).

```bash
make build           # builds bin/debvulns-exporter, bin/debvulns, bin/debvulns-mcp
# or individually:
make exporter
make cli
make mcp
```

The exporter version (reported via `debvulns_exporter_info{version=...}`) is
baked in at build time:

```bash
make build VERSION=1.2.3
```

System-wide install:

```bash
sudo make install    # copies the three binaries to /usr/local/bin
```

---

## Usage

### Prometheus exporter (`debvulns-exporter`)

```bash
debvulns-exporter
```

Starts on the default port **9222** and begins an initial vulnerability scan.
`/metrics` returns `503` until the first scan completes.

```
debvulns-exporter --help
```

Options:

| Flag                      | Default        | Description                                              |
|---------------------------|----------------|----------------------------------------------------------|
| `--port PORT`             | `9222`         | TCP port to expose `/metrics` on.                        |
| `--suite SUITE`           | auto-detected  | Debian suite codename (`bookworm`, `trixie`, `sid`, …). |
| `--refresh-interval SECS` | `86400` (24 h) | Seconds between full scans; minimum `3600` (1 h).        |
| `--cache-dir DIR`         | `/var/cache/debvulns` | Warm-start disk cache directory.               |
| `--no-cache`              | off            | Disable disk caching; always re-download.               |
| `--vuln-url URL`          | upstream       | Override the Debian Security Tracker data URL/path.     |
| `--epss-url URL`          | upstream       | Override the EPSS CSV data URL/path.                     |
| `--osv-cache-max-age SECS`| `604800` (7 d) | Max age for the OSV results cache.                       |
| `--no-osv`                | off            | Disable the OSV.dev cross-check for non-Debian packages. |
| `-v`, `--verbose`         | off            | Debug-level logging to stderr.                           |

#### Health endpoints

| Path           | Behaviour                                                        |
|----------------|------------------------------------------------------------------|
| `/metrics`     | Prometheus exposition; `503` until the first scan completes.     |
| `/-/healthy`   | Always `200 OK` — the process is alive.                          |
| `/-/ready`     | `200 Ready` once the first scan succeeded, `503` otherwise.      |

#### Exposed metrics

All metrics are in the `debvulns_` namespace and are Gauges.

| Metric                                  | Labels                                              | Description |
|-----------------------------------------|-----------------------------------------------------|-------------|
| `debvulns_exporter_info`                | `version`, `suite`                                  | Exporter metadata (always `1`). |
| `debvulns_scan_status`                  | —                                                   | `1` if the last scan succeeded, `0` otherwise. |
| `debvulns_last_scan_timestamp_seconds`  | —                                                   | Unix epoch of the last scan. |
| `debvulns_scan_duration_seconds`         | —                                                   | Duration of the last scan in seconds. |
| `debvulns_installed_packages_count`      | —                                                   | Total installed Debian packages. |
| `debvulns_vulnerabilities_total`        | `severity`, `fix_available`, `remote`               | Aggregate vulnerability count. |
| `debvulns_vulnerability_info`            | `cve`, `package`, `urgency`, `severity`, `fix_available`, `remote` | One series per active `(cve, package)` pair. |
| `debvulns_package_info`                 | `package`, `installed_version`                      | Installed version per vulnerable package (one series per package). |
| `debvulns_vulnerability_fix_info`        | `cve`, `package`, `fix_version`                     | Fix version per `(cve, package)` pair. |
| `debvulns_vulnerability_epss_score`      | `cve`, `package`                                    | EPSS probability score. |
| `debvulns_vulnerability_epss_percentile` | `cve`, `package`                                    | EPSS percentile rank. |

The high-entropy `installed_version` and `fix_version` labels are isolated
into purpose-specific metrics (`debvulns_package_info`,
`debvulns_vulnerability_fix_info`) to keep the core alerting metric
`debvulns_vulnerability_info` cheap and low-churn. Join them in PromQL:

```promql
debvulns_vulnerability_info{severity=~"critical|high"}
  * on(package) group_left(installed_version)
  debvulns_package_info
  * on(cve, package) group_left(fix_version)
  debvulns_vulnerability_fix_info
```

#### Sample output

```text
# HELP debvulns_exporter_info Metadata about the exporter configuration.
# TYPE debvulns_exporter_info gauge
debvulns_exporter_info{suite="trixie",version="0.1.2"} 1

# HELP debvulns_scan_status 1 if the last vulnerability scan completed successfully, 0 otherwise.
# TYPE debvulns_scan_status gauge
debvulns_scan_status 1

# HELP debvulns_installed_packages_count Total number of Debian packages currently installed on the host.
# TYPE debvulns_installed_packages_count gauge
debvulns_installed_packages_count 932

# HELP debvulns_vulnerabilities_total Aggregate count of vulnerabilities currently affecting the system.
# TYPE debvulns_vulnerabilities_total gauge
debvulns_vulnerabilities_total{fix_available="false",remote="false",severity="low"} 15
debvulns_vulnerabilities_total{fix_available="false",remote="false",severity="negligible"} 1670
debvulns_vulnerabilities_total{fix_available="false",remote="unknown",severity="negligible"} 21
debvulns_vulnerabilities_total{fix_available="true",remote="false",severity="negligible"} 186

# HELP debvulns_vulnerability_info Core fact metric — one series per active (cve, package) pair.
# TYPE debvulns_vulnerability_info gauge
debvulns_vulnerability_info{cve="CVE-2017-7475",fix_available="false",package="libcairo2",remote="false",severity="low",urgency="low"} 1

# HELP debvulns_package_info Installed version for each vulnerable package (one series per package).
# TYPE debvulns_package_info gauge
debvulns_package_info{installed_version="1.18.4-1+b1",package="libcairo2"} 1

# HELP debvulns_vulnerability_fix_info Fix version for each active (cve, package) pair.
# TYPE debvulns_vulnerability_fix_info gauge
debvulns_vulnerability_fix_info{cve="CVE-2017-7475",fix_version="",package="libcairo2"} 1

# HELP debvulns_vulnerability_epss_score The EPSS probability score for the detected vulnerability.
# TYPE debvulns_vulnerability_epss_score gauge
debvulns_vulnerability_epss_score{cve="CVE-2017-7475",package="libcairo2"} 0.01824

# HELP debvulns_vulnerability_epss_percentile The EPSS percentile rank of the detected vulnerability.
# TYPE debvulns_vulnerability_epss_percentile gauge
debvulns_vulnerability_epss_percentile{cve="CVE-2017-7475",package="libcairo2"} 0.77264
```

#### Suggested alerts

```yaml
groups:
  - name: debvulns_alerts
    rules:
      - alert: DebvulnsCriticalVulnerabilityWithFix
        expr: debvulns_vulnerabilities_total{severity="critical", fix_available="true"} > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Critical vulnerability with fix available on {{ $labels.instance }}"

      - alert: DebvulnsHighEpssScoreVulnerability
        expr: >
          debvulns_vulnerability_epss_score > 0.70
            * on(cve, package) group_left(severity)
            debvulns_vulnerability_info
        for: 1m
        labels: { severity: warning }
        annotations:
          summary: "High EPSS score vulnerability on {{ $labels.instance }}"

      - alert: DebvulnsScanFailed
        expr: debvulns_scan_status == 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "debvulns scan failed on {{ $labels.instance }}"

      - alert: DebvulnsNoScanReporting
        expr: (time() - debvulns_last_scan_timestamp_seconds) > 86400
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "debvulns cache stale on {{ $labels.instance }}"

      - alert: DebvulnsRemoteExploitableNoFix
        expr: debvulns_vulnerabilities_total{remote="true", fix_available="false", severity=~"critical|high"} > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Unpatched remote-exploitable vulnerability on {{ $labels.instance }}"
```

#### Running as a systemd service

A ready-to-use unit is provided at
[`contrib/systemd/debvulns-exporter.service`](contrib/systemd/debvulns-exporter.service).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin debvulns
sudo make install
sudo cp contrib/systemd/debvulns-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now debvulns-exporter
sudo journalctl -u debvulns-exporter -f
```

The unit runs as the `debvulns` user, applies security hardening
(`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`), and writes
its disk cache to `/var/cache/debvulns`.

#### Grafana dashboard

A pre-built dashboard JSON is at
[`contrib/grafana/debvulns-dashboard.json`](contrib/grafana/debvulns-dashboard.json).
Import it via **Dashboards → Import** and select your Prometheus data source.
It works unchanged because the metric names and labels are identical to the
Python exporter.

---

### Standalone CLI (`debvulns`)

Scans once and prints the result as JSON (default) or CSV.

```bash
debvulns                       # all severities, JSON, grouped by severity
debvulns --severity low --format csv --sort-by cve
debvulns --suite trixie --no-cache --no-osv
```

Options:

| Flag                       | Description                                            |
|----------------------------|--------------------------------------------------------|
| `-s, --severity {critical\|high\|medium\|low\|negligible}` | Filter by severity.           |
| `-f, --format {json\|csv}` | Output format (default `json`).                        |
| `--sort-by {package\|cve}`  | Sort order.                                            |
| `--suite SUITE`            | Debian suite (auto-detected by default).               |
| `--cache-dir DIR`          | Disk cache dir (default `/var/cache/debvulns`).        |
| `--cache-max-age SECS`     | Vuln/EPSS cache TTL (default `86400`).                |
| `--osv-cache-max-age SECS` | OSV results cache TTL (default `604800`).              |
| `--no-cache`              | Bypass the disk cache.                                 |
| `--vuln-url URL`          | Custom vulnerability data URL/path.                    |
| `--epss-url URL`          | Custom EPSS data URL/path.                             |
| `--no-osv`                | Disable the OSV.dev cross-check.                       |
| `-v, --verbose`           | Verbose debug logging to stderr.                       |

---

### MCP server (`debvulns-mcp`)

A minimal MCP server over stdio (JSON-RPC 2.0) exposing two tools:

- `list_vulnerabilities` — returns CVE IDs grouped by derived severity.
- `research_cves` — returns detailed markdown for a list of CVE IDs
  (package, urgency, EPSS score/percentile, fix availability, remote
  exploitability, description).

Set `DEBSECAN_SUITE` to override the auto-detected suite.

```bash
debvulns-mcp                 # stdio transport
DEBSECAN_SUITE=bookworm debvulns-mcp
```

Add to VSCode / opencode / Claude Desktop:

```json
{
  "mcpServers": {
    "debvulns": {
      "command": "debvulns-mcp",
      "env": { "DEBSECAN_SUITE": "bookworm" }
    }
  }
}
```

> The Go MCP server supports the **stdio** transport. HTTP/SSE transports are
> not implemented in this rewrite; use stdio (the default for Claude Desktop,
> VSCode and opencode).

---

## How it works

1. **Package discovery** — enumerates installed packages via `dpkg-query`
   (binary name, version, source package, source version).
2. **Vulnerability data** — fetches the zlib-compressed debsecan feed from the
   [Debian Security Tracker](https://security-tracker.debian.org/).
3. **EPSS enrichment** — downloads the gzipped EPSS CSV from
   [CISA/FIRST](https://www.first.org/epss) and joins by CVE-ID.
4. **Version matching** — compares installed versions against vulnerability
   fix lines using the native dpkg `verrevcmp` algorithm
   (`internal/version`), an exact port of libdpkg.
5. **OSV cross-check** (optional, on by default) — for packages that do not
   originate from the Debian archive, candidate CVEs from the Debian feed are
   confirmed against [OSV.dev](https://osv.dev) using its affected-version
   list.

### Caching

- The exporter keeps the latest scan result in an in-memory `Cache` protected
  by an `RWMutex`; the lock is held only for the pointer swap, so scrapes are
  never blocked by a refresh.
- Disk caching (warm start) is optional but on by default: the debsecan feed
  and EPSS data are cached for `--refresh-interval` (24 h), and OSV results
  for `--osv-cache-max-age` (7 days). Cache files are written atomically via
  temp-file + rename.
- The refresher uses exponential backoff during boot (first scan not yet
  successful) and a fixed interval once steady-state is reached.

---

## Project layout

```
debvulns-go/
├── cmd/
│   ├── debvulns-exporter/   # Prometheus exporter entry point
│   ├── debvulns/            # standalone CLI entry point
│   └── debvulns-mcp/        # MCP server entry point
├── internal/
│   ├── version/             # dpkg version comparison (verrevcmp port)
│   ├── debpkg/              # installed-package enumeration via dpkg-query
│   ├── vuln/                # debsecan feed parser + severity categoriser
│   ├── epss/                # EPSS CSV download + parse
│   ├── osv/                 # OSV.dev cross-check for non-Debian packages
│   ├── suite/               # Debian suite detection (/etc/os-release)
│   ├── scan/                # shared scan pipeline + disk cache
│   ├── cache/               # thread-safe *scan.Result holder
│   ├── refresher/           # background refresh goroutine + backoff
│   ├── exporter/            # HTTP server + Prometheus collector (KEY)
│   ├── format/              # CLI JSON/CSV rendering
│   └── mcp/                 # stdio JSON-RPC 2.0 MCP server
├── contrib/
│   ├── systemd/             # debvulns-exporter.service
│   └── grafana/             # dashboard JSON
├── Makefile
└── go.mod
```

---

## Requirements

- Go 1.25+ to build.
- A Debian-based distribution (Debian, Ubuntu, …) with `dpkg-query`.
- Network access to download the debsecan feed and EPSS data (or a local
  mirror via `--vuln-url` / `--epss-url`).

## License

Same license as the upstream project — see [`LICENSE`](LICENSE).
