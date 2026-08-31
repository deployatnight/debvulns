// Package format renders scan results as JSON or CSV for the debvulns CLI,
// matching the layout of the Python `debvulns` command.
package format

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/deployatnight/debvulns/internal/vuln"
)

// vulnDict is the JSON record for one vulnerability, matching the Python
// format_vuln_dict output.
type vulnDict struct {
	CVE            string  `json:"cve"`
	Package        string  `json:"package"`
	Severity       string  `json:"severity"`
	InstalledVer   string  `json:"installed_version"`
	FixedVer       string  `json:"fixed_version"`
	EPSSScore      float64 `json:"epss_score"`
	EPSSPercentile float64 `json:"epss_percentile"`
	FixAvailable   string  `json:"fix_available"`
	Remote         string  `json:"remote"`
	Description    string  `json:"description"`
	Source         string  `json:"source"`
}

// sortKey selects the sort dimension for the CLI output.
type sortKey string

const (
	sortNone    sortKey = ""
	sortPackage sortKey = "package"
	sortCVE     sortKey = "cve"
)

// formatVuln converts a Vulnerability into a JSON record. The remote field
// uses the Python CLI's "Yes"/"No" representation (unknown treated as "No").
func formatVuln(v vuln.Vulnerability, severity string) vulnDict {
	pkgName := v.InstalledPackage
	if pkgName == "" {
		pkgName = v.Package
	}

	installedVer := ""
	if v.InstalledVersion != nil {
		installedVer = v.InstalledVersion.String()
	}

	fixedVer := "None"
	switch {
	case v.UnstableVersion != nil && v.UnstableVersion.String() != "":
		fixedVer = v.UnstableVersion.String()
	case len(v.OtherVersions) > 0:
		parts := make([]string, 0, len(v.OtherVersions))
		for _, ov := range v.OtherVersions {
			parts = append(parts, ov.String())
		}
		fixedVer = strings.Join(parts, ", ")
	}

	fixAvail := "No"
	if v.FixAvailable {
		fixAvail = "Yes"
	}

	remote := "No"
	if v.Remote != nil && *v.Remote {
		remote = "Yes"
	}

	source := v.Source
	if source == "" {
		source = "debian"
	}

	return vulnDict{
		CVE:            v.BugID,
		Package:        pkgName,
		Severity:       severity,
		InstalledVer:   installedVer,
		FixedVer:       fixedVer,
		EPSSScore:      v.EPSSScore,
		EPSSPercentile: v.EPSSPercentile,
		FixAvailable:   fixAvail,
		Remote:         remote,
		Description:    v.Description,
		Source:         source,
	}
}

// sortVulnerabilities returns a sorted copy of vulns by the given key.
func sortVulnerabilities(vs []vulnDict, by sortKey) []vulnDict {
	if by == sortNone {
		return vs
	}
	out := make([]vulnDict, len(vs))
	copy(out, vs)
	switch by {
	case sortPackage:
		sort.Slice(out, func(i, j int) bool {
			if out[i].Package != out[j].Package {
				return out[i].Package < out[j].Package
			}
			return out[i].CVE < out[j].CVE
		})
	case sortCVE:
		sort.Slice(out, func(i, j int) bool {
			if out[i].CVE != out[j].CVE {
				return out[i].CVE < out[j].CVE
			}
			return out[i].Package < out[j].Package
		})
	}
	return out
}

// WriteJSON writes the categorized vulnerabilities as JSON. When severity is
// non-empty, only that category is emitted as a flat array; otherwise an
// object keyed by severity is emitted.
func WriteJSON(w io.Writer, categorized map[string][]vuln.Vulnerability, severity string, sortBy string) error {
	by := sortKey(sortBy)

	if severity != "" {
		vs := categorized[severity]
		dicts := make([]vulnDict, 0, len(vs))
		for _, v := range vs {
			dicts = append(dicts, formatVuln(v, severity))
		}
		dicts = sortVulnerabilities(dicts, by)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(dicts)
	}

	// Grouped by severity in canonical order.
	out := make(map[string][]vulnDict, len(vuln.SeverityLevels()))
	for _, sev := range vuln.SeverityLevels() {
		vs := categorized[sev]
		dicts := make([]vulnDict, 0, len(vs))
		for _, v := range vs {
			dicts = append(dicts, formatVuln(v, sev))
		}
		out[sev] = sortVulnerabilities(dicts, by)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// csvHeader is the column order for CSV output.
var csvHeader = []string{
	"CVE", "Package", "Severity", "Installed Version", "Fixed Version",
	"EPSS Score", "EPSS Percentile", "Fix Available", "Remote", "Description",
}

// WriteCSV writes all categorized vulnerabilities as CSV (severity filter
// applied when non-empty), in the given sort order.
func WriteCSV(w io.Writer, categorized map[string][]vuln.Vulnerability, severity string, sortBy string) error {
	by := sortKey(sortBy)

	var all []vulnDict
	if severity != "" {
		for _, v := range categorized[severity] {
			all = append(all, formatVuln(v, severity))
		}
	} else {
		for _, sev := range vuln.SeverityLevels() {
			for _, v := range categorized[sev] {
				all = append(all, formatVuln(v, sev))
			}
		}
	}
	all = sortVulnerabilities(all, by)

	ww := csv.NewWriter(w)
	if err := ww.Write(csvHeader); err != nil {
		return err
	}
	for _, v := range all {
		if err := ww.Write([]string{
			v.CVE,
			v.Package,
			v.Severity,
			v.InstalledVer,
			v.FixedVer,
			fmt.Sprintf("%.4f", v.EPSSScore),
			fmt.Sprintf("%.2f%%", v.EPSSPercentile*100),
			v.FixAvailable,
			v.Remote,
			v.Description,
		}); err != nil {
			return err
		}
	}
	ww.Flush()
	return ww.Error()
}
