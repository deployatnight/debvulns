// Package osv cross-checks non-Debian packages against the OSV.dev database.
//
// Strategy (mirrors the Python osv module):
//  1. For each non-Debian package, find candidate CVEs from the Debian
//     Security Tracker feed (the feed lists upstream CVEs even when Debian
//     itself ships no fix).
//  2. For each candidate CVE, fetch the authoritative OSV record via
//     GET https://api.osv.dev/v1/vulns/{CVE-ID}.
//  3. If the installed version is NOT in the OSV affected[] versions list, the
//     upstream fix is already present -> drop it.
//  4. Return only genuinely affected (cve, package) pairs.
//
// Fetches run with bounded concurrency to be polite to the OSV API while
// still completing quickly for hosts with many third-party packages.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/deployatnight/debvulns/internal/debpkg"
	"github.com/deployatnight/debvulns/internal/epss"
	"github.com/deployatnight/debvulns/internal/vuln"
)

// OSVBaseURL is the OSV.dev vulnerability lookup endpoint.
const OSVBaseURL = "https://api.osv.dev/v1/vulns"

// maxConcurrentRequests bounds the number of in-flight OSV API calls.
const maxConcurrentRequests = 8

// OsvVulnerability is a lightweight view of an OSV record.
type OsvVulnerability struct {
	ID               string
	Summary          string
	Details          string
	Severity         []map[string]any
	AffectedVersions []string
	Aliases          []string
}

// CVSSBaseScore extracts the numeric CVSS base score from the severity entries,
// falling back to 5.0 (a conservative "medium") when the score is not present.
func (o OsvVulnerability) CVSSBaseScore() float64 {
	for _, entry := range o.Severity {
		if scoreVal, ok := entry["base_score"]; ok {
			switch s := scoreVal.(type) {
			case float64:
				return s
			case int:
				return float64(s)
			}
		}
	}
	return 5.0
}

// UrgencyFromCVSS maps a CVSS base score to a Debian-style urgency label.
func (o OsvVulnerability) UrgencyFromCVSS() string {
	score := o.CVSSBaseScore()
	switch {
	case score >= 9.0:
		return "high" // will be promoted to critical by the categoriser
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// Result is one OSV-confirmed vulnerable (cve, package) pair.
type Result struct {
	CVE              string  `json:"cve"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	Urgency          string  `json:"urgency"`
	EPSSScore        float64 `json:"epss_score"`
	EPSSPercentile   float64 `json:"epss_percentile"`
	Description      string  `json:"description"`
	FixAvailable     bool    `json:"fix_available"`
	Remote           *bool   `json:"remote"` // always nil ("unknown") for OSV results
	Source           string  `json:"source"`
}

// CheckNonDebianPackages cross-checks the given non-Debian packages against
// OSV.dev, using CVE IDs discovered in the Debian feed as candidates.
//
// Only (cve, package) pairs whose installed version appears in the OSV
// affected[] list are returned.
func CheckNonDebianPackages(
	ctx context.Context,
	nonDebianPkgs []debpkg.Package,
	vulnFeed map[string][]vuln.Vulnerability,
	epssData epss.Map,
) ([]Result, error) {
	client := &http.Client{Timeout: osvHTTPTimeout}

	type cached struct {
		v   *OsvVulnerability
		err error
	}

	var (
		mu        sync.Mutex
		osvCache  = make(map[string]*OsvVulnerability)
		osvErr    = make(map[string]error)
		results   []Result
		resultsMu sync.Mutex
	)

	sem := make(chan struct{}, maxConcurrentRequests)
	var wg sync.WaitGroup

	fetchOSV := func(cveID string) (*OsvVulnerability, error) {
		mu.Lock()
		if v, ok := osvCache[cveID]; ok {
			err := osvErr[cveID]
			mu.Unlock()
			return v, err
		}
		mu.Unlock()

		sem <- struct{}{}
		defer func() { <-sem }()

		v, err := fetchOSVVuln(ctx, client, cveID)

		mu.Lock()
		if v != nil {
			osvCache[cveID] = v
		}
		if err != nil {
			osvErr[cveID] = err
		}
		mu.Unlock()
		return v, err
	}

	for _, pkg := range nonDebianPkgs {
		candidates := vulnFeed[pkg.Source]
		if candidates == nil {
			candidates = vulnFeed[pkg.Name]
		}

		// Collect unique CVE IDs from the candidate list.
		seen := make(map[string]struct{})
		var cveIDs []string
		for _, dv := range candidates {
			if _, ok := seen[dv.BugID]; ok {
				continue
			}
			seen[dv.BugID] = struct{}{}
			cveIDs = append(cveIDs, dv.BugID)
		}

		for _, cveID := range cveIDs {
			cveID := cveID
			pkg := pkg
			wg.Add(1)
			go func() {
				defer wg.Done()
				osvV, err := fetchOSV(cveID)
				if err != nil || osvV == nil {
					return
				}
				if !isVersionAffected(pkg.Version.String(), *osvV) {
					return
				}
				epssInfo := epssData.Lookup(cveID)
				description := osvV.Details
				if description == "" {
					description = osvV.Summary
				}
				if len(description) > 200 {
					description = description[:200]
				}

				resultsMu.Lock()
				results = append(results, Result{
					CVE:              cveID,
					Package:          pkg.Name,
					InstalledVersion: pkg.Version.String(),
					Urgency:          osvV.UrgencyFromCVSS(),
					EPSSScore:        epssInfo.Score,
					EPSSPercentile:   epssInfo.Percentile,
					Description:      description,
					FixAvailable:     true,
					Remote:           nil,
					Source:           "osv.dev",
				})
				resultsMu.Unlock()
			}()
		}
	}

	wg.Wait()
	return results, nil
}

// fetchOSVVuln fetches a single vulnerability record by CVE ID.
//
// Returns (nil, nil) when OSV has no record (HTTP 404) or the record has no
// enumerated affected versions.
func fetchOSVVuln(ctx context.Context, client *http.Client, cveID string) (*OsvVulnerability, error) {
	url := OSVBaseURL + "/" + cveID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return parseOSVResponse(data), nil
}

// parseOSVResponse converts a raw OSV API response into an OsvVulnerability.
func parseOSVResponse(data map[string]any) *OsvVulnerability {
	if data == nil {
		return nil
	}
	v := &OsvVulnerability{
		ID:      getString(data, "id"),
		Summary: getString(data, "summary"),
		Details: getString(data, "details"),
		Aliases: getStringSlice(data, "aliases"),
	}
	if sev, ok := data["severity"].([]any); ok {
		for _, s := range sev {
			if m, ok := s.(map[string]any); ok {
				v.Severity = append(v.Severity, m)
			}
		}
	}
	if affected, ok := data["affected"].([]any); ok {
		for _, a := range affected {
			if block, ok := a.(map[string]any); ok {
				if versions, ok := block["versions"].([]any); ok {
					for _, ver := range versions {
						if s, ok := ver.(string); ok {
							v.AffectedVersions = append(v.AffectedVersions, s)
						}
					}
				}
			}
		}
	}
	if len(v.AffectedVersions) == 0 {
		return nil
	}
	return v
}

// isVersionAffected reports whether installedVersion appears in the OSV
// affected versions list (leading 'v' prefix stripped from both sides).
func isVersionAffected(installedVersion string, osvV OsvVulnerability) bool {
	if len(osvV.AffectedVersions) == 0 {
		return false
	}
	normalized := strings.TrimPrefix(installedVersion, "v")
	for _, av := range osvV.AffectedVersions {
		if strings.TrimPrefix(av, "v") == normalized {
			return true
		}
	}
	return false
}

// getString returns data[key] as a string, or "".
func getString(data map[string]any, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

// getStringSlice returns data[key] as a []string.
func getStringSlice(data map[string]any, key string) []string {
	arr, ok := data[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
