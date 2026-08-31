package scan

import (
	"github.com/deployatnight/debvulns/internal/version"
	"github.com/deployatnight/debvulns/internal/vuln"
)

// vulnEntry is the on-disk representation of a Vulnerability, mirroring the
// Python debvulns cache format. Enrichment fields (EPSS, installed_*) are not
// stored: they are recomputed on every scan.
type vulnEntry struct {
	BugID           string   `json:"bug_id"`
	Package         string   `json:"package"`
	Description     string   `json:"description"`
	UnstableVersion string   `json:"unstable_version"`
	OtherVersions   []string `json:"other_versions"`
	IsBinary        bool     `json:"is_binary"`
	Urgency         string   `json:"urgency"`
	Remote          *bool    `json:"remote"`
	FixAvailable    bool     `json:"fix_available"`
}

// serializeVulnFeed converts a parsed feed into its on-disk representation.
func serializeVulnFeed(feed map[string][]vuln.Vulnerability) map[string][]vulnEntry {
	out := make(map[string][]vulnEntry, len(feed))
	for pkg, vs := range feed {
		entries := make([]vulnEntry, 0, len(vs))
		for _, v := range vs {
			entry := vulnEntry{
				BugID:        v.BugID,
				Package:      v.Package,
				Description:  v.Description,
				IsBinary:     v.IsBinary,
				Urgency:      v.Urgency,
				Remote:       v.Remote,
				FixAvailable: v.FixAvailable,
			}
			if v.UnstableVersion != nil {
				entry.UnstableVersion = v.UnstableVersion.String()
			}
			if len(v.OtherVersions) > 0 {
				entry.OtherVersions = make([]string, 0, len(v.OtherVersions))
				for _, ov := range v.OtherVersions {
					entry.OtherVersions = append(entry.OtherVersions, ov.String())
				}
			}
			entries = append(entries, entry)
		}
		out[pkg] = entries
	}
	return out
}

// deserializeVulnFeed converts the on-disk representation back into a parsed
// feed. Unparseable versions are skipped, matching the Python resilience.
func deserializeVulnFeed(raw map[string][]vulnEntry) map[string][]vuln.Vulnerability {
	out := make(map[string][]vuln.Vulnerability, len(raw))
	for pkg, entries := range raw {
		vs := make([]vuln.Vulnerability, 0, len(entries))
		for _, e := range entries {
			v := vuln.Vulnerability{
				BugID:        e.BugID,
				Package:      e.Package,
				Description:  e.Description,
				IsBinary:     e.IsBinary,
				Urgency:      e.Urgency,
				Remote:       e.Remote,
				FixAvailable: e.FixAvailable,
			}
			if e.UnstableVersion != "" {
				if uv, err := version.New(e.UnstableVersion); err == nil {
					vv := uv
					v.UnstableVersion = &vv
				}
			}
			if len(e.OtherVersions) > 0 {
				for _, s := range e.OtherVersions {
					if s == "" {
						continue
					}
					if ov, err := version.New(s); err == nil {
						v.OtherVersions = append(v.OtherVersions, ov)
					}
				}
			}
			vs = append(vs, v)
		}
		out[pkg] = vs
	}
	return out
}
