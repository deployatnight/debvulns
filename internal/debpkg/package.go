// Package debpkg models installed Debian packages and enumerates them via
// dpkg-query.
//
// The original Python implementation prefers the libapt C extension
// (python3-apt / apt_pkg) and falls back to dpkg-query. Go has no maintained
// libapt binding, so this package uses the dpkg-query path directly. This is
// the same fallback the Python code documents as covering "most cases" — it
// enumerates every installed package with its binary version, source package
// name and source version, which is everything the vulnerability matcher
// needs.
package debpkg

import (
	"bufio"
	"bytes"
	"errors"
	"os/exec"
	"strings"

	"github.com/deployatnight/debvulns/internal/version"
)

// Package is an installed Debian binary package with its source mapping.
type Package struct {
	Name          string
	Version       version.Version
	Source        string
	SourceVersion version.Version
	// Origin and Archive come from APT PackageFile metadata. The dpkg-query
	// path does not populate them, leaving them empty, which
	// IsDebianOrigin() treats as "unknown -> Debian" (the safe default).
	Origin  string
	Archive string
}

// debianArchives is the set of archive codenames/suites that prove a package
// came from the Debian archive.
var debianArchives = map[string]struct{}{
	"stable":       {},
	"testing":      {},
	"unstable":     {},
	"sid":          {},
	"experimental": {},
	"bookworm":     {},
	"bullseye":     {},
	"buster":       {},
	"stretch":      {},
	"jessie":       {},
	"wheezy":       {},
	"trixie":       {},
	"forky":        {},
}

// IsDebianOrigin reports whether the package demonstrably comes from the
// Debian archive.
//
// When both Origin and Archive are empty (the dpkg-query path, or locally
// built packages) this returns true so the package is still scanned by the
// Debian Security Tracker — the safe default that avoids missing real
// vulnerabilities. A package is considered non-Debian only when the origin is
// explicitly non-Debian, or archive is "now" (locally installed / third-party)
// with an empty origin.
func (p Package) IsDebianOrigin() bool {
	if p.Origin == "Debian" {
		return true
	}
	if _, ok := debianArchives[p.Archive]; ok {
		return true
	}
	if p.Origin == "" && p.Archive == "" {
		return true
	}
	return false
}

// ErrNoPackageSource is returned when neither dpkg-query nor any other
// backend can enumerate installed packages.
var ErrNoPackageSource = errors.New(
	"no package database source available (dpkg-query unavailable/failed)",
)

// dpkgQueryFormat is the output format requested from dpkg-query.
//
//	Field layout (tab-separated, one line per package):
//	  ${db:Status-Status}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n
//
// The \t and \n are passed literally (backslash-t, backslash-n) so dpkg-query
// interprets them as tab and newline escapes — exactly like the Python
// debvulns implementation (`-f=...\\t...\\n`).
const dpkgQueryFormat = "${db:Status-Status}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n"

// GetInstalled enumerates installed packages via dpkg-query.
//
// Packages whose version cannot be parsed are skipped (with the parse error
// swallowed), matching the Python implementation's resilience.
func GetInstalled() ([]Package, error) {
	out, err := runDpkgQuery()
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 || parts[0] != "installed" {
			continue
		}

		name := parts[1]
		verStr := parts[2]
		src := name
		srcVerStr := verStr
		if len(parts) > 3 && parts[3] != "" {
			src = parts[3]
		}
		if len(parts) > 4 && parts[4] != "" {
			srcVerStr = parts[4]
		}

		ver, err := version.New(verStr)
		if err != nil {
			continue
		}
		srcVer, err := version.New(srcVerStr)
		if err != nil {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:          name,
			Version:       ver,
			Source:        src,
			SourceVersion: srcVer,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, err
	}
	return pkgs, nil
}

// runDpkgQuery invokes dpkg-query with the standard format string.
func runDpkgQuery() ([]byte, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f="+dpkgQueryFormat)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
