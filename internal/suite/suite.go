// Package suite detects the running Debian suite codename.
package suite

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// ErrNotDetected is returned by Detect when the suite cannot be determined.
var ErrNotDetected = errors.New(
	"Debian suite could not be detected. Set DEBSECAN_SUITE environment variable.",
)

// Detect returns the current Debian suite codename.
//
// Resolution order:
//  1. DEBSECAN_SUITE environment variable, if set.
//  2. VERSION_CODENAME from /etc/os-release.
//  3. "sid" if "sid" appears in PRETTY_NAME or VERSION (unstable).
//
// Returns ErrNotDetected if all sources fail.
func Detect() (string, error) {
	if env := os.Getenv("DEBSECAN_SUITE"); env != "" {
		return env, nil
	}

	info, err := readOSRelease()
	if err == nil {
		if codename, ok := info["VERSION_CODENAME"]; ok && codename != "" {
			return codename, nil
		}
		// sid / unstable fallback.
		pretty := strings.ToLower(info["PRETTY_NAME"])
		version := strings.ToLower(info["VERSION"])
		if strings.Contains(pretty, "sid") || strings.Contains(version, "sid") {
			return "sid", nil
		}
	}

	return "", ErrNotDetected
}

// readOSRelease parses /etc/os-release into a key->value map (quotes stripped).
func readOSRelease() (map[string]string, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := make(map[string]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		v = strings.Trim(v, `"`)
		info[k] = v
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return info, nil
}
