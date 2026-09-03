// Package maxver tracks the maximum available version of each package within
// a Debian/Ubuntu release suite by querying the Packages index from official
// repositories.
package maxver

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deployatnight/debvulns/internal/version"
)

// Tracker holds cached maximum versions for packages in a suite.
type Tracker struct {
	suite       string
	maxVersions map[string]version.Version
	cacheDir    string
	ttl         time.Duration
	lastFetch   time.Time
	httpClient  *http.Client
}

// Options configures a Tracker.
type Options struct {
	Suite    string        // required: debian suite codename (e.g., "bookworm")
	CacheDir string        // optional: directory for caching package lists
	TTL      time.Duration // cache TTL (default: 6h)
}

// New creates a new Tracker for the given suite.
func New(opts Options) (*Tracker, error) {
	if opts.Suite == "" {
		return nil, fmt.Errorf("suite is required")
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = 6 * time.Hour
	}
	return &Tracker{
		suite:       opts.Suite,
		maxVersions: make(map[string]version.Version),
		cacheDir:    opts.CacheDir,
		ttl:         ttl,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetMaxVersion returns the maximum version of a package in the suite.
// Returns empty string if not found.
func (t *Tracker) GetMaxVersion(packageName string) string {
	if err := t.ensureFresh(context.Background()); err != nil {
		// Return cached data even if stale on error
	}
	v, ok := t.maxVersions[packageName]
	if !ok {
		return ""
	}
	return v.String()
}

// GetAllMaxVersions returns all tracked maximum versions.
func (t *Tracker) GetAllMaxVersions() map[string]version.Version {
	if err := t.ensureFresh(context.Background()); err != nil {
		// Continue with potentially stale data
	}
	result := make(map[string]version.Version, len(t.maxVersions))
	for k, v := range t.maxVersions {
		result[k] = v
	}
	return result
}

// ensureFresh fetches package lists if cache is expired or missing.
func (t *Tracker) ensureFresh(ctx context.Context) error {
	if time.Since(t.lastFetch) < t.ttl && len(t.maxVersions) > 0 {
		return nil
	}
	return t.fetchPackageList(ctx)
}

// fetchPackageList downloads and parses the Packages list for the suite.
func (t *Tracker) fetchPackageList(ctx context.Context) error {
	// Try to load from cache first
	cachePath := t.cachePath()
	if cachePath != "" {
		if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < t.ttl {
			if err := t.loadFromCache(cachePath); err == nil {
				t.lastFetch = time.Now()
				return nil
			}
		}
	}

	// Fetch from Debian archive
	baseURLs := []string{
		fmt.Sprintf("http://deb.debian.org/debian/dists/%s/main/binary-amd64/Packages.gz", t.suite),
		fmt.Sprintf("http://deb.debian.org/debian/dists/%s/main/binary-all/Packages.gz", t.suite),
		fmt.Sprintf("http://security.debian.org/debian-security/dists/%s-security/main/binary-amd64/Packages.gz", t.suite),
	}

	allPackages := make(map[string]version.Version)

	for _, pkgURL := range baseURLs {
		pkgs, err := t.fetchPackagesFromURL(ctx, pkgURL)
		if err != nil {
			continue // Try next URL
		}
		for name, ver := range pkgs {
			if existing, ok := allPackages[name]; !ok || ver.Greater(existing) {
				allPackages[name] = ver
			}
		}
	}

	if len(allPackages) == 0 {
		return fmt.Errorf("no packages fetched for suite %s", t.suite)
	}

	t.maxVersions = allPackages
	t.lastFetch = time.Now()

	// Save to cache
	if cachePath != "" {
		if err := t.saveToCache(cachePath); err != nil {
			// Log but don't fail
		}
	}

	return nil
}

// fetchPackagesFromURL downloads and parses a Packages.gz file.
func (t *Tracker) fetchPackagesFromURL(ctx context.Context, rawURL string) (map[string]version.Version, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
	}

	return parsePackages(resp.Body)
}

// parsePackages reads a Packages or Packages.gz file and extracts package versions.
func parsePackages(r io.Reader) (map[string]version.Version, error) {
	var reader io.Reader = r

	// Check if it's gzipped by reading first bytes
	buf := make([]byte, 2)
	n, _ := r.Read(buf)
	if n == 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		// It's gzipped
		gzReader, err := gzip.NewReader(io.MultiReader(bytes.NewReader(buf), r))
		if err != nil {
			return nil, err
		}
		reader = gzReader
	} else {
		// Not gzipped, prepend the bytes we read
		reader = io.MultiReader(bytes.NewReader(buf[:n]), r)
	}

	packages := make(map[string]version.Version)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var currentPackage string
	var currentVersion string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// End of package entry
			if currentPackage != "" && currentVersion != "" {
				if v, err := version.New(currentVersion); err == nil {
					existing, ok := packages[currentPackage]
					if !ok || v.Greater(existing) {
						packages[currentPackage] = v
					}
				}
			}
			currentPackage = ""
			currentVersion = ""
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPackage = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			currentVersion = strings.TrimPrefix(line, "Version: ")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Handle last package
	if currentPackage != "" && currentVersion != "" {
		if v, err := version.New(currentVersion); err == nil {
			existing, ok := packages[currentPackage]
			if !ok || v.Greater(existing) {
				packages[currentPackage] = v
			}
		}
	}

	return packages, nil
}

// cachePath returns the path for caching package lists.
func (t *Tracker) cachePath() string {
	if t.cacheDir == "" {
		return ""
	}
	return filepath.Join(t.cacheDir, "maxver_"+t.suite+".txt")
}

// loadFromCache loads maximum versions from a text cache file.
func (t *Tracker) loadFromCache(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	t.maxVersions = make(map[string]version.Version)

	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if v, err := version.New(parts[1]); err == nil {
			t.maxVersions[parts[0]] = v
		}
	}

	return nil
}

// saveToCache saves maximum versions to a text cache file.
func (t *Tracker) saveToCache(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var buf bytes.Buffer
	for name, ver := range t.maxVersions {
		fmt.Fprintf(&buf, "%s\t%s\n", name, ver.String())
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return err
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	return os.Rename(tmpName, path)
}

// BuildDebianURL constructs the URL for a Debian Packages list.
func BuildDebianURL(suite, component, arch string) string {
	return fmt.Sprintf(
		"http://deb.debian.org/debian/dists/%s/%s/binary-%s/Packages.gz",
		suite, component, arch,
	)
}

// BuildSecurityURL constructs the URL for Debian Security Packages list.
func BuildSecurityURL(suite, arch string) string {
	return fmt.Sprintf(
		"http://security.debian.org/debian-security/dists/%s-security/main/binary-%s/Packages.gz",
		suite, arch,
	)
}

// IsGzipped checks if a URL points to a gzipped file.
func IsGzipped(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasSuffix(u.Path, ".gz")
}

// FetchWithGzip handles both gzipped and plain HTTP responses.
func (t *Tracker) FetchWithGzip(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
	}

	if IsGzipped(rawURL) {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		return &readCloser{Reader: gzReader, Closer: resp.Body}, nil
	}

	return resp.Body, nil
}

// readCloser wraps a Reader and Closer.
type readCloser struct {
	io.Reader
	io.Closer
}
