// Package epss downloads and parses the EPSS (Exploit Prediction Scoring
// System) CSV published by CISA / FIRST, returning a map of CVE-ID to its
// probability score and percentile rank.
package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// EPSSURL is the canonical EPSS scores download URL.
const EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// Score is the EPSS data for a single CVE.
type Score struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// Map maps CVE-ID -> EPSS Score.
type Map map[string]Score

// Download fetches and parses the EPSS data.
//
// url, when empty, defaults to EPSSURL. http(s) URLs are fetched; local file
// paths are read directly. The file may be gzipped; if gzip decoding fails
// the content is treated as plain CSV (matching the Python fallback).
func Download(ctx context.Context, url string) (Map, error) {
	if url == "" {
		url = EPSSURL
	}

	raw, err := fetchBytes(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download EPSS: %w", err)
	}

	// Decompress gzip, fall back to plain CSV.
	content, err := decompressGzip(raw)
	if err != nil {
		content = raw
	}

	return parseCSV(content)
}

// Lookup returns the Score for cve, or the zero value when the CVE is absent.
func (m Map) Lookup(cve string) Score {
	return m[cve]
}

func fetchBytes(ctx context.Context, url string) ([]byte, error) {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(url)
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// parseCSV parses the EPSS CSV, skipping metadata lines that begin with '#'.
//
// Expected columns: cve, epss, percentile.
func parseCSV(content []byte) (Map, error) {
	// Drop '#' comment/metadata lines (model_version, score_date, ...).
	text := string(content)
	lines := strings.Split(text, "\n")
	dataLines := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
		dataLines = append(dataLines, l)
	}

	reader := csv.NewReader(strings.NewReader(strings.Join(dataLines, "\n")))
	reader.FieldsPerRecord = -1 // tolerate ragged rows; we skip short ones

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse EPSS CSV: %w", err)
	}

	m := make(Map, len(records))
	for _, row := range records {
		if len(row) < 3 {
			continue
		}
		cve := row[0]
		if cve == "" || cve == "cve" {
			continue // header row
		}
		score, err1 := strconv.ParseFloat(row[1], 64)
		percentile, err2 := strconv.ParseFloat(row[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		m[cve] = Score{Score: score, Percentile: percentile}
	}
	return m, nil
}
