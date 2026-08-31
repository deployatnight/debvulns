// Package mcp implements a minimal MCP (Model Context Protocol) server over
// stdio using JSON-RPC 2.0, exposing the two debvulns tools:
//
//   - list_vulnerabilities: scan installed packages and return CVE IDs
//     grouped by derived severity.
//   - research_cves: return detailed information for a list of CVE IDs.
//
// It mirrors the behaviour of the Python debvulns-mcp server (stdio transport
// only). The full scan pipeline (vuln feed + EPSS + installed packages) is
// loaded once at startup via Initialize, then reused by both tools.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/deployatnight/debvulns/internal/debpkg"
	"github.com/deployatnight/debvulns/internal/epss"
	"github.com/deployatnight/debvulns/internal/osv"
	"github.com/deployatnight/debvulns/internal/vuln"
)

// ProtocolVersion is the MCP protocol version this server speaks.
const ProtocolVersion = "2024-11-05"

// Server is the MCP server state.
type Server struct {
	Name    string
	Version string
	Suite   string
	Logger  *log.Logger

	mu            sync.RWMutex
	vulnFeed      map[string][]vuln.Vulnerability
	epssData      epss.Map
	installedPkgs []debpkg.Package
	initialized   bool
	osvEnabled    bool
}

// New creates a Server. Call Initialize before Serve to populate the
// vulnerability feed and EPSS data.
func New(name, version, suite string, osvEnabled bool, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		Name:       name,
		Version:    version,
		Suite:      suite,
		Logger:     logger,
		osvEnabled: osvEnabled,
	}
}

// Initialize fetches the vulnerability feed, EPSS data and installed packages.
// It is safe to call once before Serve.
func (s *Server) Initialize(ctx context.Context) error {
	s.Logger.Printf("Initializing %s MCP Server...", s.Name)

	feed, err := vuln.FetchData(ctx, s.Suite, "")
	if err != nil {
		return fmt.Errorf("vulnerability feed: %w", err)
	}

	data, err := epss.Download(ctx, "")
	if err != nil {
		// EPSS is optional; continue with empty scores.
		s.Logger.Printf("failed to initialize EPSS data: %v", err)
		data = epss.Map{}
	}

	pkgs, err := debpkg.GetInstalled()
	if err != nil {
		s.Logger.Printf("failed to initialize installed packages: %v", err)
	}

	s.mu.Lock()
	s.vulnFeed = feed
	s.epssData = data
	s.installedPkgs = pkgs
	s.initialized = true
	s.mu.Unlock()

	s.Logger.Printf("Initialization complete: %d feed entries, %d EPSS, %d packages",
		len(feed), len(data), len(pkgs))
	return nil
}

// Serve runs the JSON-RPC 2.0 loop over stdio until the input is closed.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	enc := json.NewEncoder(w)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.writeError(enc, nil, -32700, "Parse error")
			continue
		}
		// Notifications have no id; respond with nothing.
		if req.ID == nil && req.Method != "" {
			continue
		}
		resp := s.handle(req)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// request is a JSON-RPC 2.0 request.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// response is a JSON-RPC 2.0 response.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolDef describes one tool for tools/list.
type toolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// toolResult is the content payload for tools/call.
type toolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// handle dispatches one JSON-RPC request to its handler.
func (s *Server) handle(req request) *response {
	switch req.Method {
	case "initialize":
		return s.ok(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    s.Name,
				"version": s.Version,
			},
		})
	case "notifications/initialized":
		return nil
	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": s.tools()})
	case "tools/call":
		return s.handleToolCall(req)
	case "ping":
		return s.ok(req.ID, map[string]any{})
	default:
		return s.err(req.ID, -32601, "method not found: "+req.Method)
	}
}

func (s *Server) ok(id json.RawMessage, result any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) err(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func (s *Server) writeError(enc *json.Encoder, id json.RawMessage, code int, msg string) {
	_ = enc.Encode(&response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

// tools returns the tool definitions exposed by this server.
func (s *Server) tools() []toolDef {
	return []toolDef{
		{
			Name:        "list_vulnerabilities",
			Description: "Lists all vulnerabilities affecting the currently installed packages on the system, categorised by severity (critical, high, medium, low, negligible) and EPSS score.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "research_cves",
			Description: "Provides detailed information for a list of CVE IDs, including package, urgency, EPSS score and percentile, fix availability, remote exploitability and description.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cves": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
				},
				"required": []string{"cves"},
			},
		},
	}
}

// handleToolCall dispatches tools/call to the named tool.
func (s *Server) handleToolCall(req request) *response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.err(req.ID, -32602, "invalid params")
	}

	var text string
	var callErr error
	switch params.Name {
	case "list_vulnerabilities":
		text = s.listVulnerabilities(context.Background())
	case "research_cves":
		var args struct {
			CVEs []string `json:"cves"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return s.err(req.ID, -32602, "invalid arguments: "+err.Error())
		}
		text = s.researchCVEs(args.CVEs)
	default:
		return s.err(req.ID, -32602, "unknown tool: "+params.Name)
	}
	_ = callErr

	return s.ok(req.ID, toolResult{
		Content: []content{{Type: "text", Text: text}},
	})
}

// listVulnerabilities runs the scan and returns CVE IDs grouped by severity as
// JSON text.
func (s *Server) listVulnerabilities(ctx context.Context) string {
	s.mu.RLock()
	feed := s.vulnFeed
	data := s.epssData
	pkgs := s.installedPkgs
	osvOn := s.osvEnabled
	s.mu.RUnlock()

	detected := matchInstalled(pkgs, feed, data)
	unique := dedup(detected)

	// OSV cross-check for non-Debian packages.
	if osvOn {
		_, nonDebian := splitByOrigin(pkgs)
		if len(nonDebian) > 0 {
			results, err := osv.CheckNonDebianPackages(ctx, nonDebian, feed, data)
			if err != nil {
				s.Logger.Printf("OSV cross-check failed: %v", err)
			}
			for _, r := range results {
				key := [2]string{r.CVE, r.Package}
				if _, ok := unique[key]; ok {
					continue
				}
				unique[key] = osvToVuln(r)
			}
		}
	}

	categorized := vuln.Categorise(valuesOf(unique))

	out := make(map[string][]string, len(categorized))
	for sev, vs := range categorized {
		ids := make([]string, 0, len(vs))
		for _, v := range vs {
			ids = append(ids, v.BugID)
		}
		out[sev] = ids
	}
	if len(out) == 0 {
		return "No vulnerabilities detected on the system."
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

// researchCVEs returns detailed markdown for the given CVE IDs.
func (s *Server) researchCVEs(cves []string) string {
	s.mu.RLock()
	feed := s.vulnFeed
	data := s.epssData
	pkgs := s.installedPkgs
	s.mu.RUnlock()

	installedNames := map[string]struct{}{}
	installedSources := map[string]struct{}{}
	for _, p := range pkgs {
		installedNames[p.Name] = struct{}{}
		installedSources[p.Source] = struct{}{}
	}

	var sb strings.Builder
	for _, raw := range cves {
		cve := strings.ToUpper(strings.TrimSpace(raw))
		if sb.Len() > 0 {
			sb.WriteString("\n---\n")
		}
		var found []vuln.Vulnerability
		for _, vs := range feed {
			for _, v := range vs {
				if v.BugID == cve {
					found = append(found, v)
					break
				}
			}
		}
		if len(found) == 0 {
			fmt.Fprintf(&sb, "### %s\nNo detailed information found in current feed.", cve)
			continue
		}
		// Prioritise vulns affecting installed packages.
		sortFound(found, installedNames, installedSources)
		v := found[0]
		info := data.Lookup(v.BugID)

		status := ""
		if _, ok := installedNames[v.Package]; ok {
			status = " (INSTALLED)"
		} else if _, ok := installedSources[v.Package]; ok {
			status = " (INSTALLED)"
		}

		fmt.Fprintf(&sb, "### %s%s\n", v.BugID, status)
		fmt.Fprintf(&sb, "- **Package**: %s\n", v.Package)
		fmt.Fprintf(&sb, "- **Urgency**: %s\n", v.Urgency)
		fmt.Fprintf(&sb, "- **EPSS Score**: %.4f\n", info.Score)
		fmt.Fprintf(&sb, "- **EPSS Percentile**: %.2f%%\n", info.Percentile*100)
		fmt.Fprintf(&sb, "- **Fix Available**: %s\n", yesNo(v.FixAvailable))
		fmt.Fprintf(&sb, "- **Remote**: %s\n", remoteStr(v.Remote))
		fmt.Fprintf(&sb, "- **Description**: %s\n", v.Description)
	}
	return sb.String()
}

// matchInstalled is the debsecan matcher reused by the MCP server.
func matchInstalled(pkgs []debpkg.Package, feed map[string][]vuln.Vulnerability, data epss.Map) []vuln.Vulnerability {
	var detected []vuln.Vulnerability
	for _, pkg := range pkgs {
		if !pkg.IsDebianOrigin() {
			continue
		}
		relevant := feed[pkg.Source]
		if relevant == nil {
			relevant = feed[pkg.Name]
		}
		for _, v := range relevant {
			if !v.IsVulnerable(pkg) {
				continue
			}
			info := data.Lookup(v.BugID)
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

func dedup(vs []vuln.Vulnerability) map[[2]string]vuln.Vulnerability {
	out := make(map[[2]string]vuln.Vulnerability, len(vs))
	for _, v := range vs {
		key := [2]string{v.BugID, v.InstalledPackage}
		if _, ok := out[key]; !ok {
			out[key] = v
		}
	}
	return out
}

func valuesOf(m map[[2]string]vuln.Vulnerability) []vuln.Vulnerability {
	out := make([]vuln.Vulnerability, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

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

func osvToVuln(r osv.Result) vuln.Vulnerability {
	return vuln.Vulnerability{
		BugID:            r.CVE,
		Package:          r.Package,
		Description:      r.Description,
		IsBinary:         false,
		Urgency:          r.Urgency,
		Remote:           r.Remote,
		FixAvailable:     r.FixAvailable,
		EPSSScore:        r.EPSSScore,
		EPSSPercentile:   r.EPSSPercentile,
		InstalledPackage: r.Package,
		Source:           r.Source,
	}
}

// sortFound sorts so installed-package matches come first (stable enough for
// presentation; full ordering is not required).
func sortFound(vs []vuln.Vulnerability, names, sources map[string]struct{}) {
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0; j-- {
			if installedScore(vs[j], names, sources) > installedScore(vs[j-1], names, sources) {
				vs[j], vs[j-1] = vs[j-1], vs[j]
			} else {
				break
			}
		}
	}
}

func installedScore(v vuln.Vulnerability, names, sources map[string]struct{}) int {
	if _, ok := names[v.Package]; ok {
		return 1
	}
	if _, ok := sources[v.Package]; ok {
		return 1
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func remoteStr(remote *bool) string {
	if remote == nil {
		return "unknown"
	}
	if *remote {
		return "Yes"
	}
	return "No"
}
