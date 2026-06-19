// Package osv provides vulnerability scanning via the OSV.dev API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/internal/entities/packages"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const (
	apiBase    = "https://api.osv.dev"
	batchSize  = 100
	batchDelay = 200 * time.Millisecond
	queryDelay = 80 * time.Millisecond
)

// VulnScanData is stored in system_details.vulns as JSON.
type VulnScanData struct {
	ScannedAt string                      `json:"scannedAt"`
	Services  map[string]*ServiceVulnInfo `json:"services"`
	Kernel    *ServiceVulnInfo            `json:"kernel,omitempty"`
	// KernelVersion is the kernel release string that was used during kernel scan.
	KernelVersion string `json:"kernelVersion,omitempty"`
}

// ServiceVulnInfo holds vulnerability information for a single service.
type ServiceVulnInfo struct {
	Status string     `json:"status"` // "safe" | "vulnerable"
	Vulns  []VulnInfo `json:"vulns,omitempty"`
}

// VulnInfo represents a single vulnerability.
type VulnInfo struct {
	ID       string  `json:"id"`
	Summary  string  `json:"summary,omitempty"`
	Score    float64 `json:"score,omitempty"`    // CVSS base score (0-10)
	Severity string  `json:"severity,omitempty"` // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}

// --- OSV API request/response types ---

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package batchPackage `json:"package"`
	Version string       `json:"version"`
}

type batchPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []vulnRef `json:"vulns"`
}

type vulnRef struct {
	ID string `json:"id"`
}

type queryRequest struct {
	Package batchPackage `json:"package"`
	Version string       `json:"version"`
}

type queryResponse struct {
	Vulns []vulnDetail `json:"vulns"`
}

type vulnDetail struct {
	ID               string             `json:"id"`
	Summary          string             `json:"summary"`
	Details          string             `json:"details"`
	Severity         []osvSeverity      `json:"severity"`
	DatabaseSpecific map[string]any     `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// --- Scanner ---

// Scanner handles OSV vulnerability scanning for all systems.
type Scanner struct {
	app    core.App
	client *http.Client

	queue      chan scanJob
	workerOnce sync.Once
	pendingMu  sync.Mutex
	pending    map[string]bool
	statusMu   sync.RWMutex
	statuses   map[string]ScanStatus
}

// NewScanner creates a new OSV vulnerability scanner.
func NewScanner(app core.App) *Scanner {
	return &Scanner{
		app:     app,
		client:  &http.Client{Timeout: 30 * time.Second},
		queue:   make(chan scanJob, 32),
		pending: make(map[string]bool),
	}
}

type systemRow struct {
	ID          string `db:"id"`
	PackagesRaw string `db:"packages"`
	OsName      string `db:"os_name"`
	Kernel      string `db:"kernel"`
}

// scanSystemUnlocked scans a single system for vulnerabilities.
func (s *Scanner) scanSystemUnlocked(ctx context.Context, systemID string) error {
	s.app.Logger().Info("OSV vulnerability scan started (single system)", "system", systemID)

	var row systemRow
	err := s.app.DB().
		Select("id", "packages", "os_name", "kernel").
		From("system_details").
		Where(dbx.HashExp{"id": systemID}).
		One(&row)
	if err != nil {
		return fmt.Errorf("system not found: %w", err)
	}
	return s.scanAndSaveSystem(ctx, row)
}

// scanAllSystemsUnlocked scans packages on all systems for known vulnerabilities.
func (s *Scanner) scanAllSystemsUnlocked(ctx context.Context) error {
	s.app.Logger().Info("OSV vulnerability scan started")

	var rows []systemRow
	err := s.app.DB().
		Select("id", "packages", "os_name", "kernel").
		From("system_details").
		Where(dbx.NewExp("(packages != '' AND packages IS NOT NULL) OR (kernel != '' AND kernel IS NOT NULL)")).
		All(&rows)
	if err != nil {
		return fmt.Errorf("query system_details: %w", err)
	}

	if len(rows) == 0 {
		s.app.Logger().Info("OSV scan: no systems with packages/kernel, skipping")
		return nil
	}

	var firstErr error
	for _, row := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.scanAndSaveSystem(ctx, row); err != nil {
			s.app.Logger().Error("OSV scan failed for system", "system", row.ID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	s.app.Logger().Info("OSV vulnerability scan completed", "systems", len(rows))
	return firstErr
}

func (s *Scanner) scanAndSaveSystem(ctx context.Context, row systemRow) error {
	var pkgs []*packages.PackageInfo
	if row.PackagesRaw != "" {
		if err := json.Unmarshal([]byte(row.PackagesRaw), &pkgs); err != nil {
			return fmt.Errorf("bad packages JSON: %w", err)
		}
	}
	if len(pkgs) == 0 && row.Kernel == "" {
		return nil
	}

	ecosystem := detectEcosystem(row.OsName)
	s.app.Logger().Info("OSV scan", "system", row.ID, "ecosystem", ecosystem, "packages", len(pkgs), "kernel", row.Kernel != "")

	results := make(map[string]*ServiceVulnInfo)
	if len(pkgs) > 0 {
		pkgResults, err := s.scanSystemPackages(ctx, pkgs, ecosystem)
		if err != nil {
			s.app.Logger().Warn("OSV package scan partial failure", "system", row.ID, "err", err)
		}
		if pkgResults != nil {
			results = pkgResults
		}
	}

	scanData := VulnScanData{
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Services:  results,
	}

	if row.Kernel != "" && ecosystem != "" {
		kernelInfo, err := s.scanKernel(ctx, row.Kernel, ecosystem)
		if err != nil {
			s.app.Logger().Debug("OSV kernel scan failed", "system", row.ID, "err", err)
		} else {
			scanData.Kernel = kernelInfo
			scanData.KernelVersion = row.Kernel
		}
	}

	vulnsJSON, err := json.Marshal(scanData)
	if err != nil {
		return err
	}

	_, err = s.app.DB().NewQuery("UPDATE system_details SET vulns = {:vulns} WHERE id = {:id}").
		Bind(dbx.Params{"vulns": string(vulnsJSON), "id": row.ID}).
		Execute()
	return err
}

// pkgKey deduplicates packages across services.
type pkgKey struct {
	name    string
	version string
}

func (s *Scanner) scanSystemPackages(ctx context.Context, pkgs []*packages.PackageInfo, ecosystem string) (map[string]*ServiceVulnInfo, error) {
	// Deduplicate: same package+version can back multiple services.
	svcByPkg := make(map[pkgKey][]string)
	for _, p := range pkgs {
		k := pkgKey{name: p.Package, version: p.Version}
		svcByPkg[k] = append(svcByPkg[k], p.Service)
	}

	keys := make([]pkgKey, 0, len(svcByPkg))
	cacheKeys := make([]cacheKey, 0, len(svcByPkg))
	for k := range svcByPkg {
		keys = append(keys, k)
		cacheKeys = append(cacheKeys, cacheKeyFromPkg(k, ecosystem))
	}

	cached := s.loadCacheEntries(cacheKeys)
	vulnsByPkg := make(map[pkgKey][]VulnInfo, len(svcByPkg))

	// Resolve from cache first; only query OSV for missing or stale entries.
	var toQuery []pkgKey
	for _, k := range keys {
		ck := cacheKeyFromPkg(k, ecosystem)
		if entry, ok := cached[ck]; ok && isCacheFresh(entry) {
			if entry.Status == "vulnerable" && len(entry.Vulns) > 0 {
				vulnsByPkg[k] = entry.Vulns
			} else {
				vulnsByPkg[k] = nil
			}
			continue
		}
		toQuery = append(toQuery, k)
	}

	if len(toQuery) > 0 {
		s.app.Logger().Info("OSV querying packages", "count", len(toQuery), "cached", len(keys)-len(toQuery), "ecosystem", ecosystem)
		queried, err := s.queryPackagesFromOSV(ctx, toQuery, ecosystem)
		if err != nil {
			// Fall back to stale cache entries when the API is unavailable.
			for _, k := range toQuery {
				ck := cacheKeyFromPkg(k, ecosystem)
				if entry, ok := cached[ck]; ok {
					if entry.Status == "vulnerable" && len(entry.Vulns) > 0 {
						vulnsByPkg[k] = entry.Vulns
					}
					continue
				}
			}
			if len(vulnsByPkg) == 0 {
				return nil, err
			}
			s.app.Logger().Warn("OSV query failed, using partial cache results", "err", err)
		} else {
			for k, vulns := range queried {
				vulnsByPkg[k] = vulns
				status := "safe"
				if len(vulns) > 0 {
					status = "vulnerable"
				}
				s.saveCacheEntry(cacheKeyFromPkg(k, ecosystem), cachedEntry{
					Vulns:     vulns,
					Status:    status,
					ScannedAt: time.Now().UTC(),
				})
			}
		}
	} else {
		s.app.Logger().Info("OSV scan served entirely from cache", "packages", len(keys), "ecosystem", ecosystem)
	}

	results := make(map[string]*ServiceVulnInfo, len(pkgs))
	for k, services := range svcByPkg {
		info := &ServiceVulnInfo{Status: "safe"}
		if vulns, ok := vulnsByPkg[k]; ok && len(vulns) > 0 {
			info.Status = "vulnerable"
			info.Vulns = vulns
		}
		for _, svc := range services {
			results[svc] = info
		}
	}
	return results, nil
}

// queryPackagesFromOSV queries OSV.dev for the given packages (cache miss path).
func (s *Scanner) queryPackagesFromOSV(ctx context.Context, keys []pkgKey, ecosystem string) (map[pkgKey][]VulnInfo, error) {
	queries := make([]batchQuery, 0, len(keys))
	for _, k := range keys {
		bp := batchPackage{Name: k.name}
		if ecosystem != "" {
			bp.Ecosystem = ecosystem
		}
		queries = append(queries, batchQuery{Package: bp, Version: k.version})
	}

	affectedPkgs := make(map[pkgKey]bool)
	for i := 0; i < len(queries); i += batchSize {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		end := min(i+batchSize, len(queries))

		body, _ := json.Marshal(batchRequest{Queries: queries[i:end]})
		req, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/v1/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("querybatch: %w", err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("querybatch status %d: %s", resp.StatusCode, string(respBody))
		}

		var br batchResponse
		if err := json.Unmarshal(respBody, &br); err != nil {
			return nil, fmt.Errorf("querybatch decode: %w", err)
		}
		for j, r := range br.Results {
			idx := i + j
			if idx < len(keys) && len(r.Vulns) > 0 {
				affectedPkgs[keys[idx]] = true
			}
		}

		if end < len(queries) {
			time.Sleep(batchDelay)
		}
	}

	vulnsByPkg := make(map[pkgKey][]VulnInfo, len(keys))
	for _, k := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !affectedPkgs[k] {
			vulnsByPkg[k] = nil
			continue
		}
		vulns, err := s.queryPackageVulns(ctx, k, ecosystem)
		if err != nil {
			s.app.Logger().Debug("OSV query failed", "pkg", k.name, "err", err)
			continue
		}
		vulnsByPkg[k] = vulns
		time.Sleep(queryDelay)
	}
	return vulnsByPkg, nil
}

func (s *Scanner) queryPackageVulns(ctx context.Context, k pkgKey, ecosystem string) ([]VulnInfo, error) {
	bp := batchPackage{Name: k.name}
	if ecosystem != "" {
		bp.Ecosystem = ecosystem
	}
	body, _ := json.Marshal(queryRequest{Package: bp, Version: k.version})

	req, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var qr queryResponse
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, err
	}

	out := make([]VulnInfo, 0, len(qr.Vulns))
	for _, v := range qr.Vulns {
		score, sev := extractSeverity(v)
		summary := v.Summary
		if summary == "" && v.Details != "" {
			summary = v.Details
			if len(summary) > 200 {
				summary = summary[:200] + "…"
			}
		}
		out = append(out, VulnInfo{
			ID:       v.ID,
			Summary:  summary,
			Score:    score,
			Severity: sev,
		})
	}
	return out, nil
}

// extractSeverity extracts the CVSS base score and severity label from a vuln.
// Priority: highest CVSS v3 score > database_specific > distro label.
func extractSeverity(v vulnDetail) (float64, string) {
	// Pick the highest CVSS v3 score (some entries have multiple vectors).
	var bestScore float64
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Score, "CVSS:3") {
			if score := parseCVSSv3BaseScore(s.Score); score > bestScore {
				bestScore = score
			}
		}
	}
	if bestScore > 0 {
		return bestScore, cvssLabel(bestScore)
	}
	// Try database_specific.severity (GitHub, etc.)
	if v.DatabaseSpecific != nil {
		if sev, ok := v.DatabaseSpecific["severity"].(string); ok && sev != "" {
			if score, label := labelToScore(sev); label != "" {
				return score, label
			}
		}
	}
	// Fall back to distro-specific label (Ubuntu, Debian, etc.)
	for _, s := range v.Severity {
		switch s.Type {
		case "Ubuntu", "Debian", "AlmaLinux", "Rocky Linux":
			if score, label := labelToScore(s.Score); label != "" {
				return score, label
			}
		}
	}
	return 0, ""
}

func labelToScore(sev string) (float64, string) {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 9.5, "CRITICAL"
	case "HIGH":
		return 7.5, "HIGH"
	case "MODERATE", "MEDIUM":
		return 5.0, "MEDIUM"
	case "LOW":
		return 2.5, "LOW"
	case "NEGLIGIBLE":
		return 0.5, "LOW"
	}
	return 0, ""
}

func cvssLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return ""
}

// parseCVSSv3BaseScore computes the CVSS v3 base score from a vector string.
// Vector format: CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
func parseCVSSv3BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	m := make(map[string]string, len(parts))
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}

	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"
	if !ok1 || !ok2 || !ok3 {
		return 0
	}

	var pr float64
	if scopeChanged {
		pr, _ = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[m["PR"]]
	} else {
		pr, _ = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}
	if pr == 0 {
		return 0
	}

	cVal, _ := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["C"]]
	iVal, _ := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["I"]]
	aVal, _ := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[m["A"]]

	iscBase := 1 - (1-cVal)*(1-iVal)*(1-aVal)

	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploitability)
	} else {
		base = impact + exploitability
	}
	if base > 10 {
		base = 10
	}

	// CVSS roundUp: round up to 1 decimal place
	return math.Ceil(base*10) / 10
}

// --- Ecosystem detection ---

// majorMinorRe extracts only X.Y from a version string (for Ubuntu, Alpine).
var majorMinorRe = regexp.MustCompile(`(\d+\.\d+)`)

// majorRe extracts only the leading integer (for Debian, AlmaLinux, Rocky).
var majorRe = regexp.MustCompile(`(\d+)`)

func detectEcosystem(osName string) string {
	lower := strings.ToLower(osName)

	// Ubuntu: "Ubuntu:24.04" (major.minor only, not point releases like 24.04.4)
	if strings.Contains(lower, "ubuntu") {
		if m := majorMinorRe.FindString(osName); m != "" {
			return "Ubuntu:" + m
		}
		return "Ubuntu"
	}

	// Debian: "Debian:12" (major version only)
	if strings.Contains(lower, "debian") {
		if m := majorRe.FindString(osName); m != "" {
			return "Debian:" + m
		}
		return "Debian"
	}

	// Alpine: "Alpine:v3.18" (major.minor)
	if strings.Contains(lower, "alpine") {
		if m := majorMinorRe.FindString(osName); m != "" {
			return "Alpine:v" + m
		}
		return "Alpine"
	}

	// AlmaLinux: "AlmaLinux:9" (major only)
	if strings.Contains(lower, "almalinux") {
		if m := majorRe.FindString(osName); m != "" {
			return "AlmaLinux:" + m
		}
		return "AlmaLinux"
	}

	// Rocky Linux: "Rocky Linux:9" (major only)
	if strings.Contains(lower, "rocky") {
		if m := majorRe.FindString(osName); m != "" {
			return "Rocky Linux:" + m
		}
		return "Rocky Linux"
	}

	// RHEL / CentOS / Oracle Linux — use AlmaLinux ecosystem as closest match
	for _, distro := range []string{"rhel", "centos", "oracle", "ol", "amzn", "amazon", "cloudlinux"} {
		if strings.Contains(lower, distro) {
			if m := majorRe.FindString(osName); m != "" {
				return "AlmaLinux:" + m
			}
			return "AlmaLinux"
		}
	}

	// Fedora — map to AlmaLinux major version
	if strings.Contains(lower, "fedora") {
		if m := majorRe.FindString(osName); m != "" {
			return "AlmaLinux:" + m
		}
		return "AlmaLinux"
	}

	return ""
}

// kernelPackageName returns the OSV package name for the Linux kernel per ecosystem.
func kernelPackageName(ecosystem string) string {
	lower := strings.ToLower(ecosystem)
	switch {
	case strings.HasPrefix(lower, "ubuntu"), strings.HasPrefix(lower, "debian"):
		return "linux"
	case strings.HasPrefix(lower, "alpine"):
		return "linux-lts"
	case strings.HasPrefix(lower, "almalinux"), strings.HasPrefix(lower, "rocky linux"):
		return "kernel"
	}
	return ""
}

// scanKernel queries OSV for kernel vulnerabilities (with cache).
func (s *Scanner) scanKernel(ctx context.Context, kernelVersion, ecosystem string) (*ServiceVulnInfo, error) {
	pkgName := kernelPackageName(ecosystem)
	if pkgName == "" {
		return nil, fmt.Errorf("unsupported ecosystem for kernel: %s", ecosystem)
	}

	k := pkgKey{name: pkgName, version: kernelVersion}
	ck := cacheKeyFromPkg(k, ecosystem)

	if cached := s.loadCacheEntries([]cacheKey{ck}); len(cached) > 0 {
		if entry, ok := cached[ck]; ok && isCacheFresh(entry) {
			info := &ServiceVulnInfo{Status: entry.Status}
			if len(entry.Vulns) > 0 {
				info.Vulns = entry.Vulns
			}
			return info, nil
		}
	}

	vulns, err := s.queryPackageVulns(ctx, k, ecosystem)
	if err != nil {
		return nil, err
	}

	status := "safe"
	if len(vulns) > 0 {
		status = "vulnerable"
	}
	s.saveCacheEntry(ck, cachedEntry{Vulns: vulns, Status: status, ScannedAt: time.Now().UTC()})

	info := &ServiceVulnInfo{Status: status}
	if len(vulns) > 0 {
		info.Vulns = vulns
	}
	return info, nil
}

// GetVulnData reads stored vulnerability scan data for a system.
func GetVulnData(app core.App, systemID string) (*VulnScanData, error) {
	var row struct {
		VulnsRaw string `db:"vulns"`
	}
	err := app.DB().
		Select("vulns").
		From("system_details").
		Where(dbx.HashExp{"id": systemID}).
		One(&row)
	if err != nil || row.VulnsRaw == "" {
		return nil, err
	}
	var data VulnScanData
	if err := json.Unmarshal([]byte(row.VulnsRaw), &data); err != nil {
		return nil, err
	}
	return &data, nil
}
