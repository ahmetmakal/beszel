package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
)

const cacheMaxAge = 7 * 24 * time.Hour

type cacheKey struct {
	ecosystem string
	package_  string
	version   string
}

type cachedEntry struct {
	Vulns     []VulnInfo
	Status    string
	ScannedAt time.Time
}

func (s *Scanner) loadCacheEntries(keys []cacheKey) map[cacheKey]cachedEntry {
	if len(keys) == 0 {
		return nil
	}

	// Build OR conditions for batch lookup.
	conditions := make([]string, 0, len(keys))
	params := dbx.Params{}
	for i, k := range keys {
		suffix := fmt.Sprintf("%d", i)
		conditions = append(conditions, fmt.Sprintf(
			"(ecosystem = {:eco%[1]s} AND package = {:pkg%[1]s} AND version = {:ver%[1]s})",
			suffix,
		))
		params["eco"+suffix] = k.ecosystem
		params["pkg"+suffix] = k.package_
		params["ver"+suffix] = k.version
	}

	var rows []struct {
		Ecosystem string `db:"ecosystem"`
		Package   string `db:"package"`
		Version   string `db:"version"`
		Vulns     string `db:"vulns"`
		Status    string `db:"status"`
		ScannedAt string `db:"scanned_at"`
	}
	query := fmt.Sprintf(
		"SELECT ecosystem, package, version, vulns, status, scanned_at FROM package_vuln_cache WHERE %s",
		strings.Join(conditions, " OR "),
	)
	if err := s.app.DB().NewQuery(query).Bind(params).All(&rows); err != nil {
		s.app.Logger().Debug("vuln cache lookup failed", "err", err)
		return nil
	}

	out := make(map[cacheKey]cachedEntry, len(rows))
	for _, row := range rows {
		k := cacheKey{ecosystem: row.Ecosystem, package_: row.Package, version: row.Version}
		entry := cachedEntry{Status: row.Status}
		if t, err := time.Parse(time.RFC3339, row.ScannedAt); err == nil {
			entry.ScannedAt = t
		}
		if row.Vulns != "" && row.Vulns != "[]" {
			_ = json.Unmarshal([]byte(row.Vulns), &entry.Vulns)
		}
		out[k] = entry
	}
	return out
}

func (s *Scanner) saveCacheEntry(k cacheKey, entry cachedEntry) {
	vulnsJSON, err := json.Marshal(entry.Vulns)
	if err != nil {
		return
	}
	scannedAt := entry.ScannedAt.UTC().Format(time.RFC3339)
	if scannedAt == "" {
		scannedAt = time.Now().UTC().Format(time.RFC3339)
	}
	status := entry.Status
	if status == "" {
		if len(entry.Vulns) > 0 {
			status = "vulnerable"
		} else {
			status = "safe"
		}
	}

	_, err = s.app.DB().NewQuery(`
		INSERT INTO package_vuln_cache (ecosystem, package, version, vulns, status, scanned_at)
		VALUES ({:eco}, {:pkg}, {:ver}, {:vulns}, {:status}, {:scanned_at})
		ON CONFLICT(ecosystem, package, version) DO UPDATE SET
			vulns = excluded.vulns,
			status = excluded.status,
			scanned_at = excluded.scanned_at
	`).Bind(dbx.Params{
		"eco":        k.ecosystem,
		"pkg":        k.package_,
		"ver":        k.version,
		"vulns":      string(vulnsJSON),
		"status":     status,
		"scanned_at": scannedAt,
	}).Execute()
	if err != nil {
		s.app.Logger().Debug("vuln cache save failed", "pkg", k.package_, "err", err)
	}
}

func isCacheFresh(entry cachedEntry) bool {
	if entry.ScannedAt.IsZero() {
		return false
	}
	return time.Since(entry.ScannedAt) < cacheMaxAge
}

func cacheKeyFromPkg(k pkgKey, ecosystem string) cacheKey {
	return cacheKey{ecosystem: ecosystem, package_: k.name, version: k.version}
}
