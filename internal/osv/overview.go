package osv

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/henrygd/beszel/internal/entities/packages"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const maxScanEvents = 40

// ScanEvent is a recent vulnerability scan activity entry.
type ScanEvent struct {
	At         time.Time `json:"at"`
	SystemID   string    `json:"systemId,omitempty"`
	SystemName string    `json:"systemName,omitempty"`
	Action     string    `json:"action"` // queued | started | completed | failed
	Detail     string    `json:"detail,omitempty"`
}

// QueueItem is a system waiting in or running through the scan queue.
type QueueItem struct {
	SystemID   string    `json:"systemId"`
	SystemName string    `json:"systemName"`
	AllSystems bool      `json:"allSystems,omitempty"`
	Queued     bool      `json:"queued"`
	Running    bool      `json:"running"`
	EnqueuedAt time.Time `json:"enqueuedAt,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// SystemVulnOverview is per-system vulnerability scan summary.
type SystemVulnOverview struct {
	SystemID            string `json:"systemId"`
	SystemName          string `json:"systemName"`
	Status              string `json:"status"` // no_packages | never_scanned | queued | running | scanned | failed
	PackageCount        int    `json:"packageCount"`
	ScannedAt           string `json:"scannedAt,omitempty"`
	VulnerableServices  int    `json:"vulnerableServices"`
	KernelVulnerable    bool   `json:"kernelVulnerable"`
	LastError           string `json:"lastError,omitempty"`
	Queued              bool   `json:"queued"`
	Running             bool   `json:"running"`
}

// VulnOverview is the full vulnerability scan dashboard payload.
type VulnOverview struct {
	CronSchedule       string               `json:"cronSchedule"`
	NextCronAt         string               `json:"nextCronAt"`
	LastCronAt         string               `json:"lastCronAt,omitempty"`
	HubStartedAt       string               `json:"hubStartedAt,omitempty"`
	Queue              []QueueItem          `json:"queue"`
	QueueLength        int                  `json:"queueLength"`
	RecentEvents       []ScanEvent          `json:"recentEvents"`
	Systems            []SystemVulnOverview `json:"systems"`
	Stats              VulnOverviewStats    `json:"stats"`
	CacheEntries       int                  `json:"cacheEntries"`
}

type VulnOverviewStats struct {
	Total            int `json:"total"`
	WithPackages     int `json:"withPackages"`
	Scanned          int `json:"scanned"`
	NeverScanned     int `json:"neverScanned"`
	QueuedOrRunning  int `json:"queuedOrRunning"`
	WithVulns        int `json:"withVulns"`
}

type queueEntry struct {
	systemID   string
	enqueuedAt time.Time
}

type OverviewMeta struct {
	CronSchedule string
	LastCronAt   time.Time
	HubStartedAt time.Time
}

// RecordScanEvent appends a scan activity event.
func (s *Scanner) RecordScanEvent(action, systemID, systemName, detail string) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	ev := ScanEvent{
		At:         time.Now().UTC(),
		SystemID:   systemID,
		SystemName: systemName,
		Action:     action,
		Detail:     detail,
	}
	s.events = append(s.events, ev)
	if len(s.events) > maxScanEvents {
		s.events = s.events[len(s.events)-maxScanEvents:]
	}
}

// GetRecentEvents returns recent scan events (newest last).
func (s *Scanner) GetRecentEvents() []ScanEvent {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()
	out := make([]ScanEvent, len(s.events))
	copy(out, s.events)
	return out
}

func (s *Scanner) addQueueEntry(systemID string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.queueOrder = append(s.queueOrder, queueEntry{systemID: systemID, enqueuedAt: time.Now().UTC()})
}

func (s *Scanner) removeQueueEntry(systemID string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.removeQueueEntryLocked(systemID)
}

func (s *Scanner) getQueueItems(systemNames map[string]string) []QueueItem {
	s.pendingMu.Lock()
	order := append([]queueEntry(nil), s.queueOrder...)
	s.pendingMu.Unlock()

	seen := make(map[string]bool, len(order)+4)
	items := make([]QueueItem, 0, len(order)+2)
	for _, e := range order {
		st := s.GetScanStatus(e.systemID)
		name := systemNames[e.systemID]
		if e.systemID == "" {
			name = "All systems"
		}
		seen[e.systemID] = true
		items = append(items, QueueItem{
			SystemID:   e.systemID,
			SystemName: name,
			AllSystems: e.systemID == "",
			Queued:     st.Queued || (!st.Running && st.Error == ""),
			Running:    st.Running,
			EnqueuedAt: e.enqueuedAt,
			StartedAt:  st.StartedAt,
			Error:      st.Error,
		})
	}

	// Include currently running jobs (removed from queueOrder when worker picks them up).
	s.statusMu.RLock()
	for id, st := range s.statuses {
		if !st.Running || seen[id] {
			continue
		}
		name := systemNames[id]
		if id == "" {
			name = "All systems"
		}
		items = append(items, QueueItem{
			SystemID:   id,
			SystemName: name,
			AllSystems: id == "",
			Running:    true,
			StartedAt:  st.StartedAt,
		})
	}
	s.statusMu.RUnlock()

	return items
}

// BuildOverview assembles vulnerability scan status for the given systems.
func (s *Scanner) BuildOverview(app core.App, allowedIDs map[string]bool, systemFilter string, meta OverviewMeta) (*VulnOverview, error) {
	type row struct {
		ID       string `db:"id"`
		Name     string `db:"name"`
		Packages string `db:"packages"`
		Vulns    string `db:"vulns"`
	}
	var rows []row
	err := app.DB().NewQuery(`
		SELECT s.id, s.name, sd.packages, sd.vulns
		FROM systems s
		LEFT JOIN system_details sd ON sd.id = s.id
		ORDER BY s.name
	`).All(&rows)
	if err != nil {
		return nil, err
	}

	names := make(map[string]string, len(rows))
	for _, r := range rows {
		names[r.ID] = r.Name
	}

	queue := s.getQueueItems(names)
	overview := &VulnOverview{
		CronSchedule: meta.CronSchedule,
		NextCronAt:   nextCronAtUTC().Format(time.RFC3339),
		Queue:        queue,
		QueueLength:  len(queue),
		RecentEvents: s.GetRecentEvents(),
		Systems:      []SystemVulnOverview{},
	}
	if !meta.LastCronAt.IsZero() {
		overview.LastCronAt = meta.LastCronAt.UTC().Format(time.RFC3339)
	}
	if !meta.HubStartedAt.IsZero() {
		overview.HubStartedAt = meta.HubStartedAt.UTC().Format(time.RFC3339)
	}

	var cacheCount struct {
		Count int `db:"count"`
	}
	_ = app.DB().NewQuery(`SELECT COUNT(*) AS count FROM package_vuln_cache`).One(&cacheCount)
	overview.CacheEntries = cacheCount.Count

	for _, r := range rows {
		if !allowedIDs[r.ID] {
			continue
		}
		if systemFilter != "" && r.ID != systemFilter {
			continue
		}
		sys := buildSystemOverview(r.ID, r.Name, r.Packages, r.Vulns, s.GetScanStatus(r.ID))
		overview.Systems = append(overview.Systems, sys)
		overview.Stats.Total++
		if sys.PackageCount > 0 {
			overview.Stats.WithPackages++
		}
		switch sys.Status {
		case "scanned":
			overview.Stats.Scanned++
			if sys.VulnerableServices > 0 || sys.KernelVulnerable {
				overview.Stats.WithVulns++
			}
		case "never_scanned":
			overview.Stats.NeverScanned++
		}
		if sys.Queued || sys.Running {
			overview.Stats.QueuedOrRunning++
		}
	}

	// Filter queue/recent events for non-admin single-system view is done in API layer.
	return overview, nil
}

func buildSystemOverview(id, name, packagesRaw, vulnsRaw string, scanStatus ScanStatus) SystemVulnOverview {
	sys := SystemVulnOverview{
		SystemID:   id,
		SystemName: name,
		Queued:     scanStatus.Queued,
		Running:    scanStatus.Running,
		LastError:  scanStatus.Error,
	}

	pkgCount := countPackages(packagesRaw)
	sys.PackageCount = pkgCount

	var vulnData VulnScanData
	hasVulns := false
	if vulnsRaw != "" && vulnsRaw != "null" {
		if err := json.Unmarshal([]byte(vulnsRaw), &vulnData); err == nil {
			hasVulns = vulnData.ScannedAt != ""
			sys.ScannedAt = vulnData.ScannedAt
			for _, info := range vulnData.Services {
				if info != nil && info.Status == "vulnerable" && len(info.Vulns) > 0 {
					sys.VulnerableServices++
				}
			}
			if vulnData.Kernel != nil && vulnData.Kernel.Status == "vulnerable" && len(vulnData.Kernel.Vulns) > 0 {
				sys.KernelVulnerable = true
			}
		}
	}

	switch {
	case scanStatus.Running:
		sys.Status = "running"
	case scanStatus.Queued:
		sys.Status = "queued"
	case scanStatus.Error != "" && !hasVulns:
		sys.Status = "failed"
	case pkgCount == 0:
		sys.Status = "no_packages"
	case !hasVulns:
		sys.Status = "never_scanned"
	default:
		sys.Status = "scanned"
	}
	return sys
}

func countPackages(raw string) int {
	if raw == "" || raw == "null" {
		return 0
	}
	var pkgs []*packages.PackageInfo
	if err := json.Unmarshal([]byte(raw), &pkgs); err != nil {
		return 0
	}
	return len(pkgs)
}

func nextCronAtUTC() time.Time {
	now := time.Now().UTC()
	for h := 0; h < 24; h += 6 {
		candidate := time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, time.UTC)
		if candidate.After(now) {
			return candidate
		}
	}
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

// ResolveSystemName looks up a system display name.
func ResolveSystemName(app core.App, systemID string) string {
	if systemID == "" {
		return "All systems"
	}
	var row struct {
		Name string `db:"name"`
	}
	if err := app.DB().Select("name").From("systems").Where(dbx.HashExp{"id": systemID}).One(&row); err != nil {
		return systemID
	}
	return row.Name
}

// FilterOverviewForSystem returns a copy scoped to one system (hides global queue details of others).
func FilterOverviewForSystem(overview *VulnOverview, systemID string) {
	filteredQueue := make([]QueueItem, 0, 1)
	for _, q := range overview.Queue {
		if q.SystemID == systemID || q.AllSystems {
			filteredQueue = append(filteredQueue, q)
		}
	}
	overview.Queue = filteredQueue
	overview.QueueLength = len(filteredQueue)

	filteredEvents := make([]ScanEvent, 0, len(overview.RecentEvents))
	for _, ev := range overview.RecentEvents {
		if ev.SystemID == systemID || ev.SystemID == "" || strings.Contains(ev.Detail, systemID) {
			filteredEvents = append(filteredEvents, ev)
		}
	}
	overview.RecentEvents = filteredEvents
}
