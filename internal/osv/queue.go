package osv

import (
	"context"
	"time"
)

// ScanStatus tracks vulnerability scan progress for a system (or all systems when ID is "").
type ScanStatus struct {
	Queued    bool      `json:"queued"`
	Running   bool      `json:"running"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	ScannedAt string    `json:"scannedAt,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type scanJob struct {
	systemID   string // empty = all systems
	onComplete func(systemID string)
}

// enqueueScan queues a vulnerability scan. Duplicate jobs for the same target are coalesced.
func (s *Scanner) enqueueScan(systemID string, onComplete func(systemID string)) {
	s.workerOnce.Do(func() {
		go s.worker()
	})

	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	if s.pending[systemID] {
		return
	}
	s.pending[systemID] = true
	s.queueOrder = append(s.queueOrder, queueEntry{systemID: systemID, enqueuedAt: time.Now().UTC()})
	s.setStatus(systemID, ScanStatus{Queued: true, StartedAt: time.Now().UTC()})
	s.RecordScanEvent("queued", systemID, ResolveSystemName(s.app, systemID), "")

	select {
	case s.queue <- scanJob{systemID: systemID, onComplete: onComplete}:
	default:
		go func() {
			s.pendingMu.Lock()
			delete(s.pending, systemID)
			s.pendingMu.Unlock()
			s.runJob(scanJob{systemID: systemID, onComplete: onComplete})
		}()
	}
}

func (s *Scanner) worker() {
	for job := range s.queue {
		s.pendingMu.Lock()
		delete(s.pending, job.systemID)
		s.removeQueueEntryLocked(job.systemID)
		s.pendingMu.Unlock()
		s.runJob(job)
	}
}

func (s *Scanner) removeQueueEntryLocked(systemID string) {
	for i, e := range s.queueOrder {
		if e.systemID == systemID {
			s.queueOrder = append(s.queueOrder[:i], s.queueOrder[i+1:]...)
			return
		}
	}
}

func (s *Scanner) runJob(job scanJob) {
	name := ResolveSystemName(s.app, job.systemID)
	s.RecordScanEvent("started", job.systemID, name, "")
	s.setStatus(job.systemID, ScanStatus{Running: true, StartedAt: time.Now().UTC()})

	ctx, cancel := s.jobTimeout(job.systemID)
	defer cancel()

	var err error
	if job.systemID != "" {
		err = s.scanSystemUnlocked(ctx, job.systemID)
	} else {
		err = s.scanAllSystemsUnlocked(ctx)
	}

	status := ScanStatus{Running: false}
	if err != nil {
		status.Error = err.Error()
		s.app.Logger().Error("Vulnerability scan failed", "system", job.systemID, "err", err)
		s.RecordScanEvent("failed", job.systemID, name, err.Error())
	} else {
		s.RecordScanEvent("completed", job.systemID, name, "")
		if job.systemID != "" {
			if data, getErr := GetVulnData(s.app, job.systemID); getErr == nil && data != nil {
				status.ScannedAt = data.ScannedAt
			}
		}
	}
	s.setStatus(job.systemID, status)

	if job.onComplete != nil {
		job.onComplete(job.systemID)
	}
}

// EnqueueUnscannedSystems queues scans for systems that have package data but no vuln results yet.
func (s *Scanner) EnqueueUnscannedSystems(onComplete func(systemID string)) {
	var rows []struct {
		ID string `db:"id"`
	}
	err := s.app.DB().NewQuery(`
		SELECT id FROM system_details
		WHERE (packages != '' AND packages IS NOT NULL)
		  AND (vulns IS NULL OR vulns = '' OR vulns = 'null')
	`).All(&rows)
	if err != nil {
		s.app.Logger().Error("Failed to list unscanned systems", "err", err)
		return
	}
	if len(rows) == 0 {
		s.app.Logger().Info("No unscanned systems with packages found")
		return
	}
	s.app.Logger().Info("Queueing vulnerability scans for unscanned systems", "count", len(rows))
	for _, row := range rows {
		s.enqueueScan(row.ID, onComplete)
	}
}

func (s *Scanner) jobTimeout(systemID string) (context.Context, context.CancelFunc) {
	if systemID != "" {
		return context.WithTimeout(context.Background(), 15*time.Minute)
	}
	return context.WithTimeout(context.Background(), 60*time.Minute)
}

func (s *Scanner) setStatus(systemID string, status ScanStatus) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if s.statuses == nil {
		s.statuses = make(map[string]ScanStatus)
	}
	s.statuses[systemID] = status
}

// GetScanStatus returns the current scan status for a system (or all systems when ID is "").
func (s *Scanner) GetScanStatus(systemID string) ScanStatus {
	s.statusMu.RLock()
	var status ScanStatus
	if s.statuses != nil {
		status = s.statuses[systemID]
	}
	s.statusMu.RUnlock()

	s.pendingMu.Lock()
	if s.pending[systemID] && !status.Running {
		status.Queued = true
	}
	s.pendingMu.Unlock()

	return status
}

// EnqueueSystemScan queues a scan for a single system.
func (s *Scanner) EnqueueSystemScan(systemID string, onComplete func(systemID string)) {
	s.enqueueScan(systemID, onComplete)
}

// EnqueueAllSystemsScan queues a scan for all systems.
func (s *Scanner) EnqueueAllSystemsScan(onComplete func(systemID string)) {
	s.enqueueScan("", onComplete)
}

// ScanSystem runs a synchronous scan (tests). Prefer EnqueueSystemScan in production.
func (s *Scanner) ScanSystem(ctx context.Context, systemID string) error {
	return s.scanSystemUnlocked(ctx, systemID)
}

// ScanAllSystems runs a synchronous full scan (tests). Prefer EnqueueAllSystemsScan in production.
func (s *Scanner) ScanAllSystems(ctx context.Context) error {
	return s.scanAllSystemsUnlocked(ctx)
}
