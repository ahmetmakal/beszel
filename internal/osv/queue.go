package osv

import (
	"context"
	"time"
)

// ScanStatus tracks vulnerability scan progress for a system (or all systems when ID is "").
type ScanStatus struct {
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
		s.pendingMu.Unlock()
		s.runJob(job)
	}
}

func (s *Scanner) runJob(job scanJob) {
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
	} else if job.systemID != "" {
		if data, getErr := GetVulnData(s.app, job.systemID); getErr == nil && data != nil {
			status.ScannedAt = data.ScannedAt
		}
	}
	s.setStatus(job.systemID, status)

	if job.onComplete != nil {
		job.onComplete(job.systemID)
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
	defer s.statusMu.RUnlock()
	if s.statuses == nil {
		return ScanStatus{}
	}
	return s.statuses[systemID]
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
