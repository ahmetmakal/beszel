package agent

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/agent/utils"
	"github.com/henrygd/beszel/internal/entities/system"
)

type webServerType string

const (
	wsNginx     webServerType = "nginx"
	wsApache    webServerType = "apache"
	wsLitespeed webServerType = "litespeed"
)

type webServerManager struct {
	sync.Mutex
	serverType   webServerType
	statusURL    string // HTTP URL for nginx/apache
	rtReportPath string // file path for litespeed
	httpClient   *http.Client
	prevRequests uint64
	prevBytes    uint64
	prevTime     time.Time
}

func newWebServerManager() *webServerManager {
	if url, exists := utils.GetEnv("NGINX_STATUS_URL"); exists {
		slog.Info("Web server monitoring", "type", "nginx", "url", url)
		return &webServerManager{
			serverType: wsNginx,
			statusURL:  url,
			httpClient: &http.Client{Timeout: 2 * time.Second},
		}
	}
	if url, exists := utils.GetEnv("APACHE_STATUS_URL"); exists {
		slog.Info("Web server monitoring", "type", "apache", "url", url)
		return &webServerManager{
			serverType: wsApache,
			statusURL:  url,
			httpClient: &http.Client{Timeout: 2 * time.Second},
		}
	}
	if path, exists := utils.GetEnv("LITESPEED_RTREPORT"); exists {
		slog.Info("Web server monitoring", "type", "litespeed", "path", path)
		return &webServerManager{
			serverType:   wsLitespeed,
			rtReportPath: path,
		}
	}
	return nil
}

func (m *webServerManager) getStats() *system.WebServerStats {
	m.Lock()
	defer m.Unlock()

	switch m.serverType {
	case wsNginx:
		return m.parseNginx()
	case wsApache:
		return m.parseApache()
	case wsLitespeed:
		return m.parseLitespeed()
	}
	return nil
}

// parseNginx parses nginx stub_status output:
//
//	Active connections: 291
//	server accepts handled requests
//	 16630948 16630948 31070465
//	Reading: 6 Writing: 179 Waiting: 106
func (m *webServerManager) parseNginx() *system.WebServerStats {
	resp, err := m.httpClient.Get(m.statusURL)
	if err != nil {
		slog.Debug("Nginx status error", "err", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	stats := &system.WebServerStats{Type: string(wsNginx)}
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "Active connections:"); ok {
			stats.ActiveConns = parseUint32(strings.TrimSpace(after))
		} else if strings.HasPrefix(line, "Reading:") {
			// Reading: 6 Writing: 179 Waiting: 106
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				stats.Reading = parseUint32(parts[1])
				stats.Writing = parseUint32(parts[3])
				stats.Waiting = parseUint32(parts[5])
			}
		} else if len(line) > 0 && line[0] >= '0' && line[0] <= '9' || (len(line) > 0 && line[0] == ' ') {
			// " 16630948 16630948 31070465" - accepts handled requests
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				totalRequests, _ := strconv.ParseUint(parts[2], 10, 64)
				stats.ReqPerSec = m.calcRate(totalRequests, 0)
			}
		}
	}

	stats.BusyWorkers = stats.Reading + stats.Writing
	stats.IdleWorkers = stats.Waiting

	return stats
}

// parseApache parses Apache mod_status auto output (key: value format)
func (m *webServerManager) parseApache() *system.WebServerStats {
	resp, err := m.httpClient.Get(m.statusURL)
	if err != nil {
		slog.Debug("Apache status error", "err", err)
		return nil
	}
	defer resp.Body.Close()

	stats := &system.WebServerStats{Type: string(wsApache)}
	scanner := bufio.NewScanner(resp.Body)
	var totalAccesses uint64
	var totalKBytes uint64

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)

		switch key {
		case "Total Accesses":
			totalAccesses, _ = strconv.ParseUint(val, 10, 64)
		case "Total kBytes":
			totalKBytes, _ = strconv.ParseUint(val, 10, 64)
		case "BusyWorkers":
			stats.BusyWorkers = parseUint32(val)
		case "IdleWorkers":
			stats.IdleWorkers = parseUint32(val)
		}
	}

	stats.ActiveConns = stats.BusyWorkers + stats.IdleWorkers
	stats.ReqPerSec = m.calcRate(totalAccesses, 0)
	stats.BytesPerSec = m.calcRateFloat(float64(totalKBytes*1024), 0)

	return stats
}

// parseLitespeed parses Litespeed .rtreport file
func (m *webServerManager) parseLitespeed() *system.WebServerStats {
	file, err := os.Open(m.rtReportPath)
	if err != nil {
		slog.Debug("Litespeed rtreport error", "err", err)
		return nil
	}
	defer file.Close()

	stats := &system.WebServerStats{Type: string(wsLitespeed)}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)

		switch key {
		case "REQ_PER_SEC":
			stats.ReqPerSec, _ = strconv.ParseFloat(val, 64)
		case "PLAINCONN":
			stats.ActiveConns = parseUint32(val)
		case "IDLECONN":
			stats.IdleWorkers = parseUint32(val)
		case "REQ_PROCESSING":
			stats.BusyWorkers = parseUint32(val)
		case "BYTES_PER_SEC":
			stats.BytesPerSec, _ = strconv.ParseFloat(val, 64)
		}
	}

	return stats
}

// calcRate computes per-second rate from cumulative counter using delta tracking
func (m *webServerManager) calcRate(currentRequests uint64, currentBytes uint64) float64 {
	now := time.Now()
	if m.prevTime.IsZero() {
		m.prevRequests = currentRequests
		m.prevBytes = currentBytes
		m.prevTime = now
		return 0
	}

	elapsed := now.Sub(m.prevTime).Seconds()
	if elapsed <= 0 {
		return 0
	}

	var rate float64
	if currentRequests >= m.prevRequests {
		rate = float64(currentRequests-m.prevRequests) / elapsed
	}

	m.prevRequests = currentRequests
	m.prevBytes = currentBytes
	m.prevTime = now
	return utils.TwoDecimals(rate)
}

func (m *webServerManager) calcRateFloat(currentBytes float64, _ float64) float64 {
	now := time.Now()
	if m.prevTime.IsZero() {
		m.prevBytes = uint64(currentBytes)
		m.prevTime = now
		return 0
	}

	elapsed := now.Sub(m.prevTime).Seconds()
	if elapsed <= 0 {
		return 0
	}

	var rate float64
	if uint64(currentBytes) >= m.prevBytes {
		rate = (currentBytes - float64(m.prevBytes)) / elapsed
	}

	m.prevBytes = uint64(currentBytes)
	m.prevTime = now
	return utils.TwoDecimals(rate)
}

func parseUint32(s string) uint32 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	return uint32(v)
}

func (m *webServerManager) serverTypeName() string {
	return fmt.Sprintf("%s", m.serverType)
}
