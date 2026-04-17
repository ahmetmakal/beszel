package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/internal/entities/system"
)

// cpuPrevEntry stores the previous CPU times for delta calculation.
type cpuPrevEntry struct {
	total float64 // cumulative CPU seconds (user+system)
	tsMs  int64   // timestamp when sampled (unix ms)
}

var (
	cpuPrevMu sync.Mutex
	cpuPrev   = map[int32]cpuPrevEntry{} // keyed by PID
)

// procStat holds raw data parsed from /proc/[pid]/stat.
type procStat struct {
	pid         int32
	name        string
	cmd         string
	state       string
	totalCPUSec float64
	rssBytes    uint64
	memPct      float32
}

// getTopProcesses returns top processes for embedding in system stats.
// Called every stats cycle (~60s), so cpuPrev always has prior data after the first call.
func (a *Agent) getTopProcesses(limit int) []system.TopProcess {
	if runtime.GOOS != "linux" {
		return nil
	}
	if limit <= 0 {
		limit = 10
	}

	nowMs := time.Now().UnixMilli()
	allProcs := readAllProcs()

	cpuPrevMu.Lock()
	needsPrime := len(cpuPrev) == 0
	cpuPrevMu.Unlock()

	// First call: prime cpuPrev and do a quick 2-second measurement
	if needsPrime {
		cpuPrevMu.Lock()
		for _, ps := range allProcs {
			cpuPrev[ps.pid] = cpuPrevEntry{total: ps.totalCPUSec, tsMs: nowMs}
		}
		cpuPrevMu.Unlock()
		time.Sleep(2 * time.Second)
		nowMs = time.Now().UnixMilli()
		allProcs = readAllProcs()
	}

	cpuPrevMu.Lock()
	defer cpuPrevMu.Unlock()

	seenPids := make(map[int32]struct{}, len(allProcs))

	// Aggregate by process name (same-name processes merged)
	type aggregate struct {
		cpuPct float64
		memPct float32
		rss    uint64
		count  uint16
	}
	byName := make(map[string]*aggregate, 128)

	for _, ps := range allProcs {
		seenPids[ps.pid] = struct{}{}

		var cpuPct float64
		if prev, ok := cpuPrev[ps.pid]; ok {
			deltaCPU := ps.totalCPUSec - prev.total
			elapsedSec := float64(nowMs-prev.tsMs) / 1000.0
			if deltaCPU > 0 && elapsedSec > 0.5 {
				cpuPct = (deltaCPU / elapsedSec) * 100
			}
		}
		cpuPrev[ps.pid] = cpuPrevEntry{total: ps.totalCPUSec, tsMs: nowMs}

		// Skip completely idle
		if cpuPct <= 0 && ps.memPct <= 0 {
			continue
		}

		if agg, ok := byName[ps.name]; ok {
			agg.cpuPct += cpuPct
			agg.memPct += ps.memPct
			agg.rss += ps.rssBytes
			agg.count++
		} else {
			byName[ps.name] = &aggregate{
				cpuPct: cpuPct,
				memPct: ps.memPct,
				rss:    ps.rssBytes,
				count:  1,
			}
		}
	}

	// Clean stale entries
	for pid := range cpuPrev {
		if _, ok := seenPids[pid]; !ok {
			delete(cpuPrev, pid)
		}
	}

	// Convert to slice and sort by CPU, then RSS
	results := make([]system.TopProcess, 0, len(byName))
	for name, agg := range byName {
		results = append(results, system.TopProcess{
			Name:   name,
			CpuPct: agg.cpuPct,
			MemPct: agg.memPct,
			Rss:    agg.rss,
			Count:  agg.count,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].CpuPct != results[j].CpuPct {
			return results[i].CpuPct > results[j].CpuPct
		}
		return results[i].Rss > results[j].Rss
	})

	if len(results) > limit {
		results = results[:limit]
	}

	return results
}


// readAllProcs reads /proc for all processes and returns parsed stats.
func readAllProcs() []procStat {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	memTotal := readMemTotal()
	clkTck := float64(100) // clock ticks per second (standard on Linux)

	results := make([]procStat, 0, len(entries)/2)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := int32(pid64)
		procDir := filepath.Join("/proc", entry.Name())

		statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
		if err != nil {
			continue
		}
		stat := string(statBytes)

		openParen := strings.IndexByte(stat, '(')
		closeParen := strings.LastIndexByte(stat, ')')
		if openParen < 0 || closeParen < 0 || closeParen <= openParen {
			continue
		}
		name := stat[openParen+1 : closeParen]

		// Fields after ") ": 0:state 1:ppid ... 11:utime 12:stime ... 21:rss
		rest := stat[closeParen+2:]
		fields := strings.Fields(rest)
		if len(fields) < 22 {
			continue
		}

		state := fields[0]
		utime, _ := strconv.ParseFloat(fields[11], 64)
		stime, _ := strconv.ParseFloat(fields[12], 64)
		rssPages, _ := strconv.ParseInt(fields[21], 10, 64)

		totalCPUSec := (utime + stime) / clkTck
		rssBytes := uint64(rssPages) * 4096

		var memPct float32
		if memTotal > 0 {
			memPct = float32(rssBytes) / float32(memTotal) * 100
		}

		var cmd string
		if cmdBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
			cmd = strings.ReplaceAll(strings.TrimRight(string(cmdBytes), "\x00"), "\x00", " ")
			if len(cmd) > 220 {
				cmd = cmd[:220] + "..."
			}
		}

		results = append(results, procStat{
			pid:         pid,
			name:        name,
			cmd:         cmd,
			state:       state,
			totalCPUSec: totalCPUSec,
			rssBytes:    rssBytes,
			memPct:      memPct,
		})
	}

	return results
}

// readMemTotal reads total memory from /proc/meminfo in bytes.
func readMemTotal() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	line := string(data)
	idx := strings.IndexByte(line, '\n')
	if idx > 0 {
		line = line[:idx]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	kb, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return kb * 1024
}
