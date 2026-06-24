//go:build linux

package agent

import (
	"context"
	"log/slog"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/agent/utils"
	"github.com/henrygd/beszel/internal/entities/system"
)

type libvirtPrevEntry struct {
	cpuTimeNs uint64
	tsMs      int64
}

type libvirtDomStat struct {
	cpuTimeNs uint64
	rssBytes  uint64
}

// libvirtManager collects CPU and memory stats for running libvirt VMs via virsh.
type libvirtManager struct {
	sync.Mutex
	virshPath   string
	connectArgs []string
	prev        map[string]libvirtPrevEntry
}

func newLibvirtManager() *libvirtManager {
	path, err := exec.LookPath("virsh")
	if err != nil {
		return nil
	}

	m := &libvirtManager{
		virshPath: path,
		prev:      make(map[string]libvirtPrevEntry),
	}
	if uri, exists := utils.GetEnv("LIBVIRT_URI"); exists {
		m.connectArgs = []string{"-c", uri}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmdArgs := append(append([]string{}, m.connectArgs...), "version", "--daemon")
	if err := exec.CommandContext(ctx, path, cmdArgs...).Run(); err != nil {
		slog.Debug("Libvirt", "err", err)
		return nil
	}

	slog.Info("Libvirt monitoring enabled")
	return m
}

func (m *libvirtManager) virshArgs(args ...string) []string {
	cmdArgs := make([]string, 0, len(m.connectArgs)+len(args))
	cmdArgs = append(cmdArgs, m.connectArgs...)
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

func (m *libvirtManager) runVirsh(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, m.virshPath, m.virshArgs(args...)...).Output()
}

// getTopVMs returns top running VMs by CPU usage for embedding in system stats.
func (m *libvirtManager) getTopVMs(limit int) []system.TopProcess {
	if m == nil {
		return nil
	}
	if limit <= 0 {
		limit = 10
	}

	m.Lock()
	defer m.Unlock()

	domains := m.listRunningDomains()
	if len(domains) == 0 {
		return nil
	}

	args := make([]string, 0, 3+len(domains))
	args = append(args, "domstats", "--cpu-total", "--balloon")
	args = append(args, domains...)
	output, err := m.runVirsh(args...)
	if err != nil {
		slog.Debug("Libvirt", "err", err)
		return nil
	}

	stats := parseDomstatsOutput(string(output))
	if len(stats) == 0 {
		return nil
	}

	nowMs := time.Now().UnixMilli()
	memTotal := readMemTotal()

	results := make([]system.TopProcess, 0, len(stats))
	for name, ds := range stats {
		var cpuPct float64
		if prev, ok := m.prev[name]; ok && ds.cpuTimeNs >= prev.cpuTimeNs {
			deltaNs := ds.cpuTimeNs - prev.cpuTimeNs
			elapsedSec := float64(nowMs-prev.tsMs) / 1000.0
			if deltaNs > 0 && elapsedSec > 0.5 {
				cpuPct = (float64(deltaNs) / 1e9 / elapsedSec) * 100
			}
		}
		m.prev[name] = libvirtPrevEntry{cpuTimeNs: ds.cpuTimeNs, tsMs: nowMs}

		rss := ds.rssBytes
		var memPct float32
		if memTotal > 0 && rss > 0 {
			memPct = float32(rss) / float32(memTotal) * 100
		}

		if cpuPct <= 0 && memPct <= 0 {
			continue
		}

		results = append(results, system.TopProcess{
			Name:   name,
			CpuPct: cpuPct,
			MemPct: memPct,
			Rss:    rss,
		})
	}

	for name := range m.prev {
		if _, ok := stats[name]; !ok {
			delete(m.prev, name)
		}
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

// listRunningDomains returns names of running VMs via `virsh list --name`.
func (m *libvirtManager) listRunningDomains() []string {
	output, err := m.runVirsh("list", "--name")
	if err != nil {
		slog.Debug("Libvirt", "err", err)
		return nil
	}
	return parseVirshListNames(string(output))
}

func parseVirshListNames(output string) []string {
	var names []string
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names
}

// parseDomstatsOutput parses virsh domstats output grouped by domain name.
func parseDomstatsOutput(output string) map[string]libvirtDomStat {
	stats := make(map[string]libvirtDomStat)
	var current string

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Domain:") {
			current = parseDomstatsDomainName(line)
			continue
		}
		if current == "" {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		ds := stats[current]
		switch key {
		case "cpu.time":
			ds.cpuTimeNs, _ = strconv.ParseUint(val, 10, 64)
		case "balloon.rss", "memory.rss":
			if kb, err := strconv.ParseUint(val, 10, 64); err == nil && kb > 0 {
				ds.rssBytes = kb * 1024
			}
		case "balloon.current", "memory.actual":
			if ds.rssBytes == 0 {
				if kb, err := strconv.ParseUint(val, 10, 64); err == nil && kb > 0 {
					ds.rssBytes = kb * 1024
				}
			}
		}
		stats[current] = ds
	}

	return stats
}

func parseDomstatsDomainName(line string) string {
	if start := strings.Index(line, "'"); start >= 0 {
		if end := strings.Index(line[start+1:], "'"); end >= 0 {
			return line[start+1 : start+1+end]
		}
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Domain:"))
	return strings.Trim(rest, "'\"")
}
