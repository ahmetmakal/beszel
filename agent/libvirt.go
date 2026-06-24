//go:build linux

package agent

import (
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/henrygd/beszel/agent/utils"
	"github.com/henrygd/beszel/internal/entities/libvirt"
)

type vmPrevEntry struct {
	cpuUsage uint64
	tsMs     int64
}

type libvirtManager struct {
	sync.Mutex
	prevCpu map[string]vmPrevEntry
}

func newLibvirtManager() *libvirtManager {
	if _, err := os.Stat("/run/libvirt/libvirt-sock"); err != nil {
		if _, err2 := os.Stat("/var/run/libvirt/libvirt-sock"); err2 != nil {
			slog.Debug("Libvirt unavailable", "reason", "libvirt socket not found")
			return nil
		}
	}
	slog.Info("Libvirt monitoring enabled")
	return &libvirtManager{prevCpu: make(map[string]vmPrevEntry)}
}

func (m *libvirtManager) getVMStats() []*libvirt.Stats {
	if m == nil {
		return nil
	}

	m.Lock()
	defer m.Unlock()

	domains := discoverDomains()
	if len(domains) == 0 {
		return nil
	}

	nowMs := time.Now().UnixMilli()
	stats := make([]*libvirt.Stats, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))

	for _, domain := range domains {
		seen[domain.name] = struct{}{}

		vm := &libvirt.Stats{
			Name:   domain.name,
			Id:     domain.id,
			Status: libvirt.StatusFromState(domain.state),
			Health: libvirt.HealthFromState(domain.state),
			Vcpus:  domain.vcpus,
			MemMax: domain.memMax,
		}

		if domain.scopePath != "" {
			memBytes := readCgroupMemoryBytes(domain.scopePath)
			cpuUsage := readCgroupCPUUsec(domain.scopePath)
			if cpuUsage > 0 {
				if prev, ok := m.prevCpu[domain.name]; ok && cpuUsage >= prev.cpuUsage {
					delta := cpuUsage - prev.cpuUsage
					elapsedSec := float64(nowMs-prev.tsMs) / 1000.0
					if delta > 0 && elapsedSec > 0.5 {
						vm.Cpu = (float64(delta) / 1e6 / elapsedSec) * 100
					}
				}
				m.prevCpu[domain.name] = vmPrevEntry{cpuUsage: cpuUsage, tsMs: nowMs}
			}
			if memBytes > 0 {
				vm.Mem = utils.BytesToMegabytes(float64(memBytes))
			}
			readBytes, writeBytes := readCgroupDiskBytes(domain.scopePath)
			vm.Disk = [2]uint64{readBytes, writeBytes}
		}

		if len(domain.ifaces) > 0 {
			rx, tx := readInterfaceByteTotals(domain.ifaces)
			vm.Bandwidth = [2]uint64{tx, rx}
		}

		vm.DiskSum = vm.Disk[0] + vm.Disk[1]
		stats = append(stats, vm)
	}

	for name := range m.prevCpu {
		if _, ok := seen[name]; !ok {
			delete(m.prevCpu, name)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Cpu != stats[j].Cpu {
			return stats[i].Cpu > stats[j].Cpu
		}
		return stats[i].Mem > stats[j].Mem
	})

	return stats
}
