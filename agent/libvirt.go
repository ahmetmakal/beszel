//go:build linux

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/agent/utils"
	"github.com/henrygd/beszel/internal/entities/libvirt"
)

type vmPrevEntry struct {
	cpuUsage uint64
	tsMs     int64
}

type vmPrevNet struct {
	txBytes uint64
	rxBytes uint64
	tsMs    int64
}

type vmPrevDisk struct {
	readBytes  uint64
	writeBytes uint64
	readOps    uint64
	writeOps   uint64
	tsMs       int64
}

type libvirtManager struct {
	sync.Mutex
	prevCpu map[string]vmPrevEntry
	prevNet map[string]vmPrevNet
	prevDisk map[string]vmPrevDisk
}

func newLibvirtManager() *libvirtManager {
	if !libvirtMonitoringAvailable() {
		slog.Debug("Libvirt unavailable", "reason", "no libvirt socket, runtime dir, or VM cgroups found")
		return nil
	}
	slog.Info("Libvirt monitoring enabled")
	return &libvirtManager{
		prevCpu:  make(map[string]vmPrevEntry),
		prevNet:  make(map[string]vmPrevNet),
		prevDisk: make(map[string]vmPrevDisk),
	}
}

func libvirtMonitoringAvailable() bool {
	for _, p := range []string{"/run/libvirt/libvirt-sock", "/var/run/libvirt/libvirt-sock"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if entries, err := os.ReadDir("/run/libvirt/qemu"); err == nil && len(entries) > 0 {
		return true
	}
	for _, slicePath := range findMachineSliceRoots() {
		entries, err := os.ReadDir(slicePath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "machine-qemu") {
				return true
			}
		}
	}
	return false
}

func (m *libvirtManager) getVMStats() []*libvirt.Stats {
	if m == nil {
		return nil
	}

	m.Lock()
	defer m.Unlock()

	domains := discoverDomains()
	if len(domains) == 0 {
		slog.Debug("Libvirt: no domains discovered")
		return nil
	}

	nowMs := time.Now().UnixMilli()
	stats := make([]*libvirt.Stats, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))

	for _, domain := range domains {
		seen[domain.name] = struct{}{}

		vm := &libvirt.Stats{
			Name:      domain.name,
			Id:        domain.id,
			Status:    libvirt.StatusFromState(domain.state),
			Health:    libvirt.HealthFromState(domain.state),
			Vcpus:     domain.vcpus,
			MemMax:    domain.memMax,
			Ip:        domain.ip,
			Bridge:    domain.bridge,
			DiskCap:   domain.diskCapBytes,
			UptimeSec: vmUptimeSec(domain.qemuPid),
		}

		memPath := domain.memScopePath
		cpuPath := domain.cpuScopePath
		diskPath := domain.diskScopePath
		if memPath == "" {
			memPath = domain.cpuScopePath
		}
		if cpuPath == "" {
			cpuPath = memPath
		}
		if diskPath == "" && memPath != "" {
			diskPath = diskScopePathFor(filepath.Base(memPath))
		}

		if memPath != "" {
			memBytes := readCgroupMemoryBytes(memPath)
			if memBytes > 0 {
				vm.Mem = utils.BytesToMegabytes(float64(memBytes))
				if domain.memMax > 0 {
					vm.MemPct = utils.TwoDecimals(float64(memBytes) / float64(domain.memMax) * 100)
				}
			}
		}

		if cpuPath != "" {
			cpuUsage := readCgroupCPUUsec(cpuPath)
			if cpuUsage > 0 {
				if prev, ok := m.prevCpu[domain.name]; ok && cpuUsage >= prev.cpuUsage {
					delta := cpuUsage - prev.cpuUsage
					elapsedSec := float64(nowMs-prev.tsMs) / 1000.0
					if delta > 0 && elapsedSec > 0.5 {
						cpuPct := (float64(delta) / 1e6 / elapsedSec) * 100
						if domain.vcpus > 0 {
							cpuPct /= float64(domain.vcpus)
						}
						vm.Cpu = cpuPct
					}
				}
				m.prevCpu[domain.name] = vmPrevEntry{cpuUsage: cpuUsage, tsMs: nowMs}
			}
		}

		if diskPath != "" {
			counters := readCgroupDiskCounters(diskPath)
			if prev, ok := m.prevDisk[domain.name]; ok && nowMs > prev.tsMs {
				if counters.readBytes >= prev.readBytes {
					vm.Disk[0] = counters.readBytes - prev.readBytes
				}
				if counters.writeBytes >= prev.writeBytes {
					vm.Disk[1] = counters.writeBytes - prev.writeBytes
				}
				if counters.readOps >= prev.readOps {
					vm.DiskIops[0] = counters.readOps - prev.readOps
				}
				if counters.writeOps >= prev.writeOps {
					vm.DiskIops[1] = counters.writeOps - prev.writeOps
				}
			}
			m.prevDisk[domain.name] = vmPrevDisk{
				readBytes:  counters.readBytes,
				writeBytes: counters.writeBytes,
				readOps:    counters.readOps,
				writeOps:   counters.writeOps,
				tsMs:       nowMs,
			}
		}

		ifaces := finalizeDomainIfaces(domain.name, domain.ifaces)
		if len(ifaces) == 0 && domain.state == 1 {
			slog.Warn("Libvirt: no network interface for running VM (beszel must read /run/libvirt/qemu/*.xml)", "name", domain.name)
		}
		if len(ifaces) > 0 {
			rxTotal, txTotal := readInterfaceByteTotals(ifaces)
			if prev, ok := m.prevNet[domain.name]; ok && nowMs > prev.tsMs {
				if txTotal >= prev.txBytes {
					vm.Bandwidth[0] = txTotal - prev.txBytes
				}
				if rxTotal >= prev.rxBytes {
					vm.Bandwidth[1] = rxTotal - prev.rxBytes
				}
			}
			m.prevNet[domain.name] = vmPrevNet{txBytes: txTotal, rxBytes: rxTotal, tsMs: nowMs}
		}

		vm.DiskSum = vm.Disk[0] + vm.Disk[1]
		vm.NetSum = vm.Bandwidth[0] + vm.Bandwidth[1]
		vm.DiskIopsSum = vm.DiskIops[0] + vm.DiskIops[1]
		stats = append(stats, vm)
	}

	for name := range m.prevCpu {
		if _, ok := seen[name]; !ok {
			delete(m.prevCpu, name)
		}
	}
	for name := range m.prevNet {
		if _, ok := seen[name]; !ok {
			delete(m.prevNet, name)
		}
	}
	for name := range m.prevDisk {
		if _, ok := seen[name]; !ok {
			delete(m.prevDisk, name)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Cpu != stats[j].Cpu {
			return stats[i].Cpu > stats[j].Cpu
		}
		return stats[i].Mem > stats[j].Mem
	})

	if len(stats) > 0 {
		slog.Info("Libvirt VMs collected", "count", len(stats), "names", vmNames(stats))
	}

	return stats
}

func vmNames(stats []*libvirt.Stats) []string {
	names := make([]string, len(stats))
	for i, vm := range stats {
		names[i] = vm.Name
	}
	return names
}
