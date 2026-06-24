//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reDomainUUID        = regexp.MustCompile(`<uuid[^>]*>([^<]+)</uuid>`)
	reDomainMemory      = regexp.MustCompile(`<memory[^>]*>([0-9]+)</memory>`)
	reDomainVcpu        = regexp.MustCompile(`<vcpu[^>]*>([0-9]+)</vcpu>`)
	reTargetDev         = regexp.MustCompile(`<target dev='([^']+)'`)
	machineQemuScopeRe  = regexp.MustCompile(`^machine-qemu-\d+-(.+)\.scope$`)
)

type domainMeta struct {
	name      string
	uuid      string
	id        string
	state     int
	scopePath string
	vcpus     uint16
	memMax    uint64
	ifaces    []string
}

func discoverDomains() []domainMeta {
	byName := make(map[string]*domainMeta)

	for name, meta := range discoverDefinedDomains() {
		byName[name] = meta
	}

	for _, active := range discoverActiveDomains() {
		if existing, ok := byName[active.name]; ok {
			existing.state = active.state
			existing.scopePath = active.scopePath
			if len(active.ifaces) > 0 {
				existing.ifaces = active.ifaces
			}
		} else {
			copy := active
			byName[active.name] = &copy
		}
	}

	applyRunDirState(byName)

	result := make([]domainMeta, 0, len(byName))
	for _, meta := range byName {
		if meta.id == "" && meta.uuid != "" {
			meta.id = vmIDFromUUID(meta.uuid)
		}
		if meta.id == "" {
			meta.id = vmIDFromName(meta.name)
		}
		if meta.state == 0 {
			meta.state = 5
		}
		result = append(result, *meta)
	}
	return result
}

func discoverDefinedDomains() map[string]*domainMeta {
	result := make(map[string]*domainMeta)
	entries, err := os.ReadDir("/etc/libvirt/qemu")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".xml")
		data, err := os.ReadFile(filepath.Join("/etc/libvirt/qemu", entry.Name()))
		if err != nil {
			continue
		}
		meta := parseDomainXML(string(data))
		meta.name = name
		if meta.uuid != "" {
			meta.id = vmIDFromUUID(meta.uuid)
		}
		result[name] = &meta
	}
	return result
}

func discoverActiveDomains() []domainMeta {
	var result []domainMeta
	for _, slicePath := range findMachineSlicePaths() {
		entries, err := os.ReadDir(slicePath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "machine-qemu") {
				continue
			}
			name := guestNameFromScope(entry.Name())
			if name == "" {
				continue
			}
			meta := domainMeta{
				name:      name,
				state:     1,
				scopePath: filepath.Join(slicePath, entry.Name()),
			}
			if live := readLiveDomainXML(name); live != nil {
				meta.uuid = live.uuid
				meta.id = live.id
				meta.vcpus = live.vcpus
				meta.memMax = live.memMax
				meta.ifaces = live.ifaces
			}
			result = append(result, meta)
		}
	}
	return result
}

func findMachineSlicePaths() []string {
	candidates := []string{
		"/sys/fs/cgroup/machine.slice",
		"/sys/fs/cgroup/system.slice/libvirtd.service/machine.slice",
	}
	var paths []string
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			paths = append(paths, p)
		}
	}
	return paths
}

func guestNameFromScope(scopeName string) string {
	decoded := strings.ReplaceAll(scopeName, `\x2d`, "-")
	decoded = strings.ReplaceAll(decoded, `\x5f`, "_")
	matches := machineQemuScopeRe.FindStringSubmatch(decoded)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

func readLiveDomainXML(name string) *domainMeta {
	entries, err := os.ReadDir("/run/libvirt/qemu")
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".xml") || !strings.Contains(entry.Name(), name) {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/run/libvirt/qemu", entry.Name()))
		if err != nil {
			continue
		}
		meta := parseDomainXML(string(data))
		meta.name = name
		if meta.uuid != "" {
			meta.id = vmIDFromUUID(meta.uuid)
		}
		return &meta
	}
	return nil
}

func applyRunDirState(byName map[string]*domainMeta) {
	entries, err := os.ReadDir("/run/libvirt/qemu")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".status") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/run/libvirt/qemu", entry.Name()))
		if err != nil {
			continue
		}
		state := parseStatusFileState(string(data))
		base := strings.TrimSuffix(entry.Name(), ".status")
		name := base
		if idx := strings.Index(base, "-"); idx > 0 {
			name = base[idx+1:]
		}
		if meta, ok := byName[name]; ok && state > 0 {
			meta.state = state
		}
	}
}

func parseDomainXML(xml string) domainMeta {
	var meta domainMeta
	if m := reDomainUUID.FindStringSubmatch(xml); len(m) == 2 {
		meta.uuid = strings.TrimSpace(m[1])
		meta.id = vmIDFromUUID(meta.uuid)
	}
	if m := reDomainVcpu.FindStringSubmatch(xml); len(m) == 2 {
		if v, err := strconv.ParseUint(m[1], 10, 16); err == nil {
			meta.vcpus = uint16(v)
		}
	}
	meta.memMax = parseDomainMemoryBytes(xml)
	for _, m := range reTargetDev.FindAllStringSubmatch(xml, -1) {
		if len(m) == 2 && m[1] != "" {
			meta.ifaces = append(meta.ifaces, m[1])
		}
	}
	return meta
}

func parseDomainMemoryBytes(xml string) uint64 {
	m := reDomainMemory.FindStringSubmatch(xml)
	if len(m) != 2 {
		return 0
	}
	val, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0
	}
	if strings.Contains(xml, "unit='KiB'") || strings.Contains(xml, `unit="KiB"`) {
		return val * 1024
	}
	if strings.Contains(xml, "unit='MiB'") || strings.Contains(xml, `unit="MiB"`) {
		return val * 1024 * 1024
	}
	return val
}

func parseStatusFileState(content string) int {
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "state.state=") {
			val, err := strconv.Atoi(strings.TrimPrefix(line, "state.state="))
			if err == nil {
				return val
			}
		}
	}
	return 0
}

func readCgroupMemoryBytes(scopePath string) uint64 {
	for _, rel := range []string{"memory.current", "memory.usage_in_bytes"} {
		data, err := os.ReadFile(filepath.Join(scopePath, rel))
		if err != nil {
			continue
		}
		val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil && val > 0 {
			return val
		}
	}
	return 0
}

func readCgroupCPUUsec(scopePath string) uint64 {
	data, err := os.ReadFile(filepath.Join(scopePath, "cpu.stat"))
	if err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			key, val, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok || key != "usage_usec" {
				continue
			}
			usec, err := strconv.ParseUint(val, 10, 64)
			if err == nil {
				return usec
			}
		}
	}
	data, err = os.ReadFile(filepath.Join(scopePath, "cpuacct.usage"))
	if err != nil {
		return 0
	}
	nsec, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return nsec / 1000
}

func readInterfaceByteTotals(devices []string) (rx, tx uint64) {
	for _, dev := range devices {
		rx += readNetStat(dev, "rx_bytes")
		tx += readNetStat(dev, "tx_bytes")
	}
	return rx, tx
}

func readNetStat(dev, stat string) uint64 {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", stat))
	if err != nil {
		return 0
	}
	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return val
}

func readCgroupDiskBytes(scopePath string) (read, write uint64) {
	data, err := os.ReadFile(filepath.Join(scopePath, "io.stat"))
	if err != nil {
		return 0, 0
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, field := range strings.Fields(line) {
			key, val, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				read += n
			case "wbytes":
				write += n
			}
		}
	}
	return read, write
}

func vmIDFromUUID(uuid string) string {
	id := strings.ReplaceAll(uuid, "-", "")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func vmIDFromName(name string) string {
	sum := uint64(0)
	for i := 0; i < len(name); i++ {
		sum = sum*31 + uint64(name[i])
	}
	return strconv.FormatUint(sum, 16)
}
