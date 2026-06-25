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
	reDomainName      = regexp.MustCompile(`<name[^>]*>([^<]+)</name>`)
	reDomainUUID        = regexp.MustCompile(`<uuid[^>]*>([^<]+)</uuid>`)
	reDomainMemory      = regexp.MustCompile(`<memory[^>]*>([0-9]+)</memory>`)
	reDomainVcpu        = regexp.MustCompile(`<vcpu[^>]*>([0-9]+)</vcpu>`)
	reDomainVcpuCurrent = regexp.MustCompile(`<vcpu[^>]*current=['"]?(\d+)['"]?`)
	machineQemuScopeRe  = regexp.MustCompile(`^machine-qemu-\d+-(.+)\.scope$`)
	rePidPrefix         = regexp.MustCompile(`^\d+$`)
)

type domainMeta struct {
	name          string
	uuid          string
	id            string
	state         int
	memScopePath  string
	cpuScopePath  string
	diskScopePath string
	vcpus         uint16
	memMax        uint64
	ifaces        []string
	ip            string
	bridge        string
	diskCapBytes  uint64
	qemuPid       uint64
}

func discoverDomains() []domainMeta {
	byKey := make(map[string]*domainMeta)
	add := func(meta domainMeta) {
		if meta.name == "" && meta.uuid == "" {
			return
		}
		if meta.name != "" {
			meta.name = canonicalDomainName(meta.name)
			if meta.name == "" {
				return
			}
		}
		key := domainMergeKey(&meta)
		if existing, ok := byKey[key]; ok {
			mergeDomainMeta(existing, &meta)
			return
		}
		// also merge aliases with same canonical name when uuid missing
		if meta.uuid == "" {
			for _, existing := range byKey {
				if canonicalDomainName(existing.name) == meta.name {
					mergeDomainMeta(existing, &meta)
					return
				}
			}
		}
		copy := meta
		byKey[key] = &copy
	}

	for _, meta := range discoverDefinedDomains() {
		add(*meta)
	}
	for _, meta := range discoverRunDirDomains() {
		add(*meta)
	}
	for _, active := range discoverActiveDomains() {
		add(active)
	}

	applyRunDirStateByKey(byKey)

	result := make([]domainMeta, 0, len(byKey))
	for _, meta := range byKey {
		if meta.id == "" && meta.uuid != "" {
			meta.id = vmIDFromUUID(meta.uuid)
		}
		if meta.id == "" {
			meta.id = vmIDFromName(meta.name)
		}
		if meta.state == 0 {
			meta.state = 5
		}
		if xml := readDomainXML(meta.name); xml != "" {
			enrichDomainFromXML(meta, xml)
		}
		if meta.diskScopePath == "" && meta.memScopePath != "" {
			meta.diskScopePath = diskScopePathFor(filepath.Base(meta.memScopePath))
		}
		meta.ifaces = finalizeDomainIfaces(meta.name, meta.ifaces)
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
		if meta.name == "" {
			meta.name = name
		}
		if meta.uuid != "" {
			meta.id = vmIDFromUUID(meta.uuid)
		}
		result[meta.name] = &meta
	}
	return result
}

func discoverActiveDomains() []domainMeta {
	scopeDirs := collectMachineQemuScopeDirs()
	result := make([]domainMeta, 0, len(scopeDirs))
	for scopeDir, paths := range scopeDirs {
		name := guestNameFromScope(scopeDir)
		if name == "" {
			continue
		}
		meta := domainMeta{
			name:          name,
			state:         1,
			memScopePath:  paths.mem,
			cpuScopePath:  paths.cpu,
			diskScopePath: paths.disk,
		}
		if live := readLiveDomainXML(name); live != nil {
			meta.uuid = live.uuid
			meta.id = live.id
			meta.vcpus = live.vcpus
			meta.memMax = live.memMax
			meta.ifaces = live.ifaces
			if live.name != "" {
				meta.name = live.name
			}
		}
		result = append(result, meta)
	}
	return result
}

type scopePaths struct {
	mem  string
	cpu  string
	disk string
}

func collectMachineQemuScopeDirs() map[string]scopePaths {
	found := make(map[string]scopePaths)
	for _, root := range findMachineSliceRoots() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "machine-qemu") {
				continue
			}
			scopeDir := entry.Name()
			full := filepath.Join(root, entry.Name())
			paths := found[scopeDir]
			if cgroupHasMemoryMetrics(full) {
				paths.mem = full
			}
			if cgroupHasCPUMetrics(full) {
				paths.cpu = full
			}
			found[scopeDir] = paths
		}
	}
	for scopeDir, paths := range found {
		if paths.disk == "" {
			paths.disk = diskScopePathFor(scopeDir)
			found[scopeDir] = paths
		}
	}
	return found
}

func cgroupHasMemoryMetrics(path string) bool {
	for _, f := range []string{"memory.current", "memory.usage_in_bytes"} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}

func cgroupHasCPUMetrics(path string) bool {
	for _, f := range []string{"cpu.stat", "cpuacct.usage"} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}

func discoverRunDirDomains() map[string]*domainMeta {
	result := make(map[string]*domainMeta)
	entries, err := os.ReadDir("/run/libvirt/qemu")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".xml") {
			domainName := domainNameFromRunFile(name, ".xml")
			if domainName == "" {
				continue
			}
			data, err := os.ReadFile(filepath.Join("/run/libvirt/qemu", name))
			if err != nil {
				if _, ok := result[domainName]; !ok {
					meta := domainMeta{name: domainName, state: 1, id: vmIDFromName(domainName)}
					result[domainName] = &meta
				}
				continue
			}
			meta := parseDomainXML(string(data))
			if meta.name == "" {
				meta.name = domainNameFromRunFile(name, ".xml")
			}
			if meta.state == 0 {
				meta.state = 1
			}
			if meta.id == "" {
				meta.id = vmIDFromName(meta.name)
			}
			result[meta.name] = &meta
			continue
		}
		if strings.HasSuffix(name, ".status") {
			domainName := domainNameFromRunFile(name, ".status")
			if domainName == "" {
				continue
			}
			meta, ok := result[domainName]
			if !ok {
				meta = &domainMeta{name: domainName, id: vmIDFromName(domainName)}
				result[domainName] = meta
			}
			data, err := os.ReadFile(filepath.Join("/run/libvirt/qemu", name))
			if err != nil {
				continue
			}
			if state := parseStatusFileState(string(data)); state > 0 {
				meta.state = state
			}
		}
	}
	return result
}

func domainNameFromRunFile(name, suffix string) string {
	base := strings.TrimSuffix(name, suffix)
	if idx := strings.Index(base, "-"); idx > 0 && rePidPrefix.MatchString(base[:idx]) {
		return base[idx+1:]
	}
	if idx := strings.Index(base, "_"); idx > 0 && rePidPrefix.MatchString(base[:idx]) {
		return base[idx+1:]
	}
	return base
}

func findMachineSliceRoots() []string {
	var roots []string
	seen := make(map[string]struct{})
	add := func(p string) {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			if _, ok := seen[p]; !ok {
				roots = append(roots, p)
				seen[p] = struct{}{}
			}
		}
	}
	// cgroup v2 / unified hierarchy
	add("/sys/fs/cgroup/machine.slice")
	add("/sys/fs/cgroup/system.slice/libvirtd.service/machine.slice")
	add("/sys/fs/cgroup/system.slice/virtqemud.service/machine.slice")
	// cgroup v1 split controllers (common on Ubuntu 20.04)
	for _, ctrl := range []string{"memory", "cpu,cpuacct", "cpuacct", "cpu", "unified"} {
		base := filepath.Join("/sys/fs/cgroup", ctrl)
		add(filepath.Join(base, "machine.slice"))
		add(filepath.Join(base, "system.slice", "libvirtd.service", "machine.slice"))
		add(filepath.Join(base, "system.slice", "virtqemud.service", "machine.slice"))
	}
	return roots
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

func applyRunDirStateByKey(byKey map[string]*domainMeta) {
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
		name := domainNameFromRunFile(entry.Name(), ".status")
		for _, meta := range byKey {
			if canonicalDomainName(meta.name) == canonicalDomainName(name) && state > 0 {
				meta.state = state
			}
		}
	}
}

func parseDomainXML(xml string) domainMeta {
	var meta domainMeta
	if m := reDomainName.FindStringSubmatch(xml); len(m) == 2 {
		meta.name = strings.TrimSpace(m[1])
	}
	if m := reDomainUUID.FindStringSubmatch(xml); len(m) == 2 {
		meta.uuid = strings.TrimSpace(m[1])
		meta.id = vmIDFromUUID(meta.uuid)
	}
	if m := reDomainVcpu.FindStringSubmatch(xml); len(m) == 2 {
		if v, err := strconv.ParseUint(m[1], 10, 16); err == nil {
			meta.vcpus = uint16(v)
		}
	} else if m := reDomainVcpuCurrent.FindStringSubmatch(xml); len(m) == 2 {
		if v, err := strconv.ParseUint(m[1], 10, 16); err == nil {
			meta.vcpus = uint16(v)
		}
	}
	meta.memMax = parseDomainMemoryBytes(xml)
	meta.ifaces = parseDomainInterfaces(xml)
	meta.ip, meta.bridge, _, meta.diskCapBytes, meta.qemuPid = parseDomainDetails(xml)
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
	id := strconv.FormatUint(sum, 16)
	if len(id) > 12 {
		return id[:12]
	}
	return strings.Repeat("0", 12-len(id)) + id
}
