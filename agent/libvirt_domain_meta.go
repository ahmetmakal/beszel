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
	reFilterIP      = regexp.MustCompile(`<parameter[^>]*name=['"]IP['"][^>]*value=['"]([^'"]+)['"]`)
	reSourceBridge  = regexp.MustCompile(`<source[^>]*bridge=['"]([^'"]+)['"]`)
	reDiskSourceFile = regexp.MustCompile(`<disk[^>]*>[\s\S]*?<source[^>]*file=['"]([^'"]+)['"]`)
	reDomstatusPID  = regexp.MustCompile(`<domstatus[^>]*pid=['"](\d+)['"]`)
	reCgroupNamePrefix = regexp.MustCompile(`^(\d+)[-_]?(.+)$`)
)

func canonicalDomainName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	if m := reCgroupNamePrefix.FindStringSubmatch(name); len(m) == 3 {
		return m[2]
	}
	return domainNameFromRunFile(name+".xml", ".xml")
}

func domainMergeKey(meta *domainMeta) string {
	if meta.uuid != "" {
		return "uuid:" + meta.uuid
	}
	return "name:" + canonicalDomainName(meta.name)
}

func mergeDomainMeta(dst, src *domainMeta) {
	if src.state > 0 && (dst.state == 0 || src.state == 1) {
		dst.state = src.state
	}
	if src.memScopePath != "" {
		dst.memScopePath = src.memScopePath
	}
	if src.cpuScopePath != "" {
		dst.cpuScopePath = src.cpuScopePath
	}
	if src.diskScopePath != "" {
		dst.diskScopePath = src.diskScopePath
	}
	if src.uuid != "" {
		dst.uuid = src.uuid
		dst.id = src.id
	}
	if src.vcpus > 0 {
		dst.vcpus = src.vcpus
	}
	if src.memMax > 0 {
		dst.memMax = src.memMax
	}
	if src.ip != "" {
		dst.ip = src.ip
	}
	if src.bridge != "" {
		dst.bridge = src.bridge
	}
	if src.diskCapBytes > 0 {
		dst.diskCapBytes = src.diskCapBytes
	}
	if src.qemuPid > 0 {
		dst.qemuPid = src.qemuPid
	}
	if len(src.ifaces) > 0 {
		dst.ifaces = mergeStringLists(dst.ifaces, src.ifaces)
	}
	if src.name != "" {
		if dst.name == "" || len(src.name) < len(dst.name) || strings.Contains(dst.name, canonicalDomainName(src.name)) {
			if canonicalDomainName(dst.name) == canonicalDomainName(src.name) && !strings.ContainsAny(src.name, "_-") {
				dst.name = src.name
			} else if dst.name == "" {
				dst.name = src.name
			}
		}
	}
	if dst.name == "" || (src.uuid != "" && canonicalDomainName(dst.name) != canonicalDomainName(src.name)) {
		canon := canonicalDomainName(src.name)
		if canon != "" {
			dst.name = canon
		}
	}
}

func enrichDomainFromXML(meta *domainMeta, xml string) {
	if xml == "" {
		return
	}
	parsed := parseDomainXML(xml)
	if parsed.uuid != "" && meta.uuid == "" {
		meta.uuid = parsed.uuid
		meta.id = parsed.id
	}
	if parsed.vcpus > 0 && meta.vcpus == 0 {
		meta.vcpus = parsed.vcpus
	}
	if parsed.memMax > 0 && meta.memMax == 0 {
		meta.memMax = parsed.memMax
	}
	if parsed.ip != "" {
		meta.ip = parsed.ip
	}
	if parsed.bridge != "" {
		meta.bridge = parsed.bridge
	}
	if parsed.diskCapBytes > 0 {
		meta.diskCapBytes = parsed.diskCapBytes
	}
	if parsed.qemuPid > 0 {
		meta.qemuPid = parsed.qemuPid
	}
	if parsed.name != "" {
		meta.name = parsed.name
	}
	if len(parsed.ifaces) > 0 {
		meta.ifaces = mergeStringLists(meta.ifaces, parsed.ifaces)
	}
}

func parseDomainDetails(xml string) (ip, bridge, diskPath string, diskCapBytes uint64, qemuPid uint64) {
	if m := reFilterIP.FindStringSubmatch(xml); len(m) == 2 {
		ip = strings.TrimSpace(m[1])
	}
	if m := reSourceBridge.FindStringSubmatch(xml); len(m) == 2 {
		bridge = strings.TrimSpace(m[1])
	}
	if m := reDiskSourceFile.FindStringSubmatch(xml); len(m) == 2 {
		diskPath = strings.TrimSpace(m[1])
		if st, err := os.Stat(diskPath); err == nil && !st.IsDir() {
			diskCapBytes = uint64(st.Size())
		}
	}
	if m := reDomstatusPID.FindStringSubmatch(xml); len(m) == 2 {
		qemuPid, _ = strconv.ParseUint(m[1], 10, 64)
	}
	if qemuPid == 0 {
		qemuPid = readDomainPidFile(canonicalDomainName(parseDomainNameOnly(xml)))
	}
	return ip, bridge, diskPath, diskCapBytes, qemuPid
}

func parseDomainNameOnly(xml string) string {
	if m := reDomainName.FindStringSubmatch(xml); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func readDomainPidFile(domainName string) uint64 {
	if domainName == "" {
		return 0
	}
	runDir := "/run/libvirt/qemu"
	for _, base := range []string{domainName, canonicalDomainName(domainName)} {
		data, err := os.ReadFile(filepath.Join(runDir, base+".pid"))
		if err != nil {
			continue
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			return pid
		}
	}
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pid") || !pidFileMatchesDomain(entry.Name(), domainName) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(runDir, entry.Name()))
		if err != nil {
			continue
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			return pid
		}
	}
	return 0
}

func vmUptimeSec(qemuPid uint64) uint64 {
	if qemuPid == 0 {
		return 0
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(qemuPid, 10), "stat"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return 0
	}
	startTicks, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0
	}
	uptimeSec, err := readHostUptimeSec()
	if err != nil {
		return 0
	}
	const userHz = 100.0
	startSec := float64(startTicks) / userHz
	if uptimeSec <= startSec {
		return 0
	}
	return uint64(uptimeSec - startSec)
}

func readHostUptimeSec() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	field, _, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
	return strconv.ParseFloat(field, 64)
}

func diskScopePathFor(scopeDir string) string {
	if scopeDir == "" {
		return ""
	}
	for _, root := range []string{
		"/sys/fs/cgroup/blkio/machine.slice",
		"/sys/fs/cgroup/unified/machine.slice",
		"/sys/fs/cgroup/system.slice/libvirtd.service/machine.slice",
	} {
		p := filepath.Join(root, scopeDir)
		if cgroupHasDiskMetrics(p) {
			return p
		}
	}
	return ""
}

func cgroupHasDiskMetrics(path string) bool {
	for _, f := range []string{
		"io.stat",
		"blkio.io_service_bytes",
		"blkio.throttle.io_service_bytes",
		"blkio.io_service_bytes_recursive",
	} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}

type cgroupDiskCounters struct {
	readBytes  uint64
	writeBytes uint64
	readOps    uint64
	writeOps   uint64
}

func readCgroupDiskCounters(scopePath string) cgroupDiskCounters {
	if scopePath == "" {
		return cgroupDiskCounters{}
	}
	if c := readCgroupV2DiskCounters(scopePath); c.readBytes > 0 || c.writeBytes > 0 {
		return c
	}
	return readCgroupV1BlkioCounters(scopePath)
}

func readCgroupV2DiskCounters(scopePath string) cgroupDiskCounters {
	data, err := os.ReadFile(filepath.Join(scopePath, "io.stat"))
	if err != nil {
		return cgroupDiskCounters{}
	}
	var out cgroupDiskCounters
	for line := range strings.SplitSeq(string(data), "\n") {
		for _, field := range strings.Fields(strings.TrimSpace(line)) {
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
				out.readBytes += n
			case "wbytes":
				out.writeBytes += n
			case "rios":
				out.readOps += n
			case "wios":
				out.writeOps += n
			}
		}
	}
	return out
}

func readCgroupV1BlkioCounters(scopePath string) cgroupDiskCounters {
	var out cgroupDiskCounters
	for _, name := range []string{
		"blkio.io_service_bytes",
		"blkio.throttle.io_service_bytes",
		"blkio.io_service_bytes_recursive",
		"blkio.throttle.io_service_bytes_recursive",
	} {
		if c := parseBlkioServiceFile(filepath.Join(scopePath, name)); c.readBytes > 0 || c.writeBytes > 0 {
			out.readBytes = c.readBytes
			out.writeBytes = c.writeBytes
			break
		}
	}
	for _, name := range []string{
		"blkio.io_serviced",
		"blkio.throttle.io_serviced",
		"blkio.io_serviced_recursive",
		"blkio.throttle.io_serviced_recursive",
	} {
		if c := parseBlkioServicedFile(filepath.Join(scopePath, name)); c.readOps > 0 || c.writeOps > 0 {
			out.readOps = c.readOps
			out.writeOps = c.writeOps
			break
		}
	}
	return out
}

func parseBlkioServiceFile(path string) cgroupDiskCounters {
	data, err := os.ReadFile(path)
	if err != nil {
		return cgroupDiskCounters{}
	}
	return parseBlkioServiceFileContent(string(data))
}

func parseBlkioServiceFileContent(content string) cgroupDiskCounters {
	type devRW struct{ read, write uint64 }
	byDev := make(map[string]devRW)
	for line := range strings.SplitSeq(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "Read":
			entry := byDev[fields[0]]
			entry.read = parseUint(fields[2])
			byDev[fields[0]] = entry
		case "Write":
			entry := byDev[fields[0]]
			entry.write = parseUint(fields[2])
			byDev[fields[0]] = entry
		}
	}
	var out cgroupDiskCounters
	for _, v := range byDev {
		out.readBytes += v.read
		out.writeBytes += v.write
	}
	if len(byDev) > 1 {
		out.readBytes /= uint64(len(byDev))
		out.writeBytes /= uint64(len(byDev))
	}
	return out
}

func parseBlkioServicedFile(path string) cgroupDiskCounters {
	data, err := os.ReadFile(path)
	if err != nil {
		return cgroupDiskCounters{}
	}
	return parseBlkioServicedFileContent(string(data))
}

func parseBlkioServicedFileContent(content string) cgroupDiskCounters {
	type devRW struct{ read, write uint64 }
	byDev := make(map[string]devRW)
	for line := range strings.SplitSeq(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "Read":
			entry := byDev[fields[0]]
			entry.read = parseUint(fields[2])
			byDev[fields[0]] = entry
		case "Write":
			entry := byDev[fields[0]]
			entry.write = parseUint(fields[2])
			byDev[fields[0]] = entry
		}
	}
	var out cgroupDiskCounters
	for _, v := range byDev {
		out.readOps += v.read
		out.writeOps += v.write
	}
	if len(byDev) > 1 {
		out.readOps /= uint64(len(byDev))
		out.writeOps /= uint64(len(byDev))
	}
	return out
}

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// kept for callers/tests; returns cumulative totals
func readCgroupDiskBytes(scopePath string) (read, write uint64) {
	c := readCgroupDiskCounters(scopePath)
	return c.readBytes, c.writeBytes
}
