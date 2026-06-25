//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reInterfaceBlock  = regexp.MustCompile(`(?s)<interface[^>]*>.*?</interface>`)
	reIfaceTargetDev  = regexp.MustCompile(`<target[^>]*\bdev=['"]([^'"]+)['"]`)
	reIfaceSourceDev  = regexp.MustCompile(`<source[^>]*\bdev=['"]([^'"]+)['"]`)
	reDiskLikeHostDev = regexp.MustCompile(`^(hd[a-z]|sd[a-z]|vd[a-z]|xvd[a-z]|fd[0-9]+)$`)
)

// parseDomainInterfaces returns host netdev names from libvirt <interface> blocks only.
// Uses <target dev='vnetN'/> for bridge/network taps and <source dev='vx-...'/> for direct/macvtap.
func parseDomainInterfaces(xml string) []string {
	seen := make(map[string]struct{})
	var ifaces []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if !isNetworkHostDev(name) {
			return
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			ifaces = append(ifaces, name)
		}
	}

	for _, block := range reInterfaceBlock.FindAllString(xml, -1) {
		if !isNetworkInterfaceBlock(block) {
			continue
		}
		for _, m := range reIfaceTargetDev.FindAllStringSubmatch(block, -1) {
			if len(m) >= 2 {
				add(m[1])
			}
		}
		for _, m := range reIfaceSourceDev.FindAllStringSubmatch(block, -1) {
			if len(m) >= 2 {
				add(m[1])
			}
		}
	}

	return ifaces
}

func isNetworkInterfaceBlock(block string) bool {
	if strings.Contains(block, "<disk") {
		return false
	}
	// bridge / network / direct host interfaces
	if strings.Contains(block, "<model type=") {
		return true
	}
	if strings.Contains(block, "<source bridge=") || strings.Contains(block, `<source bridge="`) {
		return true
	}
	if strings.Contains(block, "<source network=") || strings.Contains(block, `<source network="`) {
		return true
	}
	if strings.Contains(block, "<source dev=") || strings.Contains(block, `<source dev="`) {
		return true
	}
	return strings.Contains(block, "type='network'") ||
		strings.Contains(block, `type="network"`) ||
		strings.Contains(block, "type='bridge'") ||
		strings.Contains(block, `type="bridge"`) ||
		strings.Contains(block, "type='direct'") ||
		strings.Contains(block, `type="direct"`)
}

func isNetworkHostDev(name string) bool {
	if name == "" || name == "lo" {
		return false
	}
	if reDiskLikeHostDev.MatchString(name) {
		return false
	}
	return strings.HasPrefix(name, "vnet") ||
		strings.HasPrefix(name, "vx-") ||
		strings.HasPrefix(name, "vx") ||
		strings.HasPrefix(name, "macvtap") ||
		strings.HasPrefix(name, "tap") ||
		strings.HasPrefix(name, "veth")
}

func readDomainXML(domainName string) string {
	if xml := readDomainLiveXML(domainName); xml != "" {
		return xml
	}
	return readDomainXMLFromDir("/etc/libvirt/qemu", domainName)
}

// readDomainLiveXML pairs pid/xml files (e.g. 2096_wpserver.pid + 2096_wpserver.xml).
func readDomainLiveXML(domainName string) string {
	runDir := "/run/libvirt/qemu"
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}
		if !pidFileMatchesDomain(entry.Name(), domainName) {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".pid")
		xmlPath := filepath.Join(runDir, base+".xml")
		data, err := os.ReadFile(xmlPath)
		if err == nil {
			return string(data)
		}
	}

	return readDomainXMLFromDir(runDir, domainName)
}

func readDomainXMLFromDir(dir, domainName string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		if !domainXMLFileMatches(entry.Name(), domainName) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		return string(data)
	}
	return ""
}

func domainXMLFileMatches(fileName, domainName string) bool {
	if domainNameFromRunFile(fileName, ".xml") == domainName {
		return true
	}
	if strings.TrimSuffix(fileName, ".xml") == domainName {
		return true
	}
	return strings.Contains(fileName, domainName)
}

func finalizeDomainIfaces(domainName string, fromXML []string) []string {
	merged := append([]string{}, fromXML...)
	if xml := readDomainXML(domainName); xml != "" {
		merged = append(merged, parseDomainInterfaces(xml)...)
	}
	return filterHostNetworkIfaces(dedupeStrings(merged))
}

func filterHostNetworkIfaces(ifaces []string) []string {
	if len(ifaces) == 0 {
		return ifaces
	}
	out := make([]string, 0, len(ifaces))
	for _, dev := range ifaces {
		if !isNetworkHostDev(dev) {
			continue
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", dev)); err != nil {
			continue
		}
		out = append(out, dev)
	}
	return out
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func mergeStringLists(a, b []string) []string {
	return dedupeStrings(append(append([]string{}, a...), b...))
}

func pidFileMatchesDomain(pidFile, domainName string) bool {
	if domainNameFromRunFile(pidFile, ".pid") == domainName {
		return true
	}
	base := strings.TrimSuffix(pidFile, ".pid")
	if base == domainName {
		return true
	}
	return strings.HasSuffix(base, domainName) || strings.Contains(base, domainName)
}
