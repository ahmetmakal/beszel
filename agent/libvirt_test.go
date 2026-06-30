//go:build linux

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGuestNameFromScope(t *testing.T) {
	assert.Equal(t, "web-server", guestNameFromScope(`machine-qemu\x2d1\x2dweb\x2dserver.scope`))
	assert.Equal(t, "db01", guestNameFromScope("machine-qemu-2-db01.scope"))
}

func TestDomainNameFromRunFile(t *testing.T) {
	assert.Equal(t, "web-server", domainNameFromRunFile("12345-web-server.xml", ".xml"))
	assert.Equal(t, "db01", domainNameFromRunFile("99-db01.status", ".status"))
	assert.Equal(t, "wpserver", domainNameFromRunFile("2096_wpserver.xml", ".xml"))
	assert.Equal(t, "tittextile", domainNameFromRunFile("6883_tittextile.xml", ".xml"))
	assert.Equal(t, "server13659", domainNameFromRunFile("server13659.xml", ".xml"))
}

func TestParseDomainInterfaces(t *testing.T) {
	bridgeBr0 := `<interface type='bridge'>
        <mac address='52:54:00:07:7a:6e'/>
        <source bridge='br0'/>
        <target dev='vnet1'/>
      </interface>`
	assert.Equal(t, []string{"vnet1"}, parseDomainInterfaces(bridgeBr0))

	bridgeVbr := `<interface type='bridge'>
        <mac address='52:54:00:9e:e4:45'/>
        <source bridge='vbr-151'/>
        <target dev='vnet63'/>
      </interface>`
	assert.Equal(t, []string{"vnet63"}, parseDomainInterfaces(bridgeVbr))

	directVx := `<interface type='direct'><source dev='vx-1148' mode='bridge'/></interface>`
	assert.Equal(t, []string{"vx-1148"}, parseDomainInterfaces(directVx))

	combined := bridgeBr0 + bridgeVbr
	assert.Equal(t, []string{"vnet1", "vnet63"}, parseDomainInterfaces(combined))

	withDisk := `<disk type='block'><target dev='hda' bus='ide'/></disk>` + bridgeBr0
	assert.Equal(t, []string{"vnet1"}, parseDomainInterfaces(withDisk))

	// libvirt runtime domstatus wrapper (e.g. /run/libvirt/qemu/server7581.xml)
	domstatus := `<domstatus state='running' pid='3955246'>
  <domain type='kvm'>
    <name>server7581</name>
    <devices>
      <disk type='file' device='disk'><target dev='sda' bus='sata'/></disk>
      <interface type='bridge'>
        <source bridge='br0'/>
        <target dev='vnet4'/>
        <model type='e1000'/>
      </interface>
    </devices>
  </domain>
</domstatus>`
	assert.Equal(t, []string{"vnet4"}, parseDomainInterfaces(domstatus))
	assert.Equal(t, "server7581", parseDomainXML(domstatus).name)
}

func TestParseDomainXMLName(t *testing.T) {
	xml := `<domain type='kvm'><name>wpserver</name><uuid>abc</uuid><vcpu>4</vcpu><memory unit='KiB'>4194304</memory></domain>`
	meta := parseDomainXML(xml)
	assert.Equal(t, "wpserver", meta.name)
	assert.Equal(t, uint16(4), meta.vcpus)
}

func TestCanonicalDomainName(t *testing.T) {
	assert.Equal(t, "wpserver", canonicalDomainName("2096_wpserver"))
	assert.Equal(t, "wpserver", canonicalDomainName("2096-wpserver"))
	assert.Equal(t, "wpserver", canonicalDomainName("2096wpserver"))
	assert.Equal(t, "server7581", canonicalDomainName("server7581"))
}

func TestParseBlkioServiceFile(t *testing.T) {
	sample := "8:0 Read 1000\n8:0 Write 2000\n253:0 Read 1000\n253:0 Write 2000\n"
	c := parseBlkioServiceFileContent(sample)
	assert.Equal(t, uint64(1000), c.readBytes)
	assert.Equal(t, uint64(2000), c.writeBytes)
}

func TestVmIDFromName(t *testing.T) {
	id := vmIDFromName("a")
	assert.Len(t, id, 12)
	assert.Regexp(t, `^[a-f0-9]+$`, id)
}

func TestSelectVMMemoryBytes(t *testing.T) {
	const elevenGB = 11719680 * 1024
	const thirtyFourGB = elevenGB * 3

	// Sane per-VM cgroup
	assert.Equal(t, uint64(elevenGB), selectVMMemoryBytes(elevenGB, 0, elevenGB))

	// Inflated cgroup (aggregate/wrong scope) — prefer RSS
	assert.Equal(t, uint64(elevenGB), selectVMMemoryBytes(thirtyFourGB, elevenGB, elevenGB))

	// No cgroup, RSS only (common on cgroup v1 hosts without per-VM memory)
	assert.Equal(t, uint64(elevenGB), selectVMMemoryBytes(0, elevenGB, elevenGB))

	// No memMax: trust cgroup
	assert.Equal(t, uint64(thirtyFourGB), selectVMMemoryBytes(thirtyFourGB, elevenGB, 0))
}
