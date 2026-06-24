//go:build linux

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVirshListNames(t *testing.T) {
	output := "vm-one\n\nvm-two\n"
	assert.Equal(t, []string{"vm-one", "vm-two"}, parseVirshListNames(output))
	assert.Empty(t, parseVirshListNames(""))
}

func TestParseDomstatsOutput(t *testing.T) {
	output := `Domain: 'web-server'
  cpu.time=144940157444
  cpu.user=65260000000
  cpu.system=14450000000
  balloon.current=4194304
  balloon.rss=3735552
Domain: 'db-server'
  cpu.time=9876543210
  cpu.user=4000000000
  cpu.system=1000000000
  balloon.current=8388608
  balloon.rss=7340032
`

	stats := parseDomstatsOutput(output)
	assert.Len(t, stats, 2)

	web := stats["web-server"]
	assert.Equal(t, uint64(144940157444), web.cpuTimeNs)
	assert.Equal(t, uint64(3735552*1024), web.rssBytes)

	db := stats["db-server"]
	assert.Equal(t, uint64(9876543210), db.cpuTimeNs)
	assert.Equal(t, uint64(7340032*1024), db.rssBytes)
}

func TestParseDomstatsDomainName(t *testing.T) {
	assert.Equal(t, "vm1", parseDomstatsDomainName("Domain: 'vm1'"))
}
