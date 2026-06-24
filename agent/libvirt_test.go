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

func TestParseDomainMemoryBytes(t *testing.T) {
	xml := `<domain><memory unit='KiB'>1048576</memory></domain>`
	assert.Equal(t, uint64(1048576*1024), parseDomainMemoryBytes(xml))
}
