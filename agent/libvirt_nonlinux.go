//go:build !linux

package agent

import "github.com/henrygd/beszel/internal/entities/system"

type libvirtManager struct{}

func newLibvirtManager() *libvirtManager {
	return nil
}

func (m *libvirtManager) getTopVMs(limit int) []system.TopProcess {
	return nil
}
