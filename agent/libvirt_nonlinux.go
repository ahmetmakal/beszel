//go:build !linux

package agent

import "github.com/henrygd/beszel/internal/entities/libvirt"

type libvirtManager struct{}

func newLibvirtManager() *libvirtManager {
	return nil
}

func (m *libvirtManager) getVMStats() []*libvirt.Stats {
	return nil
}
