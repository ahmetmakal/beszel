//go:build !linux

package agent

import "github.com/henrygd/beszel/internal/entities/packages"

// packageManager is a no-op on non-Linux platforms.
type packageManager struct{}

func newPackageManager() *packageManager { return nil }

func (pm *packageManager) startWorker(_ func() []string, _ func()) {}

func (pm *packageManager) getVersions() []*packages.PackageInfo { return nil }
