//go:build linux

package agent

import (
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/henrygd/beszel/internal/entities/packages"
)

// packageManager detects package names and versions for monitored systemd services.
type packageManager struct {
	sync.Mutex
	pkgType  string              // "dpkg" or "rpm"
	versions []*packages.PackageInfo
	osID     string // e.g. "debian", "ubuntu", "rhel", "centos"
	osVerID  string // e.g. "12", "22.04"
	ready    bool
}

// newPackageManager creates a package manager and detects the OS and package manager type.
func newPackageManager() *packageManager {
	pm := &packageManager{}

	// Parse /etc/os-release first to determine OS family
	pm.osID, pm.osVerID = parseOsReleaseIDs()

	// Detect package manager — prefer rpm on RPM-based distros
	// (some systems like cPanel install dpkg-query alongside rpm)
	hasRpm := exec.Command("rpm", "--version").Run() == nil
	hasDpkg := exec.Command("dpkg-query", "--version").Run() == nil

	switch {
	case isRpmDistro(pm.osID) && hasRpm:
		pm.pkgType = "rpm"
	case hasDpkg:
		pm.pkgType = "dpkg"
	case hasRpm:
		pm.pkgType = "rpm"
	default:
		slog.Debug("No supported package manager found (dpkg/rpm)")
		return nil
	}

	slog.Debug("Package manager", "type", pm.pkgType, "os", pm.osID, "version", pm.osVerID)
	return pm
}

// isRpmDistro returns true for distros that use rpm as their native package manager.
func isRpmDistro(osID string) bool {
	switch osID {
	case "almalinux", "rocky", "rhel", "centos", "fedora", "ol", "amzn", "cloudlinux":
		return true
	}
	return false
}

// startWorker starts a background goroutine that refreshes package versions daily.
// onRefresh is called after each collection (including the initial one) so callers
// can react to updated versions (e.g. mark system details dirty).
func (pm *packageManager) startWorker(getServiceNames func() []string, onRefresh func()) {
	pm.collectVersions(getServiceNames())
	if onRefresh != nil {
		onRefresh()
	}

	go func() {
		for {
			time.Sleep(24 * time.Hour)
			pm.collectVersions(getServiceNames())
			if onRefresh != nil {
				onRefresh()
			}
		}
	}()
}

// getVersions returns the cached package versions.
func (pm *packageManager) getVersions() []*packages.PackageInfo {
	pm.Lock()
	defer pm.Unlock()
	return pm.versions
}

// collectVersions detects package versions for the given service names.
func (pm *packageManager) collectVersions(serviceNames []string) {
	var result []*packages.PackageInfo

	for _, svcName := range serviceNames {
		binPath := getServiceBinaryPath(svcName)
		if binPath == "" {
			continue
		}

		pkgName := pm.getPackageForBinary(binPath)
		if pkgName == "" {
			continue
		}

		pkgVersion := pm.getPackageVersion(pkgName)
		if pkgVersion == "" {
			continue
		}

		// For dpkg/rpm, resolve to the source package name so OSV.dev queries
		// match correctly (OSV uses source package names for Debian/Ubuntu/Alpine).
		sourcePkg := pm.getSourcePackageName(pkgName)

		result = append(result, &packages.PackageInfo{
			Service: svcName,
			Package: sourcePkg,
			Version: pkgVersion,
		})
	}

	pm.Lock()
	pm.versions = result
	pm.ready = true
	pm.Unlock()

	slog.Debug("Package versions collected", "count", len(result))
}

// getServiceBinaryPath extracts the main binary path from a systemd service's ExecStart.
func getServiceBinaryPath(serviceName string) string {
	out, err := exec.Command("systemctl", "show", serviceName+".service", "-p", "ExecStart").Output()
	if err != nil {
		return ""
	}

	line := strings.TrimSpace(string(out))
	line = strings.TrimPrefix(line, "ExecStart=")
	if line == "" {
		return ""
	}

	// Format: "{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx ... }"
	if strings.HasPrefix(line, "{ path=") {
		line = strings.TrimPrefix(line, "{ path=")
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			return line[:idx]
		}
		return strings.TrimSuffix(line, " }")
	}

	// Simple format: "/usr/sbin/nginx -g daemon"
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		return line[:idx]
	}
	return line
}

// getPackageForBinary finds the package that owns the given binary path.
func (pm *packageManager) getPackageForBinary(binPath string) string {
	switch pm.pkgType {
	case "dpkg":
		out, err := exec.Command("dpkg", "-S", binPath).Output()
		if err != nil {
			return ""
		}
		// Output: "nginx-core: /usr/sbin/nginx"
		line := strings.TrimSpace(string(out))
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			pkg := line[:idx]
			// Remove arch suffix if present (e.g., "nginx-core:amd64")
			if archIdx := strings.IndexByte(pkg, ','); archIdx > 0 {
				pkg = pkg[:archIdx]
			}
			return pkg
		}
	case "rpm":
		out, err := exec.Command("rpm", "-qf", "--qf", "%{NAME}", binPath).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return ""
}

// getSourcePackageName resolves a binary package name to its source package name.
// OSV.dev uses source package names for Debian/Ubuntu/Alpine ecosystems.
// Falls back to the binary package name if source cannot be determined.
func (pm *packageManager) getSourcePackageName(binaryPkg string) string {
	switch pm.pkgType {
	case "dpkg":
		out, err := exec.Command("dpkg-query", "-W", "-f=${Source}", binaryPkg).Output()
		if err != nil {
			return binaryPkg
		}
		src := strings.TrimSpace(string(out))
		if src == "" {
			return binaryPkg
		}
		// Source field may include a version in parens: "nginx (1.14.0-1)"
		if idx := strings.IndexByte(src, '('); idx > 0 {
			src = strings.TrimSpace(src[:idx])
		}
		return src
	}
	return binaryPkg
}

// getPackageVersion returns the installed version of the given package.
func (pm *packageManager) getPackageVersion(pkgName string) string {
	switch pm.pkgType {
	case "dpkg":
		out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", pkgName).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	case "rpm":
		out, err := exec.Command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkgName).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return ""
}

