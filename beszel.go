// Package beszel provides core application constants and version information
// which are used throughout the application.
package beszel

import "github.com/blang/semver"

const (
	// AppName is the name of the application.
	AppName = "beszel"
)

// Version is set at link time via -ldflags (Makefile / GoReleaser).
// Fallback is used for local go run / tests without ldflags.
var Version = "0.0.0-dev"

// MinVersionCbor is the minimum supported version for CBOR compatibility.
var MinVersionCbor = semver.MustParse("0.12.0")

// MinVersionAgentResponse is the minimum supported version for AgentResponse compatibility.
var MinVersionAgentResponse = semver.MustParse("0.13.0")
