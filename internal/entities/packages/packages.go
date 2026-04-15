package packages

// PackageInfo represents a package associated with a systemd service.
type PackageInfo struct {
	Service string `json:"s" cbor:"0,keyasint"`  // systemd service name ("nginx")
	Package string `json:"p" cbor:"1,keyasint"`  // package name ("nginx-core")
	Version string `json:"v" cbor:"2,keyasint"`  // package version ("1.24.0-2")
}
