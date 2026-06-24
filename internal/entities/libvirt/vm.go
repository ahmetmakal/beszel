package libvirt

// VmHealth mirrors container health values for consistent UI rendering.
type VmHealth = uint8

const (
	HealthNone VmHealth = iota
	HealthStarting
	HealthHealthy
	HealthUnhealthy
)

// Stats holds libvirt/KVM VM metrics collected once per agent cycle.
type Stats struct {
	Name      string    `json:"n" cbor:"0,keyasint"`
	Cpu       float64   `json:"c" cbor:"1,keyasint"`
	Mem       float64   `json:"m" cbor:"2,keyasint"` // megabytes used
	Bandwidth [2]uint64 `json:"b,omitzero" cbor:"3,keyasint,omitzero"`
	Disk      [2]uint64 `json:"d,omitzero" cbor:"4,keyasint,omitzero"` // cumulative read/write bytes

	Health  VmHealth `json:"-" cbor:"5,keyasint"`
	Status  string   `json:"-" cbor:"6,keyasint"`
	Id      string   `json:"-" cbor:"7,keyasint"`
	Vcpus   uint16   `json:"-" cbor:"8,keyasint,omitempty"`
	MemMax  uint64   `json:"-" cbor:"9,keyasint,omitempty"` // bytes
	DiskSum uint64   `json:"-" cbor:"-"`                    // read+write for table sorting

	// agent-only counters
	CpuUsage uint64 `json:"-"`
}

func HealthFromState(state int) VmHealth {
	switch state {
	case 1: // running
		return HealthHealthy
	case 2, 3: // blocked, paused
		return HealthStarting
	case 6, 7: // crashed, pm suspended
		return HealthUnhealthy
	default:
		return HealthNone
	}
}

func StatusFromState(state int) string {
	switch state {
	case 1:
		return "running"
	case 2:
		return "blocked"
	case 3:
		return "paused"
	case 4:
		return "shutdown"
	case 5:
		return "shut off"
	case 6:
		return "crashed"
	case 7:
		return "pmsuspended"
	default:
		return "unknown"
	}
}
