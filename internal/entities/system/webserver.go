package system

// WebServerStats holds metrics from web server status endpoints (Nginx, Apache, Litespeed)
type WebServerStats struct {
	Type        string  `json:"tp" cbor:"0,keyasint"`                       // nginx, apache, litespeed
	ActiveConns uint32  `json:"ac" cbor:"1,keyasint"`                       // active connections
	ReqPerSec   float64 `json:"rps" cbor:"2,keyasint"`                      // requests per second
	BytesPerSec float64 `json:"bps,omitzero" cbor:"3,keyasint,omitzero"`    // bytes per second
	BusyWorkers uint32  `json:"bw,omitzero" cbor:"4,keyasint,omitzero"`     // busy/active workers
	IdleWorkers uint32  `json:"iw,omitzero" cbor:"5,keyasint,omitzero"`     // idle workers
	Reading     uint32  `json:"r,omitzero" cbor:"6,keyasint,omitzero"`      // reading request connections
	Writing     uint32  `json:"w,omitzero" cbor:"7,keyasint,omitzero"`      // writing response connections
	Waiting     uint32  `json:"wt,omitzero" cbor:"8,keyasint,omitzero"`     // keep-alive waiting connections
}
