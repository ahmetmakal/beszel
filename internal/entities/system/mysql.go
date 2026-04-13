package system

// MySQLStats holds metrics from MySQL/MariaDB servers
type MySQLStats struct {
	QueriesPerSec     float64 `json:"qps" cbor:"0,keyasint"`                      // queries per second
	Connections       uint32  `json:"conn" cbor:"1,keyasint"`                      // current connections (Threads_connected)
	MaxConnections    uint32  `json:"maxc" cbor:"2,keyasint"`                      // max_connections
	ThreadsRunning    uint32  `json:"tr" cbor:"3,keyasint"`                        // currently running threads
	SlowQueriesPerSec float64 `json:"sq,omitzero" cbor:"4,keyasint,omitzero"`      // slow queries per second
	BufferPoolHitRate float64 `json:"bphr,omitzero" cbor:"5,keyasint,omitzero"`    // InnoDB buffer pool hit rate %
	KeyCacheHitRate   float64 `json:"kchr,omitzero" cbor:"6,keyasint,omitzero"`    // key cache hit rate %
	ReplicationLag    int64   `json:"rl" cbor:"7,keyasint"`                        // seconds behind master (-1 = no replication)
	ReplicationOk     bool    `json:"ro,omitzero" cbor:"8,keyasint,omitzero"`      // both IO and SQL threads running
}
