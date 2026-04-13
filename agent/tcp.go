package agent

import (
	"log/slog"
	"runtime"

	"github.com/henrygd/beszel/internal/entities/system"
	psutilNet "github.com/shirou/gopsutil/v4/net"
)

// TCP connection states to track
var trackedTcpStates = map[string]struct{}{
	"ESTABLISHED": {},
	"LISTEN":      {},
	"TIME_WAIT":   {},
	"CLOSE_WAIT":  {},
	"FIN_WAIT1":   {},
	"FIN_WAIT2":   {},
	"SYN_SENT":    {},
	"SYN_RECV":    {},
	"LAST_ACK":    {},
}

func (a *Agent) updateTcpConnections(systemStats *system.Stats) {
	var conns []psutilNet.ConnectionStat
	var err error

	if runtime.GOOS == "darwin" {
		// macOS does not support ConnectionsWithoutUids
		conns, err = psutilNet.Connections("tcp")
	} else {
		// Linux: use ConnectionsWithoutUids (no root needed, reads /proc/net/tcp directly)
		conns, err = psutilNet.ConnectionsWithoutUids("tcp")
	}

	if err != nil {
		slog.Debug("Error getting TCP connections", "err", err)
		return
	}

	counts := make(map[string]uint32, len(trackedTcpStates))
	for _, conn := range conns {
		if _, ok := trackedTcpStates[conn.Status]; ok {
			counts[conn.Status]++
		}
	}

	if len(counts) > 0 {
		systemStats.TcpConns = counts
	}
}
