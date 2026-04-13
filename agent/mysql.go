package agent

import (
	"database/sql"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/henrygd/beszel/agent/utils"
	"github.com/henrygd/beszel/internal/entities/system"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlManager struct {
	sync.Mutex
	db               *sql.DB
	dsn              string
	prevQueries      uint64
	prevSlowQueries  uint64
	prevTime         time.Time
}

func newMySQLManager() (*mysqlManager, error) {
	dsn, exists := utils.GetEnv("MYSQL_DSN")
	if !exists {
		return nil, nil
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	slog.Info("MySQL monitoring", "dsn", sanitizeDSN(dsn))

	return &mysqlManager{
		db:  db,
		dsn: dsn,
	}, nil
}

func (m *mysqlManager) getStats() *system.MySQLStats {
	m.Lock()
	defer m.Unlock()

	if err := m.db.Ping(); err != nil {
		slog.Debug("MySQL ping failed, reconnecting", "err", err)
		return nil
	}

	stats := &system.MySQLStats{
		ReplicationLag: -1, // default: no replication
	}

	// Collect SHOW GLOBAL STATUS
	statusMap := m.queryKeyValue("SHOW GLOBAL STATUS")
	if statusMap == nil {
		return nil
	}

	// Collect SHOW GLOBAL VARIABLES
	varsMap := m.queryKeyValue("SHOW GLOBAL VARIABLES")

	// Queries per second (delta)
	currentQueries := parseStatusUint64(statusMap["Queries"])
	stats.QueriesPerSec = m.calcQPS(currentQueries)

	// Connections
	stats.Connections = uint32(parseStatusUint64(statusMap["Threads_connected"]))
	stats.ThreadsRunning = uint32(parseStatusUint64(statusMap["Threads_running"]))
	if varsMap != nil {
		stats.MaxConnections = uint32(parseStatusUint64(varsMap["max_connections"]))
	}

	// Slow queries per second (delta)
	currentSlowQueries := parseStatusUint64(statusMap["Slow_queries"])
	stats.SlowQueriesPerSec = m.calcSlowQPS(currentSlowQueries)

	// InnoDB buffer pool hit rate
	reads := parseStatusUint64(statusMap["Innodb_buffer_pool_read_requests"])
	diskReads := parseStatusUint64(statusMap["Innodb_buffer_pool_reads"])
	if reads > 0 {
		stats.BufferPoolHitRate = utils.TwoDecimals(float64(reads-diskReads) / float64(reads) * 100)
	}

	// Key cache hit rate
	keyReads := parseStatusUint64(statusMap["Key_read_requests"])
	keyDiskReads := parseStatusUint64(statusMap["Key_reads"])
	if keyReads > 0 {
		stats.KeyCacheHitRate = utils.TwoDecimals(float64(keyReads-keyDiskReads) / float64(keyReads) * 100)
	}

	// Replication status
	m.checkReplication(stats)

	return stats
}

func (m *mysqlManager) queryKeyValue(query string) map[string]string {
	rows, err := m.db.Query(query)
	if err != nil {
		slog.Debug("MySQL query error", "query", query, "err", err)
		return nil
	}
	defer rows.Close()

	result := make(map[string]string)
	var key, value string
	for rows.Next() {
		if err := rows.Scan(&key, &value); err == nil {
			result[key] = value
		}
	}
	return result
}

func (m *mysqlManager) checkReplication(stats *system.MySQLStats) {
	rows, err := m.db.Query("SHOW SLAVE STATUS")
	if err != nil {
		// Try MariaDB syntax
		rows, err = m.db.Query("SHOW REPLICA STATUS")
		if err != nil {
			return // no replication configured
		}
	}
	defer rows.Close()

	if !rows.Next() {
		return // no replication
	}

	cols, err := rows.Columns()
	if err != nil {
		return
	}

	values := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}

	if err := rows.Scan(ptrs...); err != nil {
		return
	}

	colMap := make(map[string]string)
	for i, col := range cols {
		if values[i].Valid {
			colMap[col] = values[i].String
		}
	}

	ioRunning := colMap["Slave_IO_Running"]
	sqlRunning := colMap["Slave_SQL_Running"]
	// MariaDB uses different column names
	if ioRunning == "" {
		ioRunning = colMap["Replica_IO_Running"]
	}
	if sqlRunning == "" {
		sqlRunning = colMap["Replica_SQL_Running"]
	}

	stats.ReplicationOk = ioRunning == "Yes" && sqlRunning == "Yes"

	lagStr := colMap["Seconds_Behind_Master"]
	if lagStr == "" {
		lagStr = colMap["Seconds_Behind_Source"]
	}
	if lagStr != "" {
		lag, err := strconv.ParseInt(lagStr, 10, 64)
		if err == nil {
			stats.ReplicationLag = lag
		}
	}
}

func (m *mysqlManager) calcQPS(currentQueries uint64) float64 {
	now := time.Now()
	if m.prevTime.IsZero() {
		m.prevQueries = currentQueries
		m.prevSlowQueries = 0
		m.prevTime = now
		return 0
	}

	elapsed := now.Sub(m.prevTime).Seconds()
	if elapsed <= 0 {
		return 0
	}

	var qps float64
	if currentQueries >= m.prevQueries {
		qps = float64(currentQueries-m.prevQueries) / elapsed
	}

	m.prevQueries = currentQueries
	m.prevTime = now
	return utils.TwoDecimals(qps)
}

func (m *mysqlManager) calcSlowQPS(currentSlowQueries uint64) float64 {
	now := time.Now()
	elapsed := now.Sub(m.prevTime).Seconds()
	if elapsed <= 0 || m.prevSlowQueries == 0 {
		m.prevSlowQueries = currentSlowQueries
		return 0
	}

	var sqps float64
	if currentSlowQueries >= m.prevSlowQueries {
		sqps = float64(currentSlowQueries-m.prevSlowQueries) / elapsed
	}

	m.prevSlowQueries = currentSlowQueries
	return utils.TwoDecimals(sqps)
}

func parseStatusUint64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// sanitizeDSN removes password from DSN for logging
func sanitizeDSN(dsn string) string {
	// Format: user:pass@tcp(host:port)/db
	atIdx := -1
	for i, c := range dsn {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx == -1 {
		return dsn
	}

	colonIdx := -1
	for i, c := range dsn[:atIdx] {
		if c == ':' {
			colonIdx = i
			break
		}
	}
	if colonIdx == -1 {
		return dsn
	}

	return dsn[:colonIdx+1] + "***" + dsn[atIdx:]
}
