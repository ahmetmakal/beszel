package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`
			CREATE TABLE IF NOT EXISTS package_vuln_cache (
				ecosystem TEXT NOT NULL,
				package   TEXT NOT NULL,
				version   TEXT NOT NULL,
				vulns     TEXT NOT NULL DEFAULT '[]',
				status    TEXT NOT NULL DEFAULT 'safe',
				scanned_at TEXT NOT NULL,
				PRIMARY KEY (ecosystem, package, version)
			)
		`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery(`DROP TABLE IF EXISTS package_vuln_cache`).Execute()
		return err
	})
}
