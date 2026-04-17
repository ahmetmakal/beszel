package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		systemsCollection, err := app.FindCollectionByNameOrId("systems")
		if err != nil {
			return err
		}

		// process_snapshots: periodic top process snapshots per system
		if _, err := app.FindCollectionByNameOrId("process_snapshots"); err != nil {
			c := core.NewBaseCollection("process_snapshots")
			c.Fields.Add(
				&core.AutodateField{
					Name:     "created",
					OnCreate: true,
					System:   true,
				},
				&core.AutodateField{
					Name:     "updated",
					OnCreate: true,
					OnUpdate: true,
					System:   true,
				},
				&core.RelationField{
					Name:          "system",
					CollectionId:  systemsCollection.Id,
					Required:      true,
					MaxSelect:     1,
					CascadeDelete: true,
				},
				&core.JSONField{
					Name:    "top",
					MaxSize: 2000000, // 2MB
				},
				&core.SelectField{
					Name:     "reason",
					Required: true,
					MaxSelect: 1,
					Values:   []string{"periodic", "manual", "alert"},
				},
			)
			if err := app.Save(c); err != nil {
				return err
			}
		}

		// system_events: lightweight timeline events for correlation
		if _, err := app.FindCollectionByNameOrId("system_events"); err != nil {
			c := core.NewBaseCollection("system_events")
			c.Fields.Add(
				&core.AutodateField{
					Name:     "created",
					OnCreate: true,
					System:   true,
				},
				&core.AutodateField{
					Name:     "updated",
					OnCreate: true,
					OnUpdate: true,
					System:   true,
				},
				&core.RelationField{
					Name:          "system",
					CollectionId:  systemsCollection.Id,
					Required:      true,
					MaxSelect:     1,
					CascadeDelete: true,
				},
				&core.SelectField{
					Name:      "type",
					Required:  true,
					MaxSelect: 1,
					Values: []string{
						"process_snapshot",
						"status_change",
						"vuln_scan",
						"alert_triggered",
						"alert_resolved",
					},
				},
				&core.TextField{
					Name:     "title",
					Required: true,
					Max:      500,
				},
				&core.JSONField{
					Name:    "details",
					MaxSize: 1000000, // 1MB
				},
			)
			if err := app.Save(c); err != nil {
				return err
			}
		}

		return nil
	}, func(app core.App) error {
		if c, err := app.FindCollectionByNameOrId("process_snapshots"); err == nil {
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		if c, err := app.FindCollectionByNameOrId("system_events"); err == nil {
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		return nil
	})
}

