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

		if _, err := app.FindCollectionByNameOrId("libvirt_vms"); err != nil {
			c := core.NewBaseCollection("libvirt_vms")
			c.Fields.Add(
				&core.TextField{Name: "id", Required: true, PrimaryKey: true, Min: 6, Max: 12, Pattern: "^[a-f0-9]+$"},
				&core.RelationField{
					Name:          "system",
					CollectionId:  systemsCollection.Id,
					Required:      true,
					MaxSelect:     1,
					CascadeDelete: true,
				},
				&core.TextField{Name: "name"},
				&core.TextField{Name: "status"},
				&core.NumberField{Name: "health"},
				&core.NumberField{Name: "cpu"},
				&core.NumberField{Name: "memory"},
				&core.NumberField{Name: "net"},
				&core.NumberField{Name: "disk"},
				&core.NumberField{Name: "vcpus"},
				&core.NumberField{Name: "mem_max"},
				&core.NumberField{Name: "updated"},
			)
			if err := app.Save(c); err != nil {
				return err
			}
		}

		if _, err := app.FindCollectionByNameOrId("libvirt_vm_stats"); err != nil {
			c := core.NewBaseCollection("libvirt_vm_stats")
			c.Fields.Add(
				&core.AutodateField{Name: "created", OnCreate: true, System: true},
				&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true, System: true},
				&core.RelationField{
					Name:          "system",
					CollectionId:  systemsCollection.Id,
					Required:      true,
					MaxSelect:     1,
					CascadeDelete: true,
				},
				&core.JSONField{Name: "stats", Required: true, MaxSize: 2_000_000},
				&core.SelectField{
					Name:     "type",
					Required: true,
					MaxSelect: 1,
					Values:   []string{"1m", "10m", "20m", "120m", "480m"},
				},
			)
			if err := app.Save(c); err != nil {
				return err
			}
		}

		return nil
	}, func(app core.App) error {
		if c, err := app.FindCollectionByNameOrId("libvirt_vm_stats"); err == nil {
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		if c, err := app.FindCollectionByNameOrId("libvirt_vms"); err == nil {
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		return nil
	})
}
