package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("libvirt_vm_stats")
		if err != nil {
			return nil
		}
		f := c.Fields.GetByName("stats")
		if f == nil {
			return nil
		}
		if jsonField, ok := f.(*core.JSONField); ok && jsonField.MaxSize < 10_000_000 {
			jsonField.MaxSize = 10_000_000
			return app.Save(c)
		}
		return nil
	}, func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("libvirt_vm_stats")
		if err != nil {
			return nil
		}
		f := c.Fields.GetByName("stats")
		if f == nil {
			return nil
		}
		if jsonField, ok := f.(*core.JSONField); ok && jsonField.MaxSize > 2_000_000 {
			jsonField.MaxSize = 2_000_000
			return app.Save(c)
		}
		return nil
	})
}
