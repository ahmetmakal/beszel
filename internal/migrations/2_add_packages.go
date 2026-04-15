package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		// Add "packages" JSON field to system_details collection.
		// Stores agent-collected package name + version per systemd service.
		details, err := app.FindCollectionByNameOrId("system_details")
		if err != nil {
			return err
		}
		if details.Fields.GetByName("packages") == nil {
			details.Fields.Add(&core.JSONField{
				Id:       "json_packages",
				Name:     "packages",
				MaxSize:  500000, // 500KB max
				Required: false,
			})
			if err := app.SaveNoValidate(details); err != nil {
				return err
			}
		}
		return nil
	}, nil)
}
