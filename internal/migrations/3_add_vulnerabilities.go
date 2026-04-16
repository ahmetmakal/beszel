package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		details, err := app.FindCollectionByNameOrId("system_details")
		if err != nil {
			return err
		}
		if details.Fields.GetByName("vulns") == nil {
			details.Fields.Add(&core.JSONField{
				Id:       "json_vulns",
				Name:     "vulns",
				MaxSize:  2000000, // 2MB max
				Required: false,
			})
			if err := app.SaveNoValidate(details); err != nil {
				return err
			}
		}
		return nil
	}, nil)
}
