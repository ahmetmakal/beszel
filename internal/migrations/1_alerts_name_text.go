package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		collection, err := app.FindCollectionByNameOrId("alerts")
		if err != nil {
			return err
		}

		nameField := collection.Fields.GetByName("name")
		if nameField == nil {
			return nil
		}

		// Only migrate if it's still a select field
		if nameField.Type() != "select" {
			return nil
		}

		fieldId := nameField.GetId()

		// Remove old select field and replace with text field
		collection.Fields.RemoveById(fieldId)
		collection.Fields.Add(&core.TextField{
			Id:       fieldId,
			Name:     "name",
			Required: true,
		})

		return app.SaveNoValidate(collection)
	}, nil)
}
