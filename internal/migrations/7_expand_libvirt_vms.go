package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("libvirt_vms")
		if err != nil {
			return nil
		}
		addNumber := func(name string) {
			if c.Fields.GetByName(name) != nil {
				return
			}
			c.Fields.Add(&core.NumberField{Name: name})
		}
		addText := func(name string) {
			if c.Fields.GetByName(name) != nil {
				return
			}
			c.Fields.Add(&core.TextField{Name: name})
		}
		addNumber("memory_pct")
		addNumber("net_rx")
		addNumber("net_wx")
		addNumber("disk_read")
		addNumber("disk_write")
		addNumber("disk_iops")
		addText("ip")
		addText("bridge")
		addNumber("uptime")
		addNumber("disk_cap")
		return app.Save(c)
	}, func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("libvirt_vms")
		if err != nil {
			return nil
		}
		for _, name := range []string{
			"memory_pct", "net_rx", "net_wx", "disk_read", "disk_write", "disk_iops",
			"ip", "bridge", "uptime", "disk_cap",
		} {
			if f := c.Fields.GetByName(name); f != nil {
				c.Fields.RemoveById(f.GetId())
			}
		}
		return app.Save(c)
	})
}
