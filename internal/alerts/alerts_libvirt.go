package alerts

import (
	"fmt"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// HandleLibvirtAlerts checks libvirt VM states against configured VM alerts.
func (am *AlertManager) HandleLibvirtAlerts(systemRecord *core.Record) error {
	alerts := am.alertsCache.GetAlertsByName(systemRecord.Id, "VMBlocked")
	if len(alerts) == 0 {
		return nil
	}

	systemName := systemRecord.GetString("name")

	var blocked []struct {
		Name string `db:"name"`
	}
	err := am.hub.DB().
		Select("name").
		From("libvirt_vms").
		Where(dbx.HashExp{"system": systemRecord.Id, "status": "blocked"}).
		All(&blocked)
	if err != nil {
		return err
	}

	hasBlocked := len(blocked) > 0

	for _, alertData := range alerts {
		triggered := alertData.Triggered
		if hasBlocked && !triggered {
			names := make([]string, len(blocked))
			for i, vm := range blocked {
				names[i] = vm.Name
			}
			go am.sendVMBlockedAlert(systemRecord.Id, systemName, names, alertData, true)
		} else if !hasBlocked && triggered {
			go am.sendVMBlockedAlert(systemRecord.Id, systemName, nil, alertData, false)
		}
	}

	return nil
}

func (am *AlertManager) sendVMBlockedAlert(systemID, systemName string, vmNames []string, alertData CachedAlertData, triggering bool) {
	var title, body string
	if triggering {
		title = fmt.Sprintf("%s VM blocked", systemName)
		if len(vmNames) == 1 {
			body = fmt.Sprintf("VM %s on %s is in blocked state (likely waiting on disk I/O).", vmNames[0], systemName)
		} else {
			body = fmt.Sprintf("%d VMs on %s are blocked: %v", len(vmNames), systemName, vmNames)
		}
	} else {
		title = fmt.Sprintf("%s VM blocked recovered", systemName)
		body = fmt.Sprintf("No blocked VMs on %s.", systemName)
	}

	if err := am.setAlertTriggered(alertData, triggering); err != nil {
		return
	}

	am.SendAlert(AlertMessageData{
		UserID:   alertData.UserID,
		SystemID: systemID,
		Title:    title,
		Message:  body,
		Link:     am.hub.MakeLink("system", systemID),
		LinkText: "View " + systemName,
	})
}
