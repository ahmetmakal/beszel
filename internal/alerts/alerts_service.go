package alerts

import (
	"fmt"
	"strings"

	"github.com/henrygd/beszel/internal/entities/systemd"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const serviceAlertPrefix = "Service:"

// HandleServiceAlerts checks systemd service states against configured service alerts.
// It queries the systemd_services DB table directly so it works every update cycle,
// not just when the agent sends fresh systemd data (every 10 minutes).
func (am *AlertManager) HandleServiceAlerts(systemRecord *core.Record) error {
	alerts := am.alertsCache.GetAlertsByNamePrefix(systemRecord.Id, serviceAlertPrefix)
	if len(alerts) == 0 {
		return nil
	}

	systemName := systemRecord.GetString("name")

	for _, alertData := range alerts {
		serviceName := strings.TrimPrefix(alertData.Name, serviceAlertPrefix)
		if serviceName == "" {
			continue
		}

		// Query the DB directly for the current service state
		record, err := am.hub.FindFirstRecordByFilter(
			"systemd_services",
			"system={:system} && name={:name}",
			dbx.Params{"system": systemRecord.Id, "name": serviceName},
		)
		if err != nil {
			am.hub.Logger().Debug("HandleServiceAlerts: service not found in DB", "system", systemName, "service", serviceName, "err", err)
			continue
		}

		stateInt := record.GetInt("state")
		isActive := systemd.ServiceState(stateInt) == systemd.StatusActive
		triggered := alertData.Triggered

		am.hub.Logger().Debug("HandleServiceAlerts", "system", systemName, "service", serviceName, "state", stateInt, "isActive", isActive, "triggered", triggered)

		if !isActive && !triggered {
			state := systemd.ServiceState(stateInt)
			go am.sendServiceAlert(systemRecord.Id, systemName, serviceName, state, alertData, true)
		} else if isActive && triggered {
			go am.sendServiceAlert(systemRecord.Id, systemName, serviceName, systemd.StatusActive, alertData, false)
		}
	}

	return nil
}

func (am *AlertManager) sendServiceAlert(systemID, systemName, serviceName string, state systemd.ServiceState, alertData CachedAlertData, triggering bool) {
	var stateLabel string
	switch state {
	case systemd.StatusFailed:
		stateLabel = "failed"
	case systemd.StatusInactive:
		stateLabel = "inactive"
	case systemd.StatusActivating:
		stateLabel = "activating"
	case systemd.StatusDeactivating:
		stateLabel = "deactivating"
	default:
		stateLabel = "unknown"
	}

	var title, body string
	if triggering {
		title = fmt.Sprintf("%s %s is %s 🔴", systemName, serviceName, stateLabel)
		body = fmt.Sprintf("Service %s on %s changed state to %s.", serviceName, systemName, stateLabel)
	} else {
		title = fmt.Sprintf("%s %s recovered ✅", systemName, serviceName)
		body = fmt.Sprintf("Service %s on %s is now active.", serviceName, systemName)
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
