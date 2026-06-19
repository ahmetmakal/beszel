import { Trans } from "@lingui/react/macro"
import { redirectPage } from "@nanostores/router"
import { $router } from "@/components/router"
import { VulnScanPanel } from "@/components/vuln-scan/vuln-scan-panel"
import { Separator } from "@/components/ui/separator"
import { isAdmin } from "@/lib/api"

export default function VulnerabilitiesSettings() {
	if (!isAdmin()) {
		redirectPage($router, "settings", { name: "general" })
	}

	return (
		<div>
			<VulnScanPanel showSystemsTable />
			<Separator className="my-4" />
			<p className="text-xs text-muted-foreground">
				<Trans>
					Scans use OSV.dev with a shared package cache. Results appear on each server's Systemd Services table after
					scanning completes.
				</Trans>
			</p>
		</div>
	)
}
