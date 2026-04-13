import { t } from "@lingui/core/macro"
import { Trans } from "@lingui/react/macro"
import { useStore } from "@nanostores/react"
import { TerminalSquareIcon, Trash2Icon, PlusIcon } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { toast } from "@/components/ui/use-toast"
import { pb } from "@/lib/api"
import { $alerts } from "@/lib/stores"
import type { AlertRecord, SystemRecord } from "@/types"

const SERVICE_PREFIX = "Service:"
const endpoint = "/api/beszel/user-alerts"

function failedToast(error: unknown) {
	console.error(error)
	toast({
		title: t`Failed to update alert`,
		description: t`Please check logs for more details.`,
		variant: "destructive",
	})
}

export function ServiceAlertsSection({ system }: { system: SystemRecord }) {
	const alerts = useStore($alerts)
	const systemAlerts = alerts[system.id] ?? new Map()

	// Current service alerts for this system
	const serviceAlerts: AlertRecord[] = []
	for (const [name, alert] of systemAlerts) {
		if (name.startsWith(SERVICE_PREFIX)) {
			serviceAlerts.push(alert)
		}
	}

	const [newServiceName, setNewServiceName] = useState("")
	const [adding, setAdding] = useState(false)

	async function addServiceAlert() {
		const name = newServiceName.trim()
		if (!name) return
		const alertName = SERVICE_PREFIX + name
		// check if already exists
		if (systemAlerts.has(alertName)) {
			toast({ title: t`Alert already exists for this service`, variant: "destructive" })
			return
		}
		setAdding(true)
		try {
			await pb.send(endpoint, {
				method: "POST",
				body: { name: alertName, value: 0, min: 1, systems: [system.id], overwrite: false },
			})
			setNewServiceName("")
		} catch (error) {
			failedToast(error)
		} finally {
			setAdding(false)
		}
	}

	async function deleteServiceAlert(alertName: string) {
		try {
			await pb.send(endpoint, {
				method: "DELETE",
				body: { name: alertName, systems: [system.id] },
			})
		} catch (error) {
			failedToast(error)
		}
	}

	return (
		<div className="rounded-lg border border-muted-foreground/15 hover:border-muted-foreground/20 transition-colors duration-100">
			<div className="flex items-center gap-3 p-4 pb-3">
				<TerminalSquareIcon className="h-4 w-4 opacity-85 shrink-0" />
				<div>
					<p className="font-semibold">
						<Trans>Service Status</Trans>
					</p>
					<p className="text-sm text-muted-foreground">
						<Trans>Triggers when a monitored service is no longer active</Trans>
					</p>
				</div>
			</div>

			<div className="px-4 pb-4 grid gap-2">
				{serviceAlerts.length > 0 && (
					<div className="grid gap-1.5 mb-1">
						{serviceAlerts.map((alert) => {
							const serviceName = alert.name.slice(SERVICE_PREFIX.length)
							return (
								<div
									key={alert.name}
									className="flex items-center justify-between gap-2 rounded-md border border-muted-foreground/10 bg-muted/30 px-3 py-2 text-sm"
								>
									<span className="font-mono truncate">{serviceName}</span>
									<div className="flex items-center gap-2 shrink-0">
										{alert.triggered && (
											<span className="text-xs text-destructive font-medium">
												<Trans>Triggered</Trans>
											</span>
										)}
										<Button
											variant="ghost"
											size="icon"
											className="h-7 w-7 text-muted-foreground hover:text-destructive"
											onClick={() => deleteServiceAlert(alert.name)}
										>
											<Trash2Icon className="h-3.5 w-3.5" />
										</Button>
									</div>
								</div>
							)
						})}
					</div>
				)}

				<div className="flex gap-2">
					<Input
						placeholder={t`e.g. nginx`}
						value={newServiceName}
						onChange={(e) => setNewServiceName(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && addServiceAlert()}
						className="h-8 text-sm font-mono"
					/>
					<Button
						size="sm"
						variant="outline"
						className="h-8 shrink-0 gap-1.5"
						disabled={!newServiceName.trim() || adding}
						onClick={addServiceAlert}
					>
						<PlusIcon className="h-3.5 w-3.5" />
						<Trans>Add</Trans>
					</Button>
				</div>
			</div>
		</div>
	)
}
