import { t } from "@lingui/core/macro"
import { Trans } from "@lingui/react/macro"
import { getPagePath } from "@nanostores/router"
import {
	ClockIcon,
	HistoryIcon,
	LoaderCircleIcon,
	RefreshCwIcon,
	ShieldAlertIcon,
	ShieldCheckIcon,
	ShieldQuestionIcon,
} from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { $router } from "@/components/router"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { isAdmin, pb } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { VulnScanOverview } from "@/types"

function statusBadge(status: string) {
	switch (status) {
		case "running":
			return (
				<Badge variant="secondary" className="gap-1">
					<LoaderCircleIcon className="size-3 animate-spin" />
					<Trans>Running</Trans>
				</Badge>
			)
		case "queued":
			return (
				<Badge variant="outline" className="gap-1">
					<ClockIcon className="size-3" />
					<Trans>Queued</Trans>
				</Badge>
			)
		case "scanned":
			return (
				<Badge variant="success" className="gap-1">
					<ShieldCheckIcon className="size-3" />
					<Trans>Scanned</Trans>
				</Badge>
			)
		case "never_scanned":
			return (
				<Badge variant="outline" className="gap-1 text-amber-600 border-amber-600/40">
					<ShieldQuestionIcon className="size-3" />
					<Trans>Pending</Trans>
				</Badge>
			)
		case "failed":
			return (
				<Badge variant="destructive" className="gap-1">
					<ShieldAlertIcon className="size-3" />
					<Trans>Failed</Trans>
				</Badge>
			)
		case "no_packages":
			return (
				<Badge variant="outline" className="text-muted-foreground">
					<Trans>No packages</Trans>
				</Badge>
			)
		default:
			return <Badge variant="outline">{status}</Badge>
	}
}

function formatTime(iso?: string) {
	if (!iso) return "—"
	try {
		return new Date(iso).toLocaleString()
	} catch {
		return iso
	}
}

const emptyStats = {
	total: 0,
	withPackages: 0,
	scanned: 0,
	neverScanned: 0,
	queuedOrRunning: 0,
	withVulns: 0,
}

function normalizeOverview(data: VulnScanOverview): VulnScanOverview {
	return {
		...data,
		systems: data.systems ?? [],
		queue: data.queue ?? [],
		recentEvents: data.recentEvents ?? [],
		stats: data.stats ?? emptyStats,
	}
}

function eventLabel(action: string) {
	switch (action) {
		case "queued":
			return t`Queued`
		case "started":
			return t`Started`
		case "completed":
			return t`Completed`
		case "failed":
			return t`Failed`
		default:
			return action
	}
}

export function VulnScanPanel({
	systemId,
	compact = false,
	showSystemsTable = true,
	onOverviewUpdate,
}: {
	systemId?: string
	compact?: boolean
	showSystemsTable?: boolean
	onOverviewUpdate?: () => void
}) {
	const [overview, setOverview] = useState<VulnScanOverview | null>(null)
	const [loading, setLoading] = useState(true)
	const [scanning, setScanning] = useState(false)

	const fetchOverview = useCallback(async () => {
		try {
			const res = await pb.send<VulnScanOverview>("/api/beszel/vulnerabilities/overview", {
				query: systemId ? { system: systemId } : undefined,
			})
			setOverview(normalizeOverview(res))
			onOverviewUpdate?.()
		} catch {
			setOverview(null)
		} finally {
			setLoading(false)
		}
	}, [systemId, onOverviewUpdate])

	useEffect(() => {
		fetchOverview()
		const interval = setInterval(fetchOverview, 4000)
		return () => clearInterval(interval)
	}, [fetchOverview])

	async function triggerScan(targetSystemId?: string) {
		setScanning(true)
		try {
			await pb.send("/api/beszel/vulnerabilities/scan", {
				method: "POST",
				query: targetSystemId ? { system: targetSystemId } : undefined,
			})
			await fetchOverview()
		} finally {
			setScanning(false)
		}
	}

	if (loading && !overview) {
		return (
			<div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
				<LoaderCircleIcon className="size-4 animate-spin" />
				<Trans>Loading scan status…</Trans>
			</div>
		)
	}

	if (!overview) {
		return null
	}

	const system = systemId ? overview.systems[0] : undefined
	const queueActive = overview.queue.some((q) => q.running || q.queued)

	if (systemId && !system) {
		return (
			<div className="text-sm text-muted-foreground py-2">
				<Trans>No vulnerability scan data for this server yet.</Trans>
			</div>
		)
	}

	return (
		<div className={cn("space-y-4", compact && "space-y-3")}>
			{!compact && (
				<div className="flex flex-wrap items-start justify-between gap-3">
					<div>
						<h3 className="text-xl font-medium mb-1">
							<Trans>Vulnerability Scans</Trans>
						</h3>
						<p className="text-sm text-muted-foreground">
							<Trans>OSV.dev package scans, queue status, and per-server results.</Trans>
						</p>
					</div>
					{isAdmin() && !systemId && (
						<Button variant="outline" size="sm" disabled={scanning || queueActive} onClick={() => triggerScan()}>
							<RefreshCwIcon className={cn("size-3.5 me-1.5", scanning && "animate-spin")} />
							<Trans>Scan all systems</Trans>
						</Button>
					)}
				</div>
			)}

			{compact && system && (
				<div className="rounded-lg border bg-muted/20 px-3 py-2.5 text-sm space-y-1.5">
					<div className="flex flex-wrap items-center gap-2">
						{statusBadge(system.status)}
						{system.vulnerableServices > 0 && (
							<span className="text-red-500 font-medium">
								<Trans>{system.vulnerableServices} vulnerable services</Trans>
							</span>
						)}
						{system.kernelVulnerable && (
							<span className="text-red-500 font-medium">
								<Trans>Kernel vulnerable</Trans>
							</span>
						)}
						<Button
							variant="ghost"
							size="sm"
							className="h-7 ms-auto px-2"
							disabled={scanning || system.running || system.queued}
							onClick={() => triggerScan(systemId)}
						>
							<RefreshCwIcon className={cn("size-3.5", (scanning || system.running) && "animate-spin")} />
						</Button>
					</div>
					<div className="text-muted-foreground text-xs flex flex-wrap gap-x-4 gap-y-1">
						<span>
							<Trans>Last scan:</Trans> {formatTime(system.scannedAt)}
						</span>
						<span>
							<Trans>Packages:</Trans> {system.packageCount}
						</span>
						{system.lastError && <span className="text-red-500">{system.lastError}</span>}
					</div>
				</div>
			)}

			{!compact && (
				<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
					<StatCard label={t`Scanned`} value={overview.stats.scanned} />
					<StatCard label={t`Pending scan`} value={overview.stats.neverScanned} />
					<StatCard label={t`In queue`} value={overview.stats.queuedOrRunning} />
					<StatCard label={t`With vulnerabilities`} value={overview.stats.withVulns} highlight={overview.stats.withVulns > 0} />
				</div>
			)}

			{!compact && (
				<div className="grid gap-4 lg:grid-cols-2">
					<div className="rounded-lg border p-3 space-y-2">
						<h4 className="text-sm font-medium flex items-center gap-1.5">
							<ClockIcon className="size-4 opacity-70" />
							<Trans>Schedule</Trans>
						</h4>
						<dl className="text-sm grid gap-1.5">
							<div className="flex justify-between gap-4">
								<dt className="text-muted-foreground">
									<Trans>Automatic scan</Trans>
								</dt>
								<dd>{overview.cronSchedule}</dd>
							</div>
							<div className="flex justify-between gap-4">
								<dt className="text-muted-foreground">
									<Trans>Next scheduled</Trans>
								</dt>
								<dd>{formatTime(overview.nextCronAt)}</dd>
							</div>
							<div className="flex justify-between gap-4">
								<dt className="text-muted-foreground">
									<Trans>Last full scan</Trans>
								</dt>
								<dd>{formatTime(overview.lastCronAt)}</dd>
							</div>
							<div className="flex justify-between gap-4">
								<dt className="text-muted-foreground">
									<Trans>Cache entries</Trans>
								</dt>
								<dd>{overview.cacheEntries}</dd>
							</div>
						</dl>
					</div>

					<div className="rounded-lg border p-3 space-y-2">
						<h4 className="text-sm font-medium flex items-center gap-1.5">
							<LoaderCircleIcon className={cn("size-4 opacity-70", queueActive && "animate-spin")} />
							<Trans>Scan queue</Trans>
							{overview.queueLength > 0 && (
								<Badge variant="secondary" className="ms-1">
									{overview.queueLength}
								</Badge>
							)}
						</h4>
						{overview.queue.length === 0 ? (
							<p className="text-sm text-muted-foreground">
								<Trans>Queue is empty</Trans>
							</p>
						) : (
							<ul className="text-sm space-y-2 max-h-40 overflow-y-auto">
								{overview.queue.map((item) => (
									<li key={`${item.systemId}-${item.enqueuedAt}`} className="flex items-center justify-between gap-2">
										<span className="truncate">{item.allSystems ? t`All systems` : item.systemName}</span>
										{item.running ? (
											<Badge variant="secondary" className="shrink-0 gap-1">
												<LoaderCircleIcon className="size-3 animate-spin" />
												<Trans>Running</Trans>
											</Badge>
										) : (
											<Badge variant="outline" className="shrink-0">
												<Trans>Queued</Trans>
											</Badge>
										)}
									</li>
								))}
							</ul>
						)}
					</div>
				</div>
			)}

			{(compact ? overview.recentEvents.length > 0 : true) && overview.recentEvents.length > 0 && (
				<div className={cn("rounded-lg border p-3 space-y-2", compact && "text-xs")}>
					<h4 className={cn("font-medium flex items-center gap-1.5", compact ? "text-xs" : "text-sm")}>
						<HistoryIcon className="size-4 opacity-70" />
						<Trans>Recent activity</Trans>
					</h4>
					<ul className={cn("space-y-1 max-h-32 overflow-y-auto", compact ? "text-xs" : "text-sm")}>
						{[...overview.recentEvents].reverse().slice(0, compact ? 5 : 12).map((ev) => (
							<li key={`${ev.at}-${ev.action}-${ev.systemId}`} className="flex flex-wrap gap-x-2 text-muted-foreground">
								<span className="text-foreground/80">{formatTime(ev.at)}</span>
								<span>{eventLabel(ev.action)}</span>
								{ev.systemName && <span>— {ev.systemName}</span>}
								{ev.detail && <span className="text-red-500 truncate">{ev.detail}</span>}
							</li>
						))}
					</ul>
				</div>
			)}

			{showSystemsTable && !systemId && overview.systems.length > 0 && (
				<>
					<Separator />
					<div className="rounded-md border overflow-x-auto">
						<Table>
							<TableHeader>
								<TableRow>
									<TableHead>
										<Trans>Server</Trans>
									</TableHead>
									<TableHead>
										<Trans>Status</Trans>
									</TableHead>
									<TableHead>
										<Trans>Packages</Trans>
									</TableHead>
									<TableHead>
										<Trans>Last scan</Trans>
									</TableHead>
									<TableHead>
										<Trans>Vulns</Trans>
									</TableHead>
									<TableHead className="w-10" />
								</TableRow>
							</TableHeader>
							<TableBody>
								{overview.systems.map((sys) => (
									<TableRow key={sys.systemId}>
										<TableCell className="font-medium">
											<a
												href={getPagePath($router, "system", { id: sys.systemId })}
												className="hover:underline"
											>
												{sys.systemName}
											</a>
										</TableCell>
										<TableCell>{statusBadge(sys.status)}</TableCell>
										<TableCell>{sys.packageCount}</TableCell>
										<TableCell className="text-muted-foreground text-xs whitespace-nowrap">
											{formatTime(sys.scannedAt)}
										</TableCell>
										<TableCell>
											{sys.vulnerableServices > 0 || sys.kernelVulnerable ? (
												<span className="text-red-500 font-medium">{sys.vulnerableServices + (sys.kernelVulnerable ? 1 : 0)}</span>
											) : sys.status === "scanned" ? (
												<span className="text-muted-foreground">0</span>
											) : (
												"—"
											)}
										</TableCell>
										<TableCell>
											<Button
												variant="ghost"
												size="icon"
												className="size-8"
												disabled={scanning || sys.running || sys.queued || sys.packageCount === 0}
												onClick={() => triggerScan(sys.systemId)}
												title={t`Scan now`}
											>
												<RefreshCwIcon className={cn("size-3.5", sys.running && "animate-spin")} />
											</Button>
										</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
					</div>
				</>
			)}
		</div>
	)
}

function StatCard({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
	return (
		<div className="rounded-lg border px-3 py-2.5">
			<div className="text-xs text-muted-foreground mb-0.5">{label}</div>
			<div className={cn("text-2xl font-semibold tabular-nums", highlight && "text-red-500")}>{value}</div>
		</div>
	)
}
