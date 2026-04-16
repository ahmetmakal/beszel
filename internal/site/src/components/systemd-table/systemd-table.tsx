import { t } from "@lingui/core/macro"
import { Trans } from "@lingui/react/macro"
import {
	type ColumnFiltersState,
	flexRender,
	getCoreRowModel,
	getFilteredRowModel,
	getSortedRowModel,
	type Row,
	type SortingState,
	type Table as TableType,
	useReactTable,
	type VisibilityState,
} from "@tanstack/react-table"
import { useVirtualizer, type VirtualItem } from "@tanstack/react-virtual"
import { ExternalLinkIcon, LoaderCircleIcon, RefreshCwIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldQuestionIcon } from "lucide-react"
import { listenKeys } from "nanostores"
import { memo, type ReactNode, useEffect, useMemo, useRef, useState } from "react"
import { getStatusColor, createSystemdTableCols } from "@/components/systemd-table/systemd-table-columns"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { pb } from "@/lib/api"
import { ServiceStatus, ServiceStatusLabels, type ServiceSubState, ServiceSubStateLabels } from "@/lib/enums"
import { $allSystemsById } from "@/lib/stores"
import { cn, decimalString, formatBytes, useBrowserStorage } from "@/lib/utils"
import type { SystemdRecord, SystemdServiceDetails, ServicePkgInfo, SystemdPackageMap, VulnScanData, ServiceVulnInfo, SystemdPackagesResponse } from "@/types"
import { Separator } from "../ui/separator"

export default function SystemdTable({ systemId }: { systemId?: string }) {
	const loadTime = Date.now()
	const [data, setData] = useState<SystemdRecord[]>([])
	const [pkgMap, setPkgMap] = useState<SystemdPackageMap | null>(null)
	const [vulnData, setVulnData] = useState<VulnScanData | null>(null)
	const [sorting, setSorting] = useBrowserStorage<SortingState>(
		`sort-sd-${systemId ? 1 : 0}`,
		[{ id: systemId ? "name" : "system", desc: false }],
		sessionStorage
	)
	const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
	const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
	const [globalFilter, setGlobalFilter] = useState("")
	const [vulnScanning, setVulnScanning] = useState(false)

	// clear old data when systemId changes
	useEffect(() => {
		setData([])
		setPkgMap(null)
		setVulnData(null)
	}, [systemId])

	// fetch package info and vulnerability data for services of this system
	useEffect(() => {
		if (!systemId) return
		pb.send<SystemdPackagesResponse>("/api/beszel/systemd/packages", { query: { system: systemId } })
			.then((resp) => {
				setPkgMap(resp.services ?? {})
				setVulnData(resp.vulns ?? null)
			})
			.catch(() => {
				setPkgMap({})
				setVulnData(null)
			})
	}, [systemId])

	useEffect(() => {
		const lastUpdated = data[0]?.updated ?? 0

		function fetchData(systemId?: string) {
			pb.collection<SystemdRecord>("systemd_services")
				.getList(0, 2000, {
					fields: "name,state,sub,cpu,cpuPeak,memory,memPeak,updated",
					filter: systemId ? pb.filter("system={:system}", { system: systemId }) : undefined,
				})
				.then(
					({ items }) =>
						items.length &&
						setData((curItems) => {
							const lastUpdated = Math.max(items[0].updated, items.at(-1)?.updated ?? 0)
							const systemdNames = new Set()
							const newItems: SystemdRecord[] = []
							for (const item of items) {
								if (Math.abs(lastUpdated - item.updated) < 70_000) {
									systemdNames.add(item.name)
									newItems.push(item)
								}
							}
							for (const item of curItems) {
								if (!systemdNames.has(item.name) && lastUpdated - item.updated < 70_000) {
									newItems.push(item)
								}
							}
							return newItems
						})
				)
		}

		// initial load
		fetchData(systemId)

		// if no systemId, pull system containers after every system update
		if (!systemId) {
			return $allSystemsById.listen((_value, _oldValue, systemId) => {
				// exclude initial load of systems
				if (Date.now() - loadTime > 500) {
					fetchData(systemId)
				}
			})
		}

		// if systemId, fetch containers after the system is updated
		return listenKeys($allSystemsById, [systemId], (_newSystems) => {
			// don't fetch data if the last update is less than 9.5 minutes
			if (lastUpdated > Date.now() - 9.5 * 60 * 1000) {
				return
			}
			fetchData(systemId)
		})
	}, [systemId])

	// recreate columns only when pkgMap or vulnData changes
	const columns = useMemo(() => createSystemdTableCols(systemId ? pkgMap : null, systemId ? vulnData : null), [systemId, pkgMap, vulnData])

	const table = useReactTable({
		data,
		columns,
		getCoreRowModel: getCoreRowModel(),
		getSortedRowModel: getSortedRowModel(),
		getFilteredRowModel: getFilteredRowModel(),
		onSortingChange: setSorting,
		onColumnFiltersChange: setColumnFilters,
		onColumnVisibilityChange: setColumnVisibility,
		defaultColumn: {
			sortUndefined: "last",
			size: 100,
			minSize: 0,
		},
		state: {
			sorting,
			columnFilters,
			columnVisibility,
			globalFilter,
		},
		onGlobalFilterChange: setGlobalFilter,
		globalFilterFn: (row, _columnId, filterValue) => {
			const service = row.original
			const systemName = $allSystemsById.get()[service.system]?.name ?? ""
			const name = service.name ?? ""
			const statusLabel = ServiceStatusLabels[service.state as ServiceStatus] ?? ""
			const subState = service.sub ?? ""
			const searchString = `${systemName} ${name} ${statusLabel} ${subState}`.toLowerCase()

			return (filterValue as string)
				.toLowerCase()
				.split(" ")
				.every((term) => searchString.includes(term))
		},
	})

	const rows = table.getRowModel().rows
	const visibleColumns = table.getVisibleLeafColumns()

	const statusTotals = useMemo(() => {
		const totals = [0, 0, 0, 0, 0, 0]
		for (const service of data) {
			totals[service.state]++
		}
		return totals
	}, [data])

	function triggerVulnScan() {
		if (!systemId || vulnScanning) return
		setVulnScanning(true)
		pb.send("/api/beszel/vulnerabilities/scan", { method: "POST", query: { system: systemId } })
			.then(() => {
				setTimeout(() => {
					pb.send<SystemdPackagesResponse>("/api/beszel/systemd/packages", { query: { system: systemId } })
						.then((resp) => {
							setPkgMap(resp.services ?? {})
							setVulnData(resp.vulns ?? null)
						})
						.finally(() => setVulnScanning(false))
				}, 5000)
			})
			.catch(() => setVulnScanning(false))
	}

	if (!data.length && !globalFilter) {
		return null
	}

	return (
		<Card className="@container w-full px-3 py-5 sm:py-6 sm:px-6">
			<CardHeader className="p-0 mb-3 sm:mb-4">
				<div className="grid md:flex gap-x-5 gap-y-3 w-full items-end">
					<div className="px-2 sm:px-1">
						<CardTitle className="mb-2">
							<Trans>Systemd Services</Trans>
						</CardTitle>
						<div className="text-sm text-muted-foreground flex items-center flex-wrap">
							<Trans>Total: {data.length}</Trans>
							<Separator orientation="vertical" className="h-4 mx-2 bg-primary/40" />
							<Trans>Failed: {statusTotals[ServiceStatus.Failed]}</Trans>
							<Separator orientation="vertical" className="h-4 mx-2 bg-primary/40" />
							<Trans>Updated every 10 minutes.</Trans>
						</div>
					</div>
					<div className="ms-auto flex items-center gap-2">
						{systemId && (
							<Button
								variant="outline"
								size="sm"
								className="h-9 gap-1.5 shrink-0"
								disabled={vulnScanning}
								onClick={triggerVulnScan}
								title={t`Scan for vulnerabilities`}
							>
								<RefreshCwIcon className={cn("size-3.5", vulnScanning && "animate-spin")} />
								<Trans>Vuln Scan</Trans>
							</Button>
						)}
						<Input
							placeholder={t`Filter...`}
							value={globalFilter}
							onChange={(e) => setGlobalFilter(e.target.value)}
							className="px-4 w-full max-w-full md:w-64"
						/>
					</div>
				</div>
			</CardHeader>
			<div className="rounded-md">
				<AllSystemdTable table={table} rows={rows} colLength={visibleColumns.length} systemId={systemId} />
			</div>
		</Card>
	)
}

const AllSystemdTable = memo(function AllSystemdTable({
	table,
	rows,
	colLength,
	systemId,
}: {
	table: TableType<SystemdRecord>
	rows: Row<SystemdRecord>[]
	colLength: number
	systemId?: string
}) {
	// The virtualizer will need a reference to the scrollable container element
	const scrollRef = useRef<HTMLDivElement>(null)
	const activeService = useRef<SystemdRecord | null>(null)
	const [sheetOpen, setSheetOpen] = useState(false)
	const openSheet = (service: SystemdRecord) => {
		activeService.current = service
		setSheetOpen(true)
	}

	const virtualizer = useVirtualizer<HTMLDivElement, HTMLTableRowElement>({
		count: rows.length,
		estimateSize: () => 54,
		getScrollElement: () => scrollRef.current,
		overscan: 5,
	})
	const virtualRows = virtualizer.getVirtualItems()

	const paddingTop = Math.max(0, virtualRows[0]?.start ?? 0 - virtualizer.options.scrollMargin)
	const paddingBottom = Math.max(0, virtualizer.getTotalSize() - (virtualRows[virtualRows.length - 1]?.end ?? 0))

	return (
		<div
			className={cn(
				"h-min max-h-[calc(100dvh-17rem)] max-w-full relative overflow-auto border rounded-md",
				// don't set min height if there are less than 2 rows, do set if we need to display the empty state
				(!rows.length || rows.length > 2) && "min-h-50"
			)}
			ref={scrollRef}
		>
			{/* add header height to table size */}
			<div style={{ height: `${virtualizer.getTotalSize() + 48}px`, paddingTop, paddingBottom }}>
				<table className="text-sm w-full h-full text-nowrap">
					<SystemdTableHead table={table} />
					<TableBody>
						{rows.length ? (
							virtualRows.map((virtualRow) => {
								const row = rows[virtualRow.index]
								return <SystemdTableRow key={row.id} row={row} virtualRow={virtualRow} openSheet={openSheet} />
							})
						) : (
							<TableRow>
								<TableCell colSpan={colLength} className="h-37 text-center pointer-events-none">
									<Trans>No results.</Trans>
								</TableCell>
							</TableRow>
						)}
					</TableBody>
				</table>
			</div>
			<SystemdSheet
				sheetOpen={sheetOpen}
				setSheetOpen={setSheetOpen}
				activeService={activeService}
				systemId={systemId}
			/>
		</div>
	)
})

function SystemdSheet({
	sheetOpen,
	setSheetOpen,
	activeService,
	systemId,
}: {
	sheetOpen: boolean
	setSheetOpen: (open: boolean) => void
	activeService: React.RefObject<SystemdRecord | null>
	systemId?: string
}) {
	const service = activeService.current
	const [details, setDetails] = useState<SystemdServiceDetails | null>(null)
	const [pkgInfo, setPkgInfo] = useState<ServicePkgInfo | null>(null)
	const [vulnInfo, setVulnInfo] = useState<ServiceVulnInfo | null>(null)
	const [vulnScannedAt, setVulnScannedAt] = useState<string | null>(null)
	const [isLoading, setIsLoading] = useState(false)
	const [error, setError] = useState<string | null>(null)

	useEffect(() => {
		if (!sheetOpen || !service) {
			return
		}

		setError(null)

		let cancelled = false
		setDetails(null)
		setPkgInfo(null)
		setVulnInfo(null)
		setVulnScannedAt(null)
		setIsLoading(true)

		pb.send<{ details: SystemdServiceDetails; pkg?: ServicePkgInfo; vuln?: ServiceVulnInfo; vulnScannedAt?: string }>(
			"/api/beszel/systemd/info",
			{
				query: {
					system: systemId,
					service: service.name,
				},
			}
		)
			.then(({ details, pkg, vuln, vulnScannedAt }) => {
				if (cancelled) return
				if (details) {
					setDetails(details)
					setPkgInfo(pkg ?? null)
					setVulnInfo(vuln ?? null)
					setVulnScannedAt(vulnScannedAt ?? null)
				} else {
					setDetails(null)
					setError(t`No results found.`)
				}
			})
			.catch((err) => {
				if (cancelled) return
				setError(err?.message ?? "Failed to load service details")
				setDetails(null)
			})
			.finally(() => {
				if (!cancelled) {
					setIsLoading(false)
				}
			})

		return () => {
			cancelled = true
		}
	}, [sheetOpen, service, systemId])

	if (!service) return null

	const statusLabel = ServiceStatusLabels[service.state as ServiceStatus] ?? ""
	const subStateLabel = ServiceSubStateLabels[service.sub as ServiceSubState] ?? ""

	const notAvailable = <span className="text-muted-foreground">N/A</span>

	const formatMemory = (value?: number | null) => {
		if (value === undefined || value === null) {
			return value === null ? t`Unlimited` : undefined
		}
		const { value: convertedValue, unit } = formatBytes(value, false, undefined, false)
		const digits = convertedValue >= 10 ? 1 : 2
		return `${decimalString(convertedValue, digits)} ${unit}`
	}

	const formatCpuTime = (ns?: number) => {
		if (!ns) return undefined
		const seconds = ns / 1_000_000_000
		if (seconds >= 3600) {
			const hours = Math.floor(seconds / 3600)
			const minutes = Math.floor((seconds % 3600) / 60)
			const secs = Math.floor(seconds % 60)
			return [hours ? `${hours}h` : null, minutes ? `${minutes}m` : null, secs ? `${secs}s` : null]
				.filter(Boolean)
				.join(" ")
		}
		if (seconds >= 60) {
			const minutes = Math.floor(seconds / 60)
			const secs = Math.floor(seconds % 60)
			return `${minutes}m ${secs}s`
		}
		if (seconds >= 1) {
			return `${decimalString(seconds, 2)}s`
		}
		return `${decimalString(seconds * 1000, 2)}ms`
	}

	const formatTasks = (current?: number, max?: number) => {
		const hasCurrent = typeof current === "number" && current >= 0
		const hasMax = typeof max === "number" && max > 0 && max !== null
		if (!hasCurrent && !hasMax) {
			return undefined
		}
		return (
			<>
				{hasCurrent ? current : notAvailable}
				{hasMax && <span className="text-muted-foreground ms-1.5">{`(${t`limit`}: ${max})`}</span>}
				{max === null && (
					<span className="text-muted-foreground ms-1.5">{`(${t`limit`}: ${t`Unlimited`.toLowerCase()})`}</span>
				)}
			</>
		)
	}

	const formatTimestamp = (timestamp?: number) => {
		if (!timestamp) return undefined
		// systemd timestamps are in microseconds, convert to milliseconds for JavaScript Date
		const date = new Date(timestamp / 1000)
		if (Number.isNaN(date.getTime())) return undefined
		return date.toLocaleString()
	}

	const activeStateValue = (() => {
		const stateText = details?.ActiveState
			? details.SubState
				? `${details.ActiveState} (${details.SubState})`
				: details.ActiveState
			: subStateLabel
				? `${statusLabel} (${subStateLabel})`
				: statusLabel

		for (const [index, status] of ServiceStatusLabels.entries()) {
			if (details?.ActiveState?.toLowerCase() === status.toLowerCase()) {
				service.state = index as ServiceStatus
				break
			}
		}

		return (
			<div className="flex items-center gap-2">
				<div className={cn("w-2 h-2 rounded-full flex-shrink-0", getStatusColor(service.state))} />
				{stateText}
			</div>
		)
	})()

	const statusTextValue = details?.Result

	const cpuTime = formatCpuTime(details?.CPUUsageNSec)
	const tasks = formatTasks(details?.TasksCurrent, details?.TasksMax)
	const memoryCurrent = formatMemory(details?.MemoryCurrent)
	const memoryPeak = formatMemory(details?.MemoryPeak)
	const memoryLimit = formatMemory(details?.MemoryLimit)
	const restartsValue = typeof details?.NRestarts === "number" ? details.NRestarts : undefined
	const mainPidValue = typeof details?.MainPID === "number" && details.MainPID > 0 ? details.MainPID : undefined
	const execMainPidValue =
		typeof details?.ExecMainPID === "number" && details.ExecMainPID > 0 && details.ExecMainPID !== details?.MainPID
			? details.ExecMainPID
			: undefined
	const activeEnterTimestamp = formatTimestamp(details?.ActiveEnterTimestamp)
	const activeExitTimestamp = formatTimestamp(details?.ActiveExitTimestamp)
	const inactiveEnterTimestamp = formatTimestamp(details?.InactiveEnterTimestamp)
	const execMainStartTimestamp = undefined // Property not available in current systemd interface

	// Build the version value (with package name in parens if different) for the service info table
	const versionValue: ReactNode | undefined = (() => {
		if (!pkgInfo) return undefined
		const { p: pkgName, v: version, s: svcName } = pkgInfo
		return (
			<div className="text-sm">
				<span className="font-mono">{version}</span>
				{pkgName && pkgName !== svcName && (
					<span className="text-xs text-muted-foreground ms-1.5">({pkgName})</span>
				)}
			</div>
		)
	})()

	const renderRow = (key: string, label: ReactNode, value?: ReactNode, alwaysShow = false) => {
		if (!alwaysShow && (value === undefined || value === null || value === "")) {
			return null
		}
		return (
			<tr key={key} className="border-b last:border-b-0">
				<td className="px-3 py-2 font-medium bg-muted dark:bg-muted/40 align-top w-35">{label}</td>
				<td className="px-3 py-2">{value ?? notAvailable}</td>
			</tr>
		)
	}

	const capitalize = (str: string) => `${str.charAt(0).toUpperCase()}${str.slice(1).toLowerCase()}`

	return (
		<Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
			<SheetContent className="w-full sm:max-w-220 p-6 overflow-y-auto">
				<SheetHeader className="p-0">
					<SheetTitle>
						<Trans>Service Details</Trans>
					</SheetTitle>
				</SheetHeader>
				<div className="grid gap-6">
					{isLoading && (
						<div className="flex items-center gap-2 text-sm text-muted-foreground">
							<LoaderCircleIcon className="size-4 animate-spin" />
							<Trans>Loading...</Trans>
						</div>
					)}
					{error && (
						<Alert className="border-destructive/50 text-destructive dark:border-destructive/60 dark:text-destructive">
							<AlertTitle>
								<Trans>Error</Trans>
							</AlertTitle>
							<AlertDescription>{error}</AlertDescription>
						</Alert>
					)}

					<div>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow("name", t`Name`, service.name, true)}
									{renderRow("version", t`Version`, versionValue)}
									{renderRow("description", t`Description`, details?.Description, true)}
									{renderRow("loadState", t`Load state`, details?.LoadState, true)}
									{renderRow(
										"bootState",
										t`Boot state`,
										<div className="flex items-center">
											{details?.UnitFileState}
											{details?.UnitFilePreset && (
												<span className="text-muted-foreground ms-1.5">(preset: {details?.UnitFilePreset})</span>
											)}
										</div>,
										true
									)}
									{renderRow("unitFile", t`Unit file`, details?.FragmentPath, true)}
									{renderRow("active", t`Active state`, activeStateValue, true)}
									{renderRow("status", t`Status`, statusTextValue, true)}
									{renderRow(
										"documentation",
										t`Documentation`,
										Array.isArray(details?.Documentation) && details.Documentation.length > 0
											? details.Documentation.join(", ")
											: undefined
									)}
								</tbody>
							</table>
						</div>
					</div>

					<div>
						<h3 className="text-sm font-medium mb-3">
							<Trans>Runtime Metrics</Trans>
						</h3>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow("mainPid", t`Main PID`, mainPidValue, true)}
									{renderRow("execMainPid", t`Exec main PID`, execMainPidValue)}
									{renderRow("tasks", t`Tasks`, tasks, true)}
									{renderRow("cpuTime", t`CPU time`, cpuTime)}
									{renderRow("memory", t`Memory`, memoryCurrent, true)}
									{renderRow("memoryPeak", capitalize(t`Memory Peak`), memoryPeak)}
									{renderRow("memoryLimit", t`Memory limit`, memoryLimit)}
									{renderRow("restarts", t`Restarts`, restartsValue, true)}
								</tbody>
							</table>
						</div>
					</div>

					<div className="hidden has-[tr]:block">
						<h3 className="text-sm font-medium mb-3">
							<Trans>Relationships</Trans>
						</h3>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow(
										"wants",
										t`Wants`,
										Array.isArray(details?.Wants) && details.Wants.length > 0 ? details.Wants.join(", ") : undefined
									)}
									{renderRow(
										"requires",
										t`Requires`,
										Array.isArray(details?.Requires) && details.Requires.length > 0
											? details.Requires.join(", ")
											: undefined
									)}
									{renderRow(
										"requiredBy",
										t`Required by`,
										Array.isArray(details?.RequiredBy) && details.RequiredBy.length > 0
											? details.RequiredBy.join(", ")
											: undefined
									)}
									{renderRow(
										"conflicts",
										t`Conflicts`,
										Array.isArray(details?.Conflicts) && details.Conflicts.length > 0
											? details.Conflicts.join(", ")
											: undefined
									)}
									{renderRow(
										"before",
										t`Before`,
										Array.isArray(details?.Before) && details.Before.length > 0 ? details.Before.join(", ") : undefined
									)}
									{renderRow(
										"after",
										t`After`,
										Array.isArray(details?.After) && details.After.length > 0 ? details.After.join(", ") : undefined
									)}
									{renderRow(
										"triggers",
										t`Triggers`,
										Array.isArray(details?.Triggers) && details.Triggers.length > 0
											? details.Triggers.join(", ")
											: undefined
									)}
									{renderRow(
										"triggeredBy",
										t`Triggered by`,
										Array.isArray(details?.TriggeredBy) && details.TriggeredBy.length > 0
											? details.TriggeredBy.join(", ")
											: undefined
									)}
								</tbody>
							</table>
						</div>
					</div>

					<div className="hidden has-[tr]:block">
						<h3 className="text-sm font-medium mb-3">
							<Trans>Lifecycle</Trans>
						</h3>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow("activeSince", t`Became active`, activeEnterTimestamp)}
									{service.state !== ServiceStatus.Active &&
										renderRow("lastActive", t`Exited active`, activeExitTimestamp)}
									{renderRow("inactiveSince", t`Became inactive`, inactiveEnterTimestamp)}
									{renderRow("execMainStart", t`Process started`, execMainStartTimestamp)}
									{/* {renderRow("invocationId", t`Invocation ID`, details?.InvocationID)} */}
									{/* {renderRow("freezerState", t`Freezer State`, details?.FreezerState)} */}
								</tbody>
							</table>
						</div>
					</div>

					{/* Vulnerability Scan Section */}
					<div>
						<h3 className="text-sm font-medium mb-3 flex items-center gap-2">
							{vulnInfo?.status === "vulnerable" ? (
								<ShieldAlertIcon className="size-4 text-red-500" />
							) : vulnInfo?.status === "safe" ? (
								<ShieldCheckIcon className="size-4 text-green-500" />
							) : (
								<ShieldQuestionIcon className="size-4 text-muted-foreground" />
							)}
							<Trans>Vulnerability Scan</Trans>
						</h3>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow(
										"vulnStatus",
										t`Status`,
										vulnInfo ? (
											vulnInfo.status === "vulnerable" ? (
												<span className="text-red-500 font-medium">{t`Vulnerabilities found`} ({vulnInfo.vulns?.length ?? 0})</span>
											) : (
												<span className="text-green-500">{t`Safe`}</span>
											)
										) : (
											<span className="text-muted-foreground">{t`Not scanned`}</span>
										),
										true
									)}
									{renderRow(
										"vulnScannedAt",
										t`Scanned at`,
										vulnScannedAt ? new Date(vulnScannedAt).toLocaleString() : undefined,
										true
									)}
								</tbody>
							</table>
						</div>
						{vulnInfo?.status === "vulnerable" && vulnInfo.vulns && vulnInfo.vulns.length > 0 && (
							<div className="mt-3 border rounded-md overflow-hidden">
								<table className="w-full text-sm">
									<thead>
										<tr className="border-b bg-muted dark:bg-muted/40">
											<th className="px-3 py-2 text-left font-medium">{t`Severity`}</th>
											<th className="px-3 py-2 text-left font-medium">{t`ID`}</th>
											<th className="px-3 py-2 text-left font-medium">{t`Summary`}</th>
										</tr>
									</thead>
									<tbody>
										{vulnInfo.vulns.map((v) => (
											<tr key={v.id} className="border-b last:border-b-0">
												<td className="px-3 py-2 whitespace-nowrap">
													<SeverityBadge score={v.score} severity={v.severity} />
												</td>
												<td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
													<a
														href={`https://osv.dev/vulnerability/${v.id}`}
														target="_blank"
														rel="noopener noreferrer"
														className="text-blue-500 hover:underline inline-flex items-center gap-1"
													>
														{v.id}
														<ExternalLinkIcon className="size-3" />
													</a>
												</td>
												<td className="px-3 py-2 text-xs">{v.summary || "—"}</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
					</div>

					<div className="hidden has-[tr]:block">
						<h3 className="text-sm font-medium mb-3">
							<Trans>Capabilities</Trans>
						</h3>
						<div className="border rounded-md">
							<table className="w-full text-sm">
								<tbody>
									{renderRow("canStart", t`Can start`, details?.CanStart ? t`Yes` : t`No`)}
									{renderRow("canStop", t`Can stop`, details?.CanStop ? t`Yes` : t`No`)}
									{renderRow("canReload", t`Can reload`, details?.CanReload ? t`Yes` : t`No`)}
									{/* {renderRow("refuseManualStart", t`Refuse Manual Start`, details?.RefuseManualStart ? t`Yes` : t`No`)}
									{renderRow("refuseManualStop", t`Refuse Manual Stop`, details?.RefuseManualStop ? t`Yes` : t`No`)} */}
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</SheetContent>
		</Sheet>
	)
}

function SystemdTableHead({ table }: { table: TableType<SystemdRecord> }) {
	return (
		<TableHeader className="sticky top-0 z-50 w-full border-b-2">
			{table.getHeaderGroups().map((headerGroup) => (
				<tr key={headerGroup.id}>
					{headerGroup.headers.map((header) => {
						return (
							<TableHead className="px-2" key={header.id}>
								{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
							</TableHead>
						)
					})}
				</tr>
			))}
		</TableHeader>
	)
}

const SystemdTableRow = memo(function SystemdTableRow({
	row,
	virtualRow,
	openSheet,
}: {
	row: Row<SystemdRecord>
	virtualRow: VirtualItem
	openSheet: (service: SystemdRecord) => void
}) {
	return (
		<TableRow
			data-state={row.getIsSelected() && "selected"}
			className="cursor-pointer transition-opacity"
			onClick={() => openSheet(row.original)}
		>
			{row.getVisibleCells().map((cell) => (
				<TableCell
					key={cell.id}
					className="py-0"
					style={{
						height: virtualRow.size,
					}}
				>
					{flexRender(cell.column.columnDef.cell, cell.getContext())}
				</TableCell>
			))}
		</TableRow>
	)
})

function SeverityBadge({ score, severity }: { score?: number; severity?: string }) {
	if (!score && !severity) {
		return <span className="text-xs text-muted-foreground">—</span>
	}

	const colors: Record<string, string> = {
		CRITICAL: "bg-red-600 text-white",
		HIGH: "bg-orange-500 text-white",
		MEDIUM: "bg-yellow-500 text-black",
		LOW: "bg-blue-400 text-white",
	}
	const colorClass = colors[severity ?? ""] ?? "bg-zinc-400 text-white"

	return (
		<span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold leading-none", colorClass)}>
			{score ? score.toFixed(1) : "?"} <span className="font-normal text-[10px] opacity-85">{severity ?? ""}</span>
		</span>
	)
}
