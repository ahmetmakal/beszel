import type { Column, ColumnDef } from "@tanstack/react-table"
import { Button } from "@/components/ui/button"
import { cn, decimalString, formatBytes, hourWithSeconds } from "@/lib/utils"
import type { SystemdRecord, SystemdPackageMap, ServiceVulnInfo, VulnScanData } from "@/types"
import { ServiceStatus, ServiceStatusLabels, ServiceSubState, ServiceSubStateLabels } from "@/lib/enums"
import {
	ActivityIcon,
	ArrowUpDownIcon,
	ClockIcon,
	CpuIcon,
	MemoryStickIcon,
	ShieldCheckIcon,
	ShieldAlertIcon,
	ShieldQuestionIcon,
	TerminalSquareIcon,
} from "lucide-react"
import { Badge } from "../ui/badge"
import { t } from "@lingui/core/macro"

function getSubStateColor(subState: ServiceSubState) {
	switch (subState) {
		case ServiceSubState.Running:
			return "bg-green-500"
		case ServiceSubState.Failed:
			return "bg-red-500"
		case ServiceSubState.Dead:
			return "bg-yellow-500"
		default:
			return "bg-zinc-500"
	}
}

/** Creates systemd table column definitions. Pass pkgMap to populate the version column. */
export function createSystemdTableCols(pkgMap: SystemdPackageMap | null, vulnData?: VulnScanData | null): ColumnDef<SystemdRecord>[] {
	return [
		{
			id: "name",
			sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
			accessorFn: (record) => record.name,
			header: ({ column }) => <HeaderButton column={column} name={t`Name`} Icon={TerminalSquareIcon} />,
			cell: ({ getValue }) => {
				return <span className="ms-1.5 xl:w-50 block truncate">{getValue() as string}</span>
			},
		},
		{
			id: "version",
			accessorFn: (record) => pkgMap?.[record.name]?.version ?? "",
			header: ({ column }) => <HeaderButton column={column} name={t`Version`} Icon={TerminalSquareIcon} />,
			cell: ({ row }) => {
				const svcName = row.original.name
				const info = pkgMap?.[svcName]

				if (pkgMap === null) {
					return <span className="ms-1.5 text-muted-foreground text-xs">…</span>
				}
				if (!info) {
					return <span className="ms-1.5 text-muted-foreground text-xs">—</span>
				}

				const svcVuln = vulnData?.services?.[svcName]

				return (
					<div className="ms-1.5 flex items-center gap-1.5">
						<span>
							<span className="text-xs font-mono">{info.version}</span>
							{info.pkgName && info.pkgName !== svcName && (
								<span className="text-xs text-muted-foreground ms-1">({info.pkgName})</span>
							)}
						</span>
						<VulnBadge svcVuln={svcVuln} hasVulnData={!!vulnData} />
					</div>
				)
			},
		},
		{
			id: "state",
			accessorFn: (record) => record.state,
			header: ({ column }) => <HeaderButton column={column} name={t`State`} Icon={ActivityIcon} />,
			cell: ({ getValue }) => {
				const statusValue = getValue() as ServiceStatus
				const statusLabel = ServiceStatusLabels[statusValue] || "Unknown"
				return (
					<Badge variant="outline" className="dark:border-white/12">
						<span className={cn("size-2 me-1.5 rounded-full", getStatusColor(statusValue))} />
						{statusLabel}
					</Badge>
				)
			},
		},
		{
			id: "sub",
			accessorFn: (record) => record.sub,
			header: ({ column }) => <HeaderButton column={column} name={t`Sub State`} Icon={ActivityIcon} />,
			cell: ({ getValue }) => {
				const subState = getValue() as ServiceSubState
				const subStateLabel = ServiceSubStateLabels[subState] || "Unknown"
				return (
					<Badge variant="outline" className="dark:border-white/12 text-xs capitalize">
						<span className={cn("size-2 me-1.5 rounded-full", getSubStateColor(subState))} />
						{subStateLabel}
					</Badge>
				)
			},
		},
		{
			id: "cpu",
			accessorFn: (record) => {
				if (record.sub !== ServiceSubState.Running) {
					return -1
				}
				return record.cpu
			},
			invertSorting: true,
			header: ({ column }) => <HeaderButton column={column} name={`${t`CPU`} (10m)`} Icon={CpuIcon} />,
			cell: ({ getValue }) => {
				const val = getValue() as number
				if (val < 0) {
					return <span className="ms-1.5 text-muted-foreground">N/A</span>
				}
				return <span className="ms-1.5 tabular-nums">{`${decimalString(val, val >= 10 ? 1 : 2)}%`}</span>
			},
		},
		{
			id: "cpuPeak",
			accessorFn: (record) => {
				if (record.sub !== ServiceSubState.Running) {
					return -1
				}
				return record.cpuPeak ?? 0
			},
			invertSorting: true,
			header: ({ column }) => <HeaderButton column={column} name={t`CPU Peak`} Icon={CpuIcon} />,
			cell: ({ getValue }) => {
				const val = getValue() as number
				if (val < 0) {
					return <span className="ms-1.5 text-muted-foreground">N/A</span>
				}
				return <span className="ms-1.5 tabular-nums">{`${decimalString(val, val >= 10 ? 1 : 2)}%`}</span>
			},
		},
		{
			id: "memory",
			accessorFn: (record) => record.memory,
			invertSorting: true,
			header: ({ column }) => <HeaderButton column={column} name={t`Memory`} Icon={MemoryStickIcon} />,
			cell: ({ getValue }) => {
				const val = getValue() as number
				if (!val) {
					return <span className="ms-1.5 text-muted-foreground">N/A</span>
				}
				const formatted = formatBytes(val, false, undefined, false)
				return (
					<span className="ms-1.5 tabular-nums">{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}</span>
				)
			},
		},
		{
			id: "memPeak",
			accessorFn: (record) => record.memPeak,
			invertSorting: true,
			header: ({ column }) => <HeaderButton column={column} name={t`Memory Peak`} Icon={MemoryStickIcon} />,
			cell: ({ getValue }) => {
				const val = getValue() as number
				if (!val) {
					return <span className="ms-1.5 text-muted-foreground">N/A</span>
				}
				const formatted = formatBytes(val, false, undefined, false)
				return (
					<span className="ms-1.5 tabular-nums">{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}</span>
				)
			},
		},
		{
			id: "updated",
			invertSorting: true,
			accessorFn: (record) => record.updated,
			header: ({ column }) => <HeaderButton column={column} name={t`Updated`} Icon={ClockIcon} />,
			cell: ({ getValue }) => {
				const timestamp = getValue() as number
				return (
					<span className="ms-1.5 tabular-nums">
						{hourWithSeconds(new Date(timestamp).toISOString())}
					</span>
				)
			},
		},
	]
}

// Keep backward-compatible export for any existing usages
export const systemdTableCols = createSystemdTableCols(null)

function VulnBadge({ svcVuln, hasVulnData }: { svcVuln?: ServiceVulnInfo; hasVulnData: boolean }) {
	if (!hasVulnData || !svcVuln) {
		return (
			<span className="shrink-0" title={t`Not scanned`}>
				<ShieldQuestionIcon className="size-3.5 text-muted-foreground" />
			</span>
		)
	}
	if (svcVuln.status === "vulnerable" && svcVuln.vulns?.length) {
		const maxVuln = svcVuln.vulns.reduce((best, v) => ((v.score ?? 0) > (best.score ?? 0) ? v : best), svcVuln.vulns[0])
		const score = maxVuln.score
		const sev = maxVuln.severity
		const colorClass = sev === "CRITICAL" ? "text-red-600" : sev === "HIGH" ? "text-orange-500" : sev === "MEDIUM" ? "text-yellow-600" : sev === "LOW" ? "text-blue-500" : "text-red-500"

		return (
			<span className={cn("inline-flex items-center gap-0.5 shrink-0 font-semibold", colorClass)} title={`${svcVuln.vulns.length} vuln – ${score ? score.toFixed(1) : "?"} ${sev ?? ""}`}>
				<ShieldAlertIcon className="size-3.5" />
				<span className="text-[10px]">{score ? score.toFixed(1) : svcVuln.vulns.length}</span>
			</span>
		)
	}
	return (
		<span className="shrink-0" title={t`Safe`}>
			<ShieldCheckIcon className="size-3.5 text-green-500" />
		</span>
	)
}

function HeaderButton({ column, name, Icon }: { column: Column<SystemdRecord>; name: string; Icon: React.ElementType }) {
	const isSorted = column.getIsSorted()
	return (
		<Button
			className={cn("h-9 px-3 flex items-center gap-2 duration-50", isSorted && "bg-accent/70 light:bg-accent text-accent-foreground/90")}
			variant="ghost"
			onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
		>
			{Icon && <Icon className="size-4" />}
			{name}
			<ArrowUpDownIcon className="size-4" />
		</Button>
	)
}

export function getStatusColor(status: ServiceStatus) {
	switch (status) {
		case ServiceStatus.Active:
			return "bg-green-500"
		case ServiceStatus.Failed:
			return "bg-red-500"
		case ServiceStatus.Reloading:
		case ServiceStatus.Activating:
		case ServiceStatus.Deactivating:
			return "bg-yellow-500"
		default:
			return "bg-zinc-500"
	}
}
