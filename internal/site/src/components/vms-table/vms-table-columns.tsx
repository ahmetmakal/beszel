import type { ComponentType } from "react"
import type { Column, ColumnDef } from "@tanstack/react-table"
import { t } from "@lingui/core/macro"
import { Button } from "@/components/ui/button"
import { cn, decimalString, formatBytes } from "@/lib/utils"
import type { LibvirtVMRecord } from "@/types"
import { ContainerHealth, ContainerHealthLabels } from "@/lib/enums"
import { Badge } from "../ui/badge"
import {
	CpuIcon,
	GaugeIcon,
	HardDriveIcon,
	MemoryStickIcon,
	ServerIcon,
	ShieldCheckIcon,
	ClockIcon,
	GlobeIcon,
} from "lucide-react"
import { EthernetIcon } from "../ui/icons"

function formatRateBytes(val: number) {
	const f = formatBytes(val, true, undefined, false)
	return `${decimalString(f.value, f.value >= 10 ? 1 : 2)} ${f.unit}`
}

function formatUptime(seconds: number) {
	if (!seconds || seconds <= 0) return "—"
	const d = Math.floor(seconds / 86400)
	const h = Math.floor((seconds % 86400) / 3600)
	const m = Math.floor((seconds % 3600) / 60)
	if (d > 0) return `${d}d ${h}h`
	if (h > 0) return `${h}h ${m}m`
	return `${m}m`
}

export const vmTableCols: ColumnDef<LibvirtVMRecord>[] = [
	{
		id: "name",
		sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
		accessorFn: (record) => record.name,
		header: ({ column }) => <HeaderButton column={column} name={t`Name`} Icon={ServerIcon} />,
		cell: ({ getValue }) => <span className="ms-1.5 xl:w-40 block truncate">{getValue() as string}</span>,
	},
	{
		id: "status",
		accessorFn: (record) => record.status,
		header: ({ column }) => <HeaderButton column={column} name={t`Status`} Icon={ServerIcon} />,
		cell: ({ getValue }) => {
			const status = getValue() as string
			const blocked = status === "blocked"
			return (
				<span
					className={cn(
						"ms-1 capitalize",
						blocked && "text-amber-600 dark:text-amber-400 font-medium"
					)}
				>
					{status}
				</span>
			)
		},
	},
	{
		id: "health",
		invertSorting: true,
		accessorFn: (record) => record.health,
		header: ({ column }) => <HeaderButton column={column} name={t`Health`} Icon={ShieldCheckIcon} />,
		cell: ({ getValue }) => {
			const healthValue = getValue() as number
			const healthStatus = ContainerHealthLabels[healthValue] || "Unknown"
			return (
				<Badge variant="outline" className="dark:border-white/12">
					<span
						className={cn("size-2 me-1.5 rounded-full", {
							"bg-green-500": healthValue === ContainerHealth.Healthy,
							"bg-red-500": healthValue === ContainerHealth.Unhealthy,
							"bg-yellow-500": healthValue === ContainerHealth.Starting,
							"bg-zinc-500": healthValue === ContainerHealth.None,
						})}
					></span>
					{healthStatus}
				</Badge>
			)
		},
	},
	{
		id: "cpu",
		accessorFn: (record) => record.cpu,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`CPU`} Icon={CpuIcon} />,
		cell: ({ getValue }) => {
			const val = getValue() as number
			return <span className="ms-1 tabular-nums">{`${decimalString(val, val >= 10 ? 1 : 2)}%`}</span>
		},
	},
	{
		id: "vcpus",
		accessorFn: (record) => record.vcpus,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`vCPUs`} Icon={CpuIcon} />,
		cell: ({ getValue }) => <span className="ms-1 tabular-nums">{getValue() as number}</span>,
	},
	{
		id: "memory",
		accessorFn: (record) => record.memory,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Memory`} Icon={MemoryStickIcon} />,
		cell: ({ getValue, row }) => {
			const val = getValue() as number
			const formatted = formatBytes(val, false, undefined, true)
			const max = row.original.mem_max
			if (max > 0) {
				const maxFmt = formatBytes(max, false, undefined, true)
				return (
					<span className="ms-1 tabular-nums">
						{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}
						<span className="text-muted-foreground">{` / ${decimalString(maxFmt.value, 1)} ${maxFmt.unit}`}</span>
					</span>
				)
			}
			return (
				<span className="ms-1 tabular-nums">{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}</span>
			)
		},
	},
	{
		id: "memory_pct",
		accessorFn: (record) => {
			if (record.memory_pct && record.memory_pct > 0) return record.memory_pct
			if (record.mem_max > 0 && record.memory > 0) {
				return (record.memory / record.mem_max) * 100
			}
			return 0
		},
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Mem %`} Icon={GaugeIcon} />,
		cell: ({ getValue }) => {
			const val = getValue() as number
			return <span className="ms-1 tabular-nums">{val > 0 ? `${decimalString(val, val >= 10 ? 1 : 2)}%` : "—"}</span>
		},
	},
	{
		id: "net_rx",
		accessorFn: (record) => record.net_rx ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Net ↓`} Icon={EthernetIcon} />,
		cell: ({ getValue }) => <div className="ms-1 tabular-nums">{formatRateBytes(getValue() as number)}</div>,
	},
	{
		id: "net_wx",
		accessorFn: (record) => record.net_wx ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Net ↑`} Icon={EthernetIcon} />,
		cell: ({ getValue }) => <div className="ms-1 tabular-nums">{formatRateBytes(getValue() as number)}</div>,
	},
	{
		id: "disk_io",
		accessorFn: (record) => record.disk ?? (record.disk_read ?? 0) + (record.disk_write ?? 0),
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Disk I/O`} Icon={HardDriveIcon} />,
		cell: ({ getValue }) => <div className="ms-1 tabular-nums">{formatRateBytes(getValue() as number)}</div>,
	},
	{
		id: "disk_write",
		accessorFn: (record) => record.disk_write ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Disk W`} Icon={HardDriveIcon} />,
		cell: ({ getValue }) => <div className="ms-1 tabular-nums">{formatRateBytes(getValue() as number)}</div>,
	},
	{
		id: "disk_iops",
		accessorFn: (record) => record.disk_iops ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`IOPS`} Icon={HardDriveIcon} />,
		cell: ({ getValue }) => {
			const val = getValue() as number
			return <div className="ms-1 tabular-nums">{val > 0 ? decimalString(val, val >= 100 ? 0 : 1) : "—"}</div>
		},
	},
	{
		id: "ip",
		accessorFn: (record) => record.ip ?? "",
		header: ({ column }) => <HeaderButton column={column} name={t`IP`} Icon={GlobeIcon} />,
		cell: ({ getValue }) => <span className="ms-1 font-mono text-xs">{getValue() as string || "—"}</span>,
	},
	{
		id: "bridge",
		accessorFn: (record) => record.bridge ?? "",
		header: ({ column }) => <HeaderButton column={column} name={t`Bridge`} Icon={EthernetIcon} />,
		cell: ({ getValue }) => <span className="ms-1">{getValue() as string || "—"}</span>,
	},
	{
		id: "uptime",
		accessorFn: (record) => record.uptime ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Uptime`} Icon={ClockIcon} />,
		cell: ({ getValue }) => <span className="ms-1 tabular-nums">{formatUptime(getValue() as number)}</span>,
	},
	{
		id: "disk_cap",
		accessorFn: (record) => record.disk_cap ?? 0,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Disk`} Icon={HardDriveIcon} />,
		cell: ({ getValue }) => {
			const gb = getValue() as number
			if (gb <= 0) return <span className="ms-1">—</span>
			return <span className="ms-1 tabular-nums">{`${decimalString(gb, gb >= 10 ? 1 : 2)} GB`}</span>
		},
	},
]

function HeaderButton({
	column,
	name,
	Icon,
}: {
	column: Column<LibvirtVMRecord>
	name: string
	Icon: ComponentType<{ className?: string }>
}) {
	return (
		<Button variant="ghost" className="px-1.5 -ms-1.5 h-8" onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}>
			<Icon className="size-3.5 me-1.5 opacity-70" />
			{name}
		</Button>
	)
}
