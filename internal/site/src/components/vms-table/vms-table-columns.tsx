import type { ComponentType } from "react"
import type { Column, ColumnDef } from "@tanstack/react-table"
import { t } from "@lingui/core/macro"
import { Button } from "@/components/ui/button"
import { cn, decimalString, formatBytes } from "@/lib/utils"
import type { LibvirtVMRecord } from "@/types"
import { ContainerHealth, ContainerHealthLabels } from "@/lib/enums"
import { Badge } from "../ui/badge"
import { CpuIcon, HardDriveIcon, MemoryStickIcon, ServerIcon, ShieldCheckIcon } from "lucide-react"
import { EthernetIcon } from "../ui/icons"

export const vmTableCols: ColumnDef<LibvirtVMRecord>[] = [
	{
		id: "name",
		sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
		accessorFn: (record) => record.name,
		header: ({ column }) => <HeaderButton column={column} name={t`Name`} Icon={ServerIcon} />,
		cell: ({ getValue }) => <span className="ms-1.5 xl:w-48 block truncate">{getValue() as string}</span>,
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
		id: "net",
		accessorFn: (record) => record.net,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Net`} Icon={EthernetIcon} />,
		cell: ({ getValue }) => {
			const formatted = formatBytes(getValue() as number, true, undefined, false)
			return (
				<div className="ms-1 tabular-nums">{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}</div>
			)
		},
	},
	{
		id: "disk",
		accessorFn: (record) => record.disk,
		invertSorting: true,
		header: ({ column }) => <HeaderButton column={column} name={t`Disk I/O`} Icon={HardDriveIcon} />,
		cell: ({ getValue }) => {
			const formatted = formatBytes(getValue() as number, true, undefined, false)
			return (
				<div className="ms-1 tabular-nums">{`${decimalString(formatted.value, formatted.value >= 10 ? 1 : 2)} ${formatted.unit}`}</div>
			)
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
		id: "status",
		accessorFn: (record) => record.status,
		header: ({ column }) => <HeaderButton column={column} name={t`Status`} Icon={ServerIcon} />,
		cell: ({ getValue }) => <span className="ms-1 capitalize">{getValue() as string}</span>,
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
