import { t } from "@lingui/core/macro"
import { Trans } from "@lingui/react/macro"
import {
	type ColumnFiltersState,
	flexRender,
	getCoreRowModel,
	getFilteredRowModel,
	getSortedRowModel,
	type SortingState,
	useReactTable,
	type VisibilityState,
} from "@tanstack/react-table"
import { LoaderCircleIcon, XIcon } from "lucide-react"
import { listenKeys } from "nanostores"
import { useEffect, useState } from "react"
import { vmTableCols } from "@/components/vms-table/vms-table-columns"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { pb } from "@/lib/api"
import { $allSystemsById } from "@/lib/stores"
import { useBrowserStorage } from "@/lib/utils"
import type { LibvirtVMRecord } from "@/types"

export default function VMsTable({ systemId }: { systemId?: string }) {
	const loadTime = Date.now()
	const [data, setData] = useState<LibvirtVMRecord[] | undefined>(undefined)
	const [sorting, setSorting] = useBrowserStorage<SortingState>(
		`sort-v-${systemId ? 1 : 0}`,
		systemId ? [{ id: "disk_write", desc: true }] : [{ id: "name", desc: false }],
		sessionStorage
	)
	const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
	const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
	const [globalFilter, setGlobalFilter] = useState("")

	useEffect(() => {
		function fetchData(filterSystemId?: string) {
			pb.collection<LibvirtVMRecord>("libvirt_vms")
				.getList(0, 2000, {
					fields: "id,name,status,health,cpu,memory,memory_pct,net,net_rx,net_wx,disk,disk_read,disk_write,disk_iops,vcpus,mem_max,ip,bridge,uptime,disk_cap,system,updated",
					filter: filterSystemId ? pb.filter("system={:system}", { system: filterSystemId }) : undefined,
				})
				.then(({ items }) => {
					if (items.length === 0) {
						setData((cur) => (filterSystemId ? cur?.filter((item) => item.system !== filterSystemId) ?? [] : []))
						return
					}
					setData((cur) => {
						const lastUpdated = Math.max(items[0].updated, items.at(-1)?.updated ?? 0)
						const ids = new Set<string>()
						const newItems: LibvirtVMRecord[] = []
						for (const item of items) {
							if (Math.abs(lastUpdated - item.updated) < 70_000) {
								ids.add(item.id)
								newItems.push(item)
							}
						}
						for (const item of cur ?? []) {
							if (!ids.has(item.id) && lastUpdated - item.updated < 70_000) {
								newItems.push(item)
							}
						}
						return newItems
					})
				})
		}

		fetchData(systemId)
		if (!systemId) {
			return $allSystemsById.listen((_value, _old, id) => {
				if (Date.now() - loadTime > 500) fetchData(id)
			})
		}
		return listenKeys($allSystemsById, [systemId], () => fetchData(systemId))
	}, [systemId])

	const table = useReactTable({
		data: data ?? [],
		columns: vmTableCols,
		getCoreRowModel: getCoreRowModel(),
		getSortedRowModel: getSortedRowModel(),
		getFilteredRowModel: getFilteredRowModel(),
		onSortingChange: setSorting,
		onColumnFiltersChange: setColumnFilters,
		onColumnVisibilityChange: setColumnVisibility,
		state: { sorting, columnFilters, columnVisibility, globalFilter },
		onGlobalFilterChange: setGlobalFilter,
		globalFilterFn: (row, _columnId, filterValue) => {
			const vm = row.original
			const search = `${vm.name} ${vm.status} ${vm.id} ${vm.ip ?? ""} ${vm.bridge ?? ""}`.toLowerCase()
			return (filterValue as string).toLowerCase().split(" ").every((term) => search.includes(term))
		},
	})

	const rows = table.getRowModel().rows

	return (
		<Card className="@container w-full px-3 py-5 sm:py-6 sm:px-6">
			<CardHeader className="p-0 mb-3 sm:mb-4">
				<div className="grid md:flex gap-x-5 gap-y-3 w-full items-end">
					<div className="px-2 sm:px-1">
						<CardTitle className="mb-2">
							<Trans>Virtual Machines</Trans>
						</CardTitle>
						<CardDescription>
							<Trans>Libvirt/KVM virtual machines on this host.</Trans>
						</CardDescription>
					</div>
					<div className="relative ms-auto w-full max-w-full md:w-64">
						<Input
							placeholder={t`Filter...`}
							value={globalFilter}
							onChange={(e) => setGlobalFilter(e.target.value)}
							className="ps-4 pe-10 w-full"
						/>
						{globalFilter && (
							<Button
								type="button"
								variant="ghost"
								size="icon"
								aria-label={t`Clear`}
								className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 text-muted-foreground"
								onClick={() => setGlobalFilter("")}
							>
								<XIcon className="h-4 w-4" />
							</Button>
						)}
					</div>
				</div>
			</CardHeader>
			<div className="rounded-md border overflow-auto max-h-[calc(100dvh-17rem)]">
				<table className="text-sm w-full text-nowrap">
					<TableHeader>
						{table.getHeaderGroups().map((headerGroup) => (
							<TableRow key={headerGroup.id}>
								{headerGroup.headers.map((header) => (
									<TableHead key={header.id}>
										{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
									</TableHead>
								))}
							</TableRow>
						))}
					</TableHeader>
					<TableBody>
						{rows.length ? (
							rows.map((row) => (
								<TableRow key={row.id}>
									{row.getVisibleCells().map((cell) => (
										<TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
									))}
								</TableRow>
							))
						) : (
							<TableRow>
								<TableCell colSpan={vmTableCols.length} className="h-37 text-center">
									{data ? <Trans>No results.</Trans> : <LoaderCircleIcon className="animate-spin size-10 opacity-60 mx-auto" />}
								</TableCell>
							</TableRow>
						)}
					</TableBody>
				</table>
			</div>
		</Card>
	)
}
