import { t } from "@lingui/core/macro"
import { useMemo } from "react"
import AreaChartDefault, { type DataPoint } from "@/components/charts/area-chart"
import { decimalString, formatBytes, toFixedFloat } from "@/lib/utils"
import type { ChartData, SystemStatsRecord } from "@/types"
import { ChartCard } from "../chart-card"

type VMMetric = "cpu" | "mem"

/**
 * Scans all systemStats records, finds the top N libvirt VM names by average metric,
 * and returns dataPoints that read directly from systemStats.
 */
function useTopLibvirtDataPoints(chartData: ChartData, metric: VMMetric, topN = 10) {
	return useMemo(() => {
		const totals = new Map<string, { sum: number; count: number }>()

		for (const record of chartData.systemStats) {
			const vms = record.stats?.tlv
			if (!vms) continue
			for (const vm of vms) {
				if (!vm.n) continue
				const value = metric === "cpu" ? vm.c : vm.m
				if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) continue
				const entry = totals.get(vm.n)
				if (entry) {
					entry.sum += value
					entry.count++
				} else {
					totals.set(vm.n, { sum: value, count: 1 })
				}
			}
		}

		const topNames = [...totals.entries()]
			.sort((a, b) => b[1].sum / b[1].count - a[1].sum / a[1].count)
			.slice(0, topN)
			.map(([name]) => name)

		const dataPoints: DataPoint<SystemStatsRecord>[] = topNames.map((name, i) => ({
			label: name,
			dataKey: ({ stats }: SystemStatsRecord) => {
				const vms = stats?.tlv
				if (!vms) return null
				let total = 0
				let found = false
				for (const vm of vms) {
					if (vm.n === name) {
						total += metric === "cpu" ? vm.c : vm.m
						found = true
					}
				}
				return found ? total : null
			},
			color: `hsl(${(i * 41 + 180) % 360} var(--chart-saturation) var(--chart-lightness))`,
			opacity: 0.16,
			strokeOpacity: 0.95,
			activeDot: false,
		}))

		return { dataPoints, hasData: topNames.length > 0 }
	}, [chartData.systemStats, metric])
}

export function TopLibvirtCpuChart({
	chartData,
	grid,
	dataEmpty,
}: { chartData: ChartData; grid: boolean; dataEmpty: boolean }) {
	const { dataPoints, hasData } = useTopLibvirtDataPoints(chartData, "cpu")

	if (!hasData) return null

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`Top VMs (CPU)`}
			description={t`Top 10 libvirt VMs by average CPU usage`}
			legend={true}
		>
			<AreaChartDefault
				chartData={chartData}
				dataPoints={dataPoints}
				tickFormatter={(val) => `${toFixedFloat(val, 2)}%`}
				contentFormatter={({ value }) => `${decimalString(value)}%`}
				domain={[0, "auto"]}
				legend={true}
				itemSorter={(a, b) => b.value - a.value}
			/>
		</ChartCard>
	)
}

export function TopLibvirtMemoryChart({
	chartData,
	grid,
	dataEmpty,
}: { chartData: ChartData; grid: boolean; dataEmpty: boolean }) {
	const { dataPoints, hasData } = useTopLibvirtDataPoints(chartData, "mem")

	if (!hasData) return null

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`Top VMs (Memory)`}
			description={t`Top 10 libvirt VMs by average memory usage`}
			legend={true}
		>
			<AreaChartDefault
				chartData={chartData}
				dataPoints={dataPoints}
				tickFormatter={(val) => `${toFixedFloat(val, 2)}%`}
				contentFormatter={(item, key) => {
					const pct = `${decimalString(item.value)}%`
					const vms = item?.payload?.stats?.tlv
					if (!vms) return pct
					let rss = 0
					for (const vm of vms) {
						if (vm.n === key && vm.r) rss += vm.r
					}
					if (!rss) return pct
					const f = formatBytes(rss, false, undefined, false)
					return `${pct} (${f.value.toFixed(1)} ${f.unit})`
				}}
				domain={[0, "auto"]}
				legend={true}
				itemSorter={(a, b) => b.value - a.value}
			/>
		</ChartCard>
	)
}
