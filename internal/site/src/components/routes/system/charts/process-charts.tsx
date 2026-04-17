import { t } from "@lingui/core/macro"
import { useMemo } from "react"
import AreaChartDefault, { type DataPoint } from "@/components/charts/area-chart"
import { decimalString, formatBytes, toFixedFloat } from "@/lib/utils"
import type { ChartData, SystemStatsRecord } from "@/types"
import { ChartCard } from "../chart-card"

type ProcessMetric = "cpu" | "mem"

/**
 * Scans all systemStats records, finds the top N process names by average metric,
 * and returns dataPoints that read directly from systemStats (no custom data needed).
 */
function useTopProcessDataPoints(chartData: ChartData, metric: ProcessMetric, topN = 10) {
	return useMemo(() => {
		const totals = new Map<string, { sum: number; count: number }>()

		for (const record of chartData.systemStats) {
			const procs = record.stats?.tp
			if (!procs) continue
			for (const proc of procs) {
				if (!proc.n) continue
				const value = metric === "cpu" ? proc.c : proc.m
				if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) continue
				const entry = totals.get(proc.n)
				if (entry) {
					entry.sum += value
					entry.count++
				} else {
					totals.set(proc.n, { sum: value, count: 1 })
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
				const procs = stats?.tp
				if (!procs) return null
				let total = 0
				let found = false
				for (const p of procs) {
					if (p.n === name) {
						total += metric === "cpu" ? p.c : p.m
						found = true
					}
				}
				return found ? total : null
			},
			color: `hsl(${(i * 41) % 360} var(--chart-saturation) var(--chart-lightness))`,
			opacity: 0.16,
			strokeOpacity: 0.95,
			activeDot: false,
		}))

		return { dataPoints, hasData: topNames.length > 0 }
	}, [chartData.systemStats, metric])
}

export function TopProcessesCpuChart({
	chartData,
	grid,
	dataEmpty,
}: { chartData: ChartData; grid: boolean; dataEmpty: boolean }) {
	const { dataPoints, hasData } = useTopProcessDataPoints(chartData, "cpu")

	if (!hasData) return null

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`Top Processes (CPU)`}
			description={t`Top 10 processes by average CPU usage`}
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

export function TopProcessesMemoryChart({
	chartData,
	grid,
	dataEmpty,
}: { chartData: ChartData; grid: boolean; dataEmpty: boolean }) {
	const { dataPoints, hasData } = useTopProcessDataPoints(chartData, "mem")

	if (!hasData) return null

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`Top Processes (Memory)`}
			description={t`Top 10 processes by average memory usage`}
			legend={true}
		>
			<AreaChartDefault
				chartData={chartData}
				dataPoints={dataPoints}
				tickFormatter={(val) => `${toFixedFloat(val, 2)}%`}
				contentFormatter={(item, key) => {
					const pct = `${decimalString(item.value)}%`
					// Try to show RSS from the current data point
					const procs = item?.payload?.stats?.tp
					if (!procs) return pct
					let rss = 0
					for (const p of procs) {
						if (p.n === key && p.r) rss += p.r
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
