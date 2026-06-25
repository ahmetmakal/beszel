import { t } from "@lingui/core/macro"
import { Trans } from "@lingui/react/macro"
import AreaChartDefault from "@/components/charts/area-chart"
import { decimalString, toFixedFloat } from "@/lib/utils"
import type { ChartData, SystemStatsRecord } from "@/types"
import { pinnedAxisDomain } from "@/components/ui/chart"
import { cn } from "@/lib/utils"
import { ChartCard } from "../chart-card"

function ioWait({ stats }: SystemStatsRecord) {
	return stats?.cpub?.[2] ?? 0
}

function readAwait({ stats }: SystemStatsRecord) {
	return stats?.dios?.[3] ?? 0
}

function writeAwait({ stats }: SystemStatsRecord) {
	return stats?.dios?.[4] ?? 0
}

function StallStat({ label, value, unit, warn }: { label: string; value: number; unit: string; warn: boolean }) {
	return (
		<div className="rounded-md border bg-muted/20 px-3 py-2 min-w-[7rem]">
			<div className="text-xs text-muted-foreground mb-0.5">{label}</div>
			<div className={cn("text-lg font-semibold tabular-nums", warn && "text-amber-600 dark:text-amber-400")}>
				{decimalString(value, value >= 10 ? 1 : 2)}
				{unit}
			</div>
		</div>
	)
}

export function KvmHostIoCard({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const hasIoWait = chartData.systemStats.some((record) => ioWait(record) > 0)
	const hasAwait = chartData.systemStats.some((record) => readAwait(record) > 0 || writeAwait(record) > 0)
	if (!hasIoWait && !hasAwait) {
		return null
	}

	const latest = chartData.systemStats.at(-1)?.stats
	const currentIoWait = latest?.cpub?.[2] ?? 0
	const currentReadAwait = latest?.dios?.[3] ?? 0
	const currentWriteAwait = latest?.dios?.[4] ?? 0

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`Host I/O Stall Indicators`}
			description={t`CPU I/O wait and disk latency on the hypervisor — common KVM bottleneck signals`}
		>
			<div className="flex flex-wrap gap-2 mb-4">
				<StallStat label={t`I/O Wait`} value={currentIoWait} unit="%" warn={currentIoWait >= 10} />
				<StallStat label={t`Read await`} value={currentReadAwait} unit=" ms" warn={currentReadAwait >= 20} />
				<StallStat label={t`Write await`} value={currentWriteAwait} unit=" ms" warn={currentWriteAwait >= 20} />
			</div>
			<AreaChartDefault
				chartData={chartData}
				dataPoints={[
					{
						label: t`I/O Wait`,
						dataKey: ioWait,
						color: 4,
						opacity: 0.45,
					},
					{
						label: t`Write await`,
						dataKey: writeAwait,
						color: 2,
						opacity: 0.35,
					},
					{
						label: t`Read await`,
						dataKey: readAwait,
						color: 3,
						opacity: 0.35,
					},
				]}
				tickFormatter={(val) => `${toFixedFloat(val, val >= 10 ? 0 : 1)}`}
				contentFormatter={({ value, name }) => {
					if (String(name).toLowerCase().includes("i/o wait")) {
						return `${decimalString(value)}%`
					}
					return `${decimalString(value)} ms`
				}}
				domain={pinnedAxisDomain()}
				legend={true}
			/>
			<p className="text-xs text-muted-foreground mt-3">
				<Trans>High I/O wait or disk await often points to storage pressure affecting VMs on this host.</Trans>
			</p>
		</ChartCard>
	)
}
