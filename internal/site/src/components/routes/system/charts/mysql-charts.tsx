import { t } from "@lingui/core/macro"
import type { ChartData } from "@/types"
import { ChartCard } from "../chart-card"
import LineChartDefault from "@/components/charts/line-chart"
import { toFixedFloat, decimalString } from "@/lib/utils"

export function MySQLQueriesChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	if (!lastStats?.mysql) {
		return null
	}

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`MySQL Queries & Connections`}
			description={t`Query rate and connection usage`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => decimalString(item.value)}
				tickFormatter={(value) => String(toFixedFloat(value, 0))}
				legend={true}
				dataPoints={[
					{
						label: t`Queries/sec`,
						color: "hsl(142, 71%, 45%)",
						dataKey: ({ stats }) => stats?.mysql?.qps,
					},
					{
						label: t`Connections`,
						color: "hsl(217, 91%, 60%)",
						dataKey: ({ stats }) => stats?.mysql?.conn,
					},
					{
						label: t`Threads Running`,
						color: "hsl(25, 95%, 53%)",
						dataKey: ({ stats }) => stats?.mysql?.tr,
					},
					{
						label: t`Slow Queries/sec`,
						color: "hsl(0, 84%, 60%)",
						dataKey: ({ stats }) => stats?.mysql?.sq,
					},
				]}
			/>
		</ChartCard>
	)
}

export function MySQLCacheChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	if (!lastStats?.mysql) {
		return null
	}

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`MySQL Cache Performance`}
			description={t`Buffer pool and key cache hit rates`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => `${decimalString(item.value)}%`}
				tickFormatter={(value) => `${toFixedFloat(value, 0)}%`}
				domain={[0, 100]}
				legend={true}
				dataPoints={[
					{
						label: t`Buffer Pool Hit Rate`,
						color: "hsl(142, 71%, 45%)",
						dataKey: ({ stats }) => stats?.mysql?.bphr,
					},
					{
						label: t`Key Cache Hit Rate`,
						color: "hsl(217, 91%, 60%)",
						dataKey: ({ stats }) => stats?.mysql?.kchr,
					},
				]}
			/>
		</ChartCard>
	)
}

export function MySQLReplicationChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	// Only show if replication is configured (lag >= 0)
	if (!lastStats?.mysql || lastStats.mysql.rl < 0) {
		return null
	}

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`MySQL Replication`}
			description={t`Replication lag in seconds`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => `${decimalString(item.value)}s`}
				tickFormatter={(value) => `${toFixedFloat(value, 0)}s`}
				legend={true}
				dataPoints={[
					{
						label: t`Replication Lag`,
						color: "hsl(25, 95%, 53%)",
						dataKey: ({ stats }) => {
							const lag = stats?.mysql?.rl
							return lag !== undefined && lag >= 0 ? lag : undefined
						},
					},
				]}
			/>
		</ChartCard>
	)
}
