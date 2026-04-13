import { t } from "@lingui/core/macro"
import type { ChartData } from "@/types"
import { ChartCard } from "../chart-card"
import LineChartDefault from "@/components/charts/line-chart"
import { toFixedFloat, formatBytes } from "@/lib/utils"

export function WebServerConnectionsChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	if (!lastStats?.ws) {
		return null
	}

	const serverType = lastStats.ws.tp
	const title = `${serverType.charAt(0).toUpperCase() + serverType.slice(1)} ${t`Connections`}`

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={title}
			description={t`Active connections and worker status`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => String(toFixedFloat(item.value, 0))}
				tickFormatter={(value) => String(toFixedFloat(value, 0))}
				legend={true}
				dataPoints={[
					{
						label: t({ message: `Active`, comment: "Web server connections" }),
						color: "hsl(142, 71%, 45%)",
						dataKey: ({ stats }) => stats?.ws?.ac,
					},
					{
						label: t({ message: `Busy`, comment: "Web server workers" }),
						color: "hsl(0, 84%, 60%)",
						dataKey: ({ stats }) => stats?.ws?.bw,
					},
					{
						label: t({ message: `Idle`, comment: "Web server workers" }),
						color: "hsl(217, 91%, 60%)",
						dataKey: ({ stats }) => stats?.ws?.iw,
					},
					{
						label: t({ message: `Reading`, comment: "Web server connections" }),
						color: "hsl(271, 81%, 60%)",
						dataKey: ({ stats }) => stats?.ws?.r,
					},
					{
						label: t({ message: `Writing`, comment: "Web server connections" }),
						color: "hsl(25, 95%, 53%)",
						dataKey: ({ stats }) => stats?.ws?.w,
					},
					{
						label: t({ message: `Waiting`, comment: "Web server connections" }),
						color: "hsl(55, 80%, 45%)",
						dataKey: ({ stats }) => stats?.ws?.wt,
					},
				]}
			/>
		</ChartCard>
	)
}

export function WebServerTrafficChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	if (!lastStats?.ws) {
		return null
	}

	const serverType = lastStats.ws.tp
	const title = `${serverType.charAt(0).toUpperCase() + serverType.slice(1)} ${t`Traffic`}`

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={title}
			description={t`Requests per second and bandwidth`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => {
					if (item.dataKey.toString().includes("bps")) {
						return formatBytes(item.value, true)
					}
					return `${toFixedFloat(item.value, 2)} req/s`
				}}
				tickFormatter={(value) => String(toFixedFloat(value, 1))}
				legend={true}
				dataPoints={[
					{
						label: t`Requests/sec`,
						color: "hsl(142, 71%, 45%)",
						dataKey: ({ stats }) => stats?.ws?.rps,
					},
					{
						label: t`Bytes/sec`,
						color: "hsl(217, 91%, 60%)",
						dataKey: ({ stats }) => stats?.ws?.bps,
					},
				]}
			/>
		</ChartCard>
	)
}
