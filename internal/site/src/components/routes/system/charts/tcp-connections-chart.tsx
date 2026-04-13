import { t } from "@lingui/core/macro"
import type { ChartData } from "@/types"
import { ChartCard } from "../chart-card"
import LineChartDefault from "@/components/charts/line-chart"
import { toFixedFloat } from "@/lib/utils"

export function TcpConnectionsChart({
	chartData,
	grid,
	dataEmpty,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
}) {
	const lastStats = chartData.systemStats.at(-1)?.stats
	if (!lastStats?.tcp) {
		return null
	}

	return (
		<ChartCard
			empty={dataEmpty}
			grid={grid}
			title={t`TCP Connections`}
			description={t`TCP connection counts by state`}
			legend={true}
		>
			<LineChartDefault
				chartData={chartData}
				contentFormatter={(item) => String(toFixedFloat(item.value, 0))}
				tickFormatter={(value) => String(toFixedFloat(value, 0))}
				legend={true}
				dataPoints={[
					{
						label: t({ message: `Established`, comment: "TCP connection state" }),
						color: "hsl(142, 71%, 45%)",
						dataKey: ({ stats }) => stats?.tcp?.ESTABLISHED,
					},
					{
						label: t({ message: `Listen`, comment: "TCP connection state" }),
						color: "hsl(217, 91%, 60%)",
						dataKey: ({ stats }) => stats?.tcp?.LISTEN,
					},
					{
						label: t({ message: `Time Wait`, comment: "TCP connection state" }),
						color: "hsl(25, 95%, 53%)",
						dataKey: ({ stats }) => stats?.tcp?.TIME_WAIT,
					},
					{
						label: t({ message: `Close Wait`, comment: "TCP connection state" }),
						color: "hsl(0, 84%, 60%)",
						dataKey: ({ stats }) => stats?.tcp?.CLOSE_WAIT,
					},
					{
						label: t({ message: `FIN Wait 1`, comment: "TCP connection state" }),
						color: "hsl(280, 65%, 55%)",
						dataKey: ({ stats }) => stats?.tcp?.FIN_WAIT1,
					},
					{
						label: t({ message: `FIN Wait 2`, comment: "TCP connection state" }),
						color: "hsl(310, 65%, 55%)",
						dataKey: ({ stats }) => stats?.tcp?.FIN_WAIT2,
					},
					{
						label: t({ message: `SYN Sent`, comment: "TCP connection state" }),
						color: "hsl(180, 70%, 45%)",
						dataKey: ({ stats }) => stats?.tcp?.SYN_SENT,
					},
					{
						label: t({ message: `SYN Recv`, comment: "TCP connection state" }),
						color: "hsl(55, 80%, 45%)",
						dataKey: ({ stats }) => stats?.tcp?.SYN_RECV,
					},
					{
						label: t({ message: `Last ACK`, comment: "TCP connection state" }),
						color: "hsl(340, 70%, 50%)",
						dataKey: ({ stats }) => stats?.tcp?.LAST_ACK,
					},
				]}
			/>
		</ChartCard>
	)
}
