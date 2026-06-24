import { t } from "@lingui/core/macro"
import type { ChartConfig } from "@/components/ui/chart"
import AreaChartDefault from "@/components/charts/area-chart"
import { useContainerDataPoints } from "@/components/charts/hooks"
import { decimalString, formatBytes, pinnedAxisDomain, toFixedFloat } from "@/lib/utils"
import type { ChartData } from "@/types"
import { ChartCard } from "../chart-card"

function VmCpuChart({
	chartData,
	grid,
	dataEmpty,
	cpuConfig,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
	cpuConfig: ChartConfig
}) {
	const { dataPoints } = useContainerDataPoints(cpuConfig, (key, data) => data[key]?.c ?? null)
	if (!dataPoints.length) return null
	return (
		<ChartCard empty={dataEmpty} grid={grid} title={t`VM CPU Usage`} description={t`Average CPU utilization of virtual machines`} legend={true}>
			<AreaChartDefault
				chartData={chartData}
				customData={chartData.vmData}
				dataPoints={dataPoints}
				tickFormatter={(val) => `${toFixedFloat(val, 2)}%`}
				contentFormatter={({ value }) => `${decimalString(value)}%`}
				domain={pinnedAxisDomain()}
				legend={true}
				showTotal={true}
				itemSorter={(a, b) => b.value - a.value}
			/>
		</ChartCard>
	)
}

function VmMemoryChart({
	chartData,
	grid,
	dataEmpty,
	memoryConfig,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
	memoryConfig: ChartConfig
}) {
	const { dataPoints } = useContainerDataPoints(memoryConfig, (key, data) => data[key]?.m ?? null)
	if (!dataPoints.length) return null
	return (
		<ChartCard empty={dataEmpty} grid={grid} title={t`VM Memory Usage`} description={t`Memory usage of virtual machines`} legend={true}>
			<AreaChartDefault
				chartData={chartData}
				customData={chartData.vmData}
				dataPoints={dataPoints}
				tickFormatter={(val) => {
					const f = formatBytes(val, false, undefined, true)
					return `${toFixedFloat(f.value, 1)} ${f.unit}`
				}}
				contentFormatter={({ value }) => {
					const f = formatBytes(value, false, undefined, true)
					return `${decimalString(f.value)} ${f.unit}`
				}}
				domain={pinnedAxisDomain()}
				legend={true}
				showTotal={true}
				itemSorter={(a, b) => b.value - a.value}
			/>
		</ChartCard>
	)
}

function VmNetworkChart({
	chartData,
	grid,
	dataEmpty,
	networkConfig,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
	networkConfig: ChartConfig
}) {
	const { dataPoints } = useContainerDataPoints(networkConfig, (key, data) => {
		const vm = data[key]
		if (!vm) return null
		return (vm.b?.[0] ?? 0) + (vm.b?.[1] ?? 0)
	})
	if (!dataPoints.length) return null
	return (
		<ChartCard empty={dataEmpty} grid={grid} title={t`VM Network`} description={t`Network traffic of virtual machines`} legend={true}>
			<AreaChartDefault
				chartData={chartData}
				customData={chartData.vmData}
				dataPoints={dataPoints}
				tickFormatter={(val) => {
					const f = formatBytes(val, true, undefined, false)
					return `${toFixedFloat(f.value, 1)} ${f.unit}`
				}}
				contentFormatter={({ value }) => {
					const f = formatBytes(value, true, undefined, false)
					return `${decimalString(f.value)} ${f.unit}`
				}}
				domain={pinnedAxisDomain()}
				legend={true}
				showTotal={true}
				itemSorter={(a, b) => b.value - a.value}
			/>
		</ChartCard>
	)
}

export function LibvirtCharts({
	chartData,
	grid,
	dataEmpty,
	vmChartConfigs,
}: {
	chartData: ChartData
	grid: boolean
	dataEmpty: boolean
	vmChartConfigs: { cpu: ChartConfig; memory: ChartConfig; network: ChartConfig }
}) {
	if (!chartData.vmData.length) return null
	return (
		<>
			<VmCpuChart chartData={chartData} grid={grid} dataEmpty={dataEmpty} cpuConfig={vmChartConfigs.cpu} />
			<VmMemoryChart chartData={chartData} grid={grid} dataEmpty={dataEmpty} memoryConfig={vmChartConfigs.memory} />
			<VmNetworkChart chartData={chartData} grid={grid} dataEmpty={dataEmpty} networkConfig={vmChartConfigs.network} />
		</>
	)
}
