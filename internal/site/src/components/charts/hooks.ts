import { useMemo, useState } from "react"
import { useStore } from "@nanostores/react"
import type { ChartConfig } from "@/components/ui/chart"
import type { ChartData, SystemStats, SystemStatsRecord } from "@/types"
import type { DataPoint } from "./area-chart"
import { $containerFilter } from "@/lib/stores"

/** Chart configurations for CPU, memory, and network usage charts */
export interface ContainerChartConfigs {
	cpu: ChartConfig
	memory: ChartConfig
	network: ChartConfig
}

export type VMChartConfigs = ContainerChartConfigs & {
	disk: ChartConfig
}

function buildMetricChartConfigs(
	dataSeries: ChartData["containerData"] | ChartData["vmData"],
	metrics: { cpu: (s: { c?: number }) => number; memory: (s: { m?: number }) => number; network: (s: { b?: [number, number]; ns?: number; nr?: number }) => number }
): ContainerChartConfigs {
	const configs = {
		cpu: {} as ChartConfig,
		memory: {} as ChartConfig,
		network: {} as ChartConfig,
	}
	const totalUsage = {
		cpu: new Map<string, number>(),
		memory: new Map<string, number>(),
		network: new Map<string, number>(),
	}
	for (let i = 0; i < dataSeries.length; i++) {
		const stats = dataSeries[i]
		for (const name of Object.keys(stats)) {
			if (name === "created") continue
			const itemStats = stats[name]
			if (!itemStats) continue
			totalUsage.cpu.set(name, (totalUsage.cpu.get(name) ?? 0) + metrics.cpu(itemStats))
			totalUsage.memory.set(name, (totalUsage.memory.get(name) ?? 0) + metrics.memory(itemStats))
			totalUsage.network.set(name, (totalUsage.network.get(name) ?? 0) + metrics.network(itemStats))
		}
	}
	Object.entries(totalUsage).forEach(([chartType, usageMap]) => {
		const sorted = Array.from(usageMap.entries()).sort(([, a], [, b]) => b - a)
		const chartConfig = {} as Record<string, { label: string; color: string }>
		for (let i = 0; i < sorted.length; i++) {
			const [name] = sorted[i]
			const hue = ((i * 360) / Math.max(sorted.length, 1)) % 360
			chartConfig[name] = { label: name, color: `hsl(${hue}, var(--chart-saturation), var(--chart-lightness))` }
		}
		configs[chartType as keyof typeof configs] = chartConfig
	})
	return configs
}

/**
 * Generates chart configurations for container metrics visualization
 * @param containerData - Array of container statistics data points
 * @returns Chart configurations for CPU, memory, and network metrics
 */
export function useContainerChartConfigs(containerData: ChartData["containerData"]): ContainerChartConfigs {
	return useMemo(
		() =>
			buildMetricChartConfigs(containerData, {
				cpu: (s) => s.c ?? 0,
				memory: (s) => s.m ?? 0,
				network: (s) => {
					const sent = s.b?.[0] ?? (s.ns ?? 0) * 1024 * 1024
					const recv = s.b?.[1] ?? (s.nr ?? 0) * 1024 * 1024
					return sent + recv
				},
			}),
		[containerData]
	)
}

function buildDiskChartConfig(vmData: ChartData["vmData"]): ChartConfig {
	const usage = new Map<string, number>()
	for (const stats of vmData) {
		for (const name of Object.keys(stats)) {
			if (name === "created") continue
			const vm = stats[name]
			if (!vm) continue
			usage.set(name, (usage.get(name) ?? 0) + (vm.d?.[0] ?? 0) + (vm.d?.[1] ?? 0))
		}
	}
	const sorted = Array.from(usage.entries()).sort(([, a], [, b]) => b - a)
	const chartConfig = {} as ChartConfig
	for (let i = 0; i < sorted.length; i++) {
		const [name] = sorted[i]
		const hue = ((i * 360) / Math.max(sorted.length, 1)) % 360
		chartConfig[name] = { label: name, color: `hsl(${hue}, var(--chart-saturation), var(--chart-lightness))` }
	}
	return chartConfig
}

export function useVMChartConfigs(vmData: ChartData["vmData"]): VMChartConfigs {
	const base = useMemo(
		() =>
			buildMetricChartConfigs(vmData, {
				cpu: (s) => s.c ?? 0,
				memory: (s) => s.m ?? 0,
				network: (s) => (s.b?.[0] ?? 0) + (s.b?.[1] ?? 0),
			}),
		[vmData]
	)
	const disk = useMemo(() => buildDiskChartConfig(vmData), [vmData])
	return useMemo(() => ({ ...base, disk }), [base, disk])
}

/** Sets the correct width of the y axis in recharts based on the longest label */
export function useYAxisWidth() {
	const [yAxisWidth, setYAxisWidth] = useState(0)
	let maxChars = 0
	let timeout: ReturnType<typeof setTimeout>
	function updateYAxisWidth(str: string) {
		if (str.length > maxChars) {
			maxChars = str.length
			const div = document.createElement("div")
			div.className = "text-xs tabular-nums tracking-tighter table sr-only"
			div.innerHTML = str
			clearTimeout(timeout)
			timeout = setTimeout(() => {
				document.body.appendChild(div)
				const width = div.offsetWidth + 20 
				if (width > yAxisWidth) {
					setYAxisWidth(width)
				}
				document.body.removeChild(div)
			})
		}
		return str
	}
	return { yAxisWidth, updateYAxisWidth }
}

/** Subscribes to the container filter store and returns filtered DataPoints for container charts */
export function useContainerDataPoints(
	chartConfig: ChartConfig,
	// biome-ignore lint/suspicious/noExplicitAny: container data records have dynamic keys
	dataFn: (key: string, data: Record<string, any>) => number | null
) {
	const filter = useStore($containerFilter)
	const { dataPoints, filteredKeys } = useMemo(() => {
		const filterTerms = filter
			? filter
					.toLowerCase()
					.split(" ")
					.filter((term) => term.length > 0)
			: []
		const filtered = new Set<string>()
		const points = Object.keys(chartConfig).map((key) => {
			const isFiltered = filterTerms.length > 0 && !filterTerms.some((term) => key.toLowerCase().includes(term))
			if (isFiltered) filtered.add(key)
			return {
				label: key,
				// biome-ignore lint/suspicious/noExplicitAny: container data records have dynamic keys
				dataKey: (data: Record<string, any>) => dataFn(key, data),
				color: chartConfig[key].color ?? "",
				opacity: isFiltered ? 0.05 : 0.4,
				strokeOpacity: isFiltered ? 0.1 : 1,
				activeDot: !isFiltered,
				stackId: "a",
			}
		})
		return {
			// biome-ignore lint/suspicious/noExplicitAny: container data records have dynamic keys
			dataPoints: points as DataPoint<Record<string, any>>[],
			filteredKeys: filtered,
		}
	}, [chartConfig, filter])
	return { filter, dataPoints, filteredKeys }
}

// Assures consistent colors for network interfaces
export function useNetworkInterfaces(interfaces: SystemStats["ni"]) {
	const keys = Object.keys(interfaces ?? {})
	const sortedKeys = keys.sort((a, b) => (interfaces?.[b]?.[3] ?? 0) - (interfaces?.[a]?.[3] ?? 0))
	return {
		length: sortedKeys.length,
		data: (index = 3) => {
			return sortedKeys.map((key) => ({
				label: key,
				dataKey: ({ stats }: SystemStatsRecord) => stats?.ni?.[key]?.[index],
				color: `hsl(${220 + (((sortedKeys.indexOf(key) * 360) / sortedKeys.length) % 360)}, 70%, 50%)`,

				opacity: 0.3,
			}))
		},
	}
}
