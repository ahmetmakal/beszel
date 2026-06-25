import { timeTicks } from "d3-time"
import { getPbTimestamp, pb } from "@/lib/api"
import { chartTimeData } from "@/lib/utils"
import type {
	ChartData,
	ChartTimes,
	ContainerStatsRecord,
	LibvirtVMRecord,
	LibvirtVMStats,
	LibvirtVMStatsRecord,
	SystemStatsRecord,
} from "@/types"

type ChartTimeData = {
	time: number
	data: {
		ticks: number[]
		domain: number[]
	}
	chartTime: ChartTimes
}

export const cache = new Map<
	string,
	ChartTimeData | SystemStatsRecord[] | ContainerStatsRecord[] | LibvirtVMStatsRecord[] | ChartData["containerData"] | ChartData["vmData"]
>()

// create ticks and domain for charts
export function getTimeData(chartTime: ChartTimes, lastCreated: number) {
	const cached = cache.get("td") as ChartTimeData | undefined
	if (cached && cached.chartTime === chartTime) {
		if (!lastCreated || cached.time >= lastCreated) {
			return cached.data
		}
	}

	// const buffer = chartTime === "1m" ? 400 : 20_000
	const now = new Date(Date.now())
	const startTime = chartTimeData[chartTime].getOffset(now)
	const ticks = timeTicks(startTime, now, chartTimeData[chartTime].ticks ?? 12).map((date) => date.getTime())
	const data = {
		ticks,
		domain: [chartTimeData[chartTime].getOffset(now).getTime(), now.getTime()],
	}
	cache.set("td", { time: now.getTime(), data, chartTime })
	return data
}

/** Append new records onto prev with gap detection. Converts string `created` values to ms timestamps in place.
 * Pass `maxLen` to cap the result length in one copy instead of slicing again after the call. */
export function appendData<T extends { created: string | number | null }>(
	prev: T[],
	newRecords: T[],
	expectedInterval: number,
	maxLen?: number
): T[] {
	if (!newRecords.length) return prev
	// Pre-trim prev so the single slice() below is the only copy we make
	const trimmed = maxLen && prev.length >= maxLen ? prev.slice(-(maxLen - newRecords.length)) : prev
	const result = trimmed.slice()
	let prevTime = (trimmed.at(-1)?.created as number) ?? 0
	for (const record of newRecords) {
		if (record.created !== null) {
			if (typeof record.created === "string") {
				record.created = new Date(record.created).getTime()
			}
			if (prevTime && (record.created as number) - prevTime > expectedInterval * 1.5) {
				result.push({ created: null, ...("stats" in record ? { stats: null } : {}) } as T)
			}
			prevTime = record.created as number
		}
		result.push(record)
	}
	return result
}

export async function getStats<T extends SystemStatsRecord | ContainerStatsRecord | LibvirtVMStatsRecord>(
	collection: string,
	systemId: string,
	chartTime: ChartTimes
): Promise<T[]> {
	const cachedStats = cache.get(`${systemId}_${chartTime}_${collection}`) as T[] | undefined
	const lastCached = cachedStats?.at(-1)?.created as number
	return await pb.collection<T>(collection).getFullList({
		filter: pb.filter("system={:id} && created > {:created} && type={:type}", {
			id: systemId,
			created: getPbTimestamp(chartTime, lastCached ? new Date(lastCached + 1000) : undefined),
			type: chartTimeData[chartTime].type,
		}),
		fields: "created,stats",
		sort: "created",
	})
}

export function makeContainerData(containers: ContainerStatsRecord[]): ChartData["containerData"] {
	const result = [] as ChartData["containerData"]
	for (const { created, stats } of containers) {
		if (!created) {
			result.push({ created: null } as ChartData["containerData"][0])
			continue
		}
		result.push(makeContainerPoint(new Date(created).getTime(), stats))
	}
	return result
}

/** Transform a single realtime container stats message into a ChartDataContainer point. */
export function makeContainerPoint(
	created: number,
	stats: ContainerStatsRecord["stats"]
): ChartData["containerData"][0] {
	const point: ChartData["containerData"][0] = { created } as ChartData["containerData"][0]
	for (const container of stats) {
		;(point as Record<string, unknown>)[container.n] = container
	}
	return point
}

function vmNum(value: unknown): number {
	const n = typeof value === "number" ? value : Number(value)
	return Number.isFinite(n) ? n : 0
}

function vmPair(value: unknown): [number, number] | undefined {
	if (Array.isArray(value) && value.length >= 2) {
		return [vmNum(value[0]), vmNum(value[1])]
	}
	return undefined
}

/** Normalize libvirt VM stats from API/DB (handles alternate field names and string JSON). */
export function normalizeVMStat(raw: unknown): LibvirtVMStats | null {
	if (!raw || typeof raw !== "object") {
		return null
	}
	const o = raw as Record<string, unknown>
	const n = String(o.n ?? o.name ?? o.Name ?? "").trim()
	if (!n) {
		return null
	}
	const b =
		vmPair(o.b ?? o.bandwidth ?? o.Bandwidth) ??
		([vmNum(o.net_wx ?? o.netWx), vmNum(o.net_rx ?? o.netRx)] as [number, number])
	const d =
		vmPair(o.d ?? o.disk ?? o.Disk) ??
		([vmNum(o.disk_read ?? o.diskRead), vmNum(o.disk_write ?? o.diskWrite)] as [number, number])
	const i =
		vmPair(o.i ?? o.iops ?? o.DiskIops) ??
		([0, vmNum(o.disk_iops ?? o.diskIops)] as [number, number])
	return {
		n,
		c: vmNum(o.c ?? o.cpu ?? o.Cpu),
		m: vmNum(o.m ?? o.memory ?? o.Mem),
		b,
		d,
		i,
	}
}

export function normalizeVMStatsList(stats: unknown): LibvirtVMStats[] {
	if (typeof stats === "string") {
		try {
			stats = JSON.parse(stats)
		} catch {
			return []
		}
	}
	if (!stats) {
		return []
	}
	const arr = Array.isArray(stats) ? stats : Object.values(stats as object)
	return arr.map(normalizeVMStat).filter((s): s is LibvirtVMStats => s !== null)
}

/** Build chart stats from live libvirt_vms table rows (fallback when history stats are missing metrics). */
export function vmRecordsToStats(records: LibvirtVMRecord[]): LibvirtVMStats[] {
	return records.map((r) => ({
		n: r.name,
		c: r.cpu ?? 0,
		m: r.memory ?? 0,
		b: [r.net_wx ?? 0, r.net_rx ?? 0],
		d: [r.disk_read ?? 0, r.disk_write ?? 0],
		i: [0, r.disk_iops ?? 0],
	}))
}

export function vmPointHasMetrics(point: ChartData["vmData"][0]): boolean {
	for (const key of Object.keys(point)) {
		if (key === "created") continue
		const vm = point[key] as LibvirtVMStats | undefined
		if (!vm) continue
		if ((vm.c ?? 0) > 0 || (vm.m ?? 0) > 0 || (vm.b?.[0] ?? 0) + (vm.b?.[1] ?? 0) > 0) {
			return true
		}
	}
	return false
}

export function makeVMData(vms: LibvirtVMStatsRecord[]): ChartData["vmData"] {
	const result = [] as ChartData["vmData"]
	for (const { created, stats } of vms) {
		if (!created) {
			result.push({ created: null } as ChartData["vmData"][0])
			continue
		}
		result.push(makeVMPoint(new Date(created).getTime(), stats))
	}
	return result
}

export function makeVMPoint(created: number, stats: unknown): ChartData["vmData"][0] {
	const point: ChartData["vmData"][0] = { created } as ChartData["vmData"][0]
	for (const vm of normalizeVMStatsList(stats)) {
		;(point as Record<string, unknown>)[vm.n] = vm
	}
	return point
}

export function dockerOrPodman(str: string, isPodman: boolean): string {
	if (isPodman) {
		return str.replace("docker", "podman").replace("Docker", "Podman")
	}
	return str
}
