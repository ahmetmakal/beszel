import { plural } from "@lingui/core/macro"
import { Trans, useLingui } from "@lingui/react/macro"
import {
	AppleIcon,
	ChevronRightSquareIcon,
	ClockArrowUp,
	CpuIcon,
	ExternalLinkIcon,
	GlobeIcon,
	MemoryStickIcon,
	MonitorIcon,
	Settings2Icon,
	ShieldAlertIcon,
	ShieldCheckIcon,
	ShieldQuestionIcon,
} from "lucide-react"
import { useMemo, useState } from "react"
import ChartTimeSelect from "@/components/charts/chart-time-select"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuLabel,
	DropdownMenuRadioGroup,
	DropdownMenuRadioItem,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { FreeBsdIcon, TuxIcon, WebSocketIcon, WindowsIcon } from "@/components/ui/icons"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ConnectionType, connectionTypeLabels, Os, SystemStatus } from "@/lib/enums"
import { cn, formatBytes, getHostDisplayValue, secondsToUptimeString, toFixedFloat } from "@/lib/utils"
import type { ChartData, ServiceVulnInfo, SystemDetailsRecord, SystemRecord } from "@/types"

export default function InfoBar({
	system,
	chartData,
	grid,
	setGrid,
	displayMode,
	setDisplayMode,
	details,
}: {
	system: SystemRecord
	chartData: ChartData
	grid: boolean
	setGrid: (grid: boolean) => void
	displayMode: "default" | "tabs"
	setDisplayMode: (mode: "default" | "tabs") => void
	details: SystemDetailsRecord | null
}) {
	const { t } = useLingui()
	const [kernelSheetOpen, setKernelSheetOpen] = useState(false)

	// values for system info bar - use details with fallback to system.info
	const systemInfo = useMemo(() => {
		if (!system.info) {
			return []
		}

		// Use details if available, otherwise fall back to system.info
		const hostname = details?.hostname ?? system.info.h
		const kernel = details?.kernel ?? system.info.k
		const cores = details?.cores ?? system.info.c
		const threads = details?.threads ?? system.info.t ?? 0
		const cpuModel = details?.cpu ?? system.info.m
		const os = details?.os ?? system.info.os ?? Os.Linux
		const osName = details?.os_name
		const arch = details?.arch
		const memory = details?.memory
		const kernelVuln = details?.vulns?.kernel
		const scannedKernelVersion = details?.vulns?.kernelVersion
		const kernelScanStale = !!kernel && !!scannedKernelVersion && kernel !== scannedKernelVersion
		const osInfo = {
			[Os.Linux]: {
				Icon: TuxIcon,
				// show kernel in tooltip if os name is available, otherwise show the kernel
				value: osName || kernel,
				label: osName ? kernel : undefined,
			},
			[Os.Darwin]: {
				Icon: AppleIcon,
				value: osName || `macOS ${kernel}`,
			},
			[Os.Windows]: {
				Icon: WindowsIcon,
				value: osName || kernel,
				label: osName ? kernel : undefined,
			},
			[Os.FreeBSD]: {
				Icon: FreeBsdIcon,
				value: osName || kernel,
				label: osName ? kernel : undefined,
			},
		}

		const info = [
			{ key: "host", value: getHostDisplayValue(system), Icon: GlobeIcon },
			{
				key: "hostname",
				value: hostname,
				Icon: MonitorIcon,
				label: "Hostname",
				// hide if hostname is same as host or name
				hide: hostname === system.host || hostname === system.name,
			},
			{ key: "uptime", value: secondsToUptimeString(system.info.u), Icon: ClockArrowUp, label: t`Uptime`, hide: !system.info.u },
			{ key: "os", ...osInfo[os] },
			{
				key: "kernel",
				value: kernel,
				Icon: ChevronRightSquareIcon,
				hide: !kernel || !osName,
				label: t`Kernel`,
				extra: <KernelVulnBadge vulnInfo={kernelVuln} stale={kernelScanStale} />,
				clickable: true,
				onClick: () => setKernelSheetOpen(true),
			},
			{
				key: "cpu",
				value: cpuModel,
				Icon: CpuIcon,
				hide: !cpuModel,
				label: `${plural(cores, { one: "# core", other: "# cores" })} / ${plural(threads, { one: "# thread", other: "# threads" })}${arch ? ` / ${arch}` : ""}`,
			},
		] as {
			key: string
			value: string | number | undefined
			label?: string
			Icon: React.ElementType
			hide?: boolean
			extra?: React.ReactNode
			clickable?: boolean
			onClick?: () => void
		}[]

		if (memory) {
			const memValue = formatBytes(memory, false, undefined, false)
			info.push({
				key: "memory",
				value: `${toFixedFloat(memValue.value, memValue.value >= 10 ? 1 : 2)} ${memValue.unit}`,
				Icon: MemoryStickIcon,
				hide: !memory,
				label: t`Memory`,
			})
		}

		return info
	}, [system, details, t])

	let translatedStatus: string = system.status
	if (system.status === SystemStatus.Up) {
		translatedStatus = t({ message: "Up", comment: "Context: System is up" })
	} else if (system.status === SystemStatus.Down) {
		translatedStatus = t({ message: "Down", comment: "Context: System is down" })
	}

	return (
		<Card>
			<div className="grid xl:flex xl:gap-4 px-4 sm:px-6 pt-3 sm:pt-4 pb-5">
				<div className="min-w-0">
					<h1 className="text-2xl sm:text-[1.6rem] font-semibold mb-1.5">{system.name}</h1>
					<div className="flex xl:flex-wrap items-center py-4 xl:p-0 -mt-3 xl:mt-1 gap-3 text-sm text-nowrap opacity-90 overflow-x-auto scrollbar-hide -mx-4 px-4 xl:mx-0">
						<Tooltip>
							<TooltipTrigger asChild>
								<div className="capitalize flex gap-2 items-center">
									<span className={cn("relative flex h-3 w-3")}>
										{system.status === SystemStatus.Up && (
											<span
												className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"
												style={{ animationDuration: "1.5s" }}
											></span>
										)}
										<span
											className={cn("relative inline-flex rounded-full h-3 w-3", {
												"bg-green-500": system.status === SystemStatus.Up,
												"bg-red-500": system.status === SystemStatus.Down,
												"bg-primary/40": system.status === SystemStatus.Paused,
												"bg-yellow-500": system.status === SystemStatus.Pending,
											})}
										></span>
									</span>
									{translatedStatus}
								</div>
							</TooltipTrigger>
							{system.info.ct && (
								<TooltipContent>
									<div className="flex gap-1 items-center">
										{system.info.ct === ConnectionType.WebSocket ? (
											<WebSocketIcon className="size-4" />
										) : (
											<ChevronRightSquareIcon className="size-4" strokeWidth={2} />
										)}
										{connectionTypeLabels[system.info.ct as ConnectionType]}
									</div>
								</TooltipContent>
							)}
						</Tooltip>

						{systemInfo.map(({ key, value, label, Icon, hide, extra, clickable, onClick }) => {
							if (hide || !value) {
								return null
							}
							const baseContent = (
								<div className="flex gap-1.5 items-center">
									<Icon className="h-4 w-4" /> {value} {extra}
								</div>
							)
							const content = clickable ? (
								<button
									type="button"
									onClick={onClick}
									className="cursor-pointer hover:text-primary transition-colors"
									aria-label={typeof value === "string" ? value : String(value)}
								>
									{baseContent}
								</button>
							) : (
								baseContent
							)
							return (
								<div key={key} className="contents">
									<Separator orientation="vertical" className="h-4 bg-primary/30" />
									{label ? (
										<Tooltip delayDuration={100}>
											<TooltipTrigger asChild>{content}</TooltipTrigger>
											<TooltipContent>{label}</TooltipContent>
										</Tooltip>
									) : (
										content
									)}
								</div>
							)
						})}
					</div>
				</div>
				<div className="xl:ms-auto flex items-center gap-2 max-sm:-mb-1">
					<ChartTimeSelect className="w-full xl:w-40" agentVersion={chartData.agentVersion} />
					<DropdownMenu>
						<DropdownMenuTrigger asChild>
							<Button
								aria-label={t`Settings`}
								variant="outline"
								size="icon"
								className="hidden xl:flex p-0 text-primary"
							>
								<Settings2Icon className="size-4 opacity-90" />
							</Button>
						</DropdownMenuTrigger>
						<DropdownMenuContent align="end" className="min-w-44">
							<DropdownMenuLabel className="px-3.5">
								<Trans context="Layout display options">Display</Trans>
							</DropdownMenuLabel>
							<DropdownMenuSeparator />
							<DropdownMenuRadioGroup
								className="px-1 pb-1"
								value={displayMode}
								onValueChange={(v) => setDisplayMode(v as "default" | "tabs")}
							>
								<DropdownMenuRadioItem value="default" onSelect={(e) => e.preventDefault()}>
									<Trans context="Default system layout option">Default</Trans>
								</DropdownMenuRadioItem>
								<DropdownMenuRadioItem value="tabs" onSelect={(e) => e.preventDefault()}>
									<Trans context="Tabs system layout option">Tabs</Trans>
								</DropdownMenuRadioItem>
							</DropdownMenuRadioGroup>
							<DropdownMenuSeparator />
							<DropdownMenuLabel className="px-3.5">
								<Trans>Chart width</Trans>
							</DropdownMenuLabel>
							<DropdownMenuSeparator />
							<DropdownMenuRadioGroup
								className="px-1 pb-1"
								value={grid ? "grid" : "full"}
								onValueChange={(v) => setGrid(v === "grid")}
							>
								<DropdownMenuRadioItem value="grid" onSelect={(e) => e.preventDefault()}>
									<Trans>Grid</Trans>
								</DropdownMenuRadioItem>
								<DropdownMenuRadioItem value="full" onSelect={(e) => e.preventDefault()}>
									<Trans>Full</Trans>
								</DropdownMenuRadioItem>
							</DropdownMenuRadioGroup>
						</DropdownMenuContent>
					</DropdownMenu>
				</div>
			</div>
			<KernelVulnSheet
				open={kernelSheetOpen}
				onOpenChange={setKernelSheetOpen}
				kernel={details?.kernel ?? system.info.k}
				kernelVuln={details?.vulns?.kernel}
				scannedKernelVersion={details?.vulns?.kernelVersion}
				scannedAt={details?.vulns?.scannedAt}
			/>
		</Card>
	)
}

function KernelVulnBadge({ vulnInfo, stale }: { vulnInfo?: ServiceVulnInfo; stale?: boolean }) {
	if (!vulnInfo || stale) {
		return (
			<span className="inline-flex items-center text-muted-foreground" title="Kernel vulnerability scan is not up to date">
				<ShieldQuestionIcon className="size-3.5" />
			</span>
		)
	}
	if (vulnInfo.status === "vulnerable" && vulnInfo.vulns?.length) {
		return (
			<span className="inline-flex items-center gap-0.5 text-red-500" title={`${vulnInfo.vulns.length} kernel vulnerabilities found`}>
				<ShieldAlertIcon className="size-3.5" />
				<span className="text-[10px] font-semibold">{vulnInfo.vulns.length}</span>
			</span>
		)
	}
	return (
		<span className="inline-flex items-center text-green-500" title="Kernel is safe">
			<ShieldCheckIcon className="size-3.5" />
		</span>
	)
}

function KernelVulnSheet({
	open,
	onOpenChange,
	kernel,
	kernelVuln,
	scannedKernelVersion,
	scannedAt,
}: {
	open: boolean
	onOpenChange: (open: boolean) => void
	kernel?: string
	kernelVuln?: ServiceVulnInfo
	scannedKernelVersion?: string
	scannedAt?: string
}) {
	const isStale = !!kernel && !!scannedKernelVersion && kernel !== scannedKernelVersion

	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent className="w-full sm:max-w-3xl overflow-y-auto">
				<SheetHeader>
					<SheetTitle>
						<Trans>Kernel Vulnerability Details</Trans>
					</SheetTitle>
				</SheetHeader>
				<div className="mt-6 grid gap-4 text-sm">
					<div className="border rounded-md">
						<table className="w-full">
							<tbody>
								<tr className="border-b">
									<td className="px-3 py-2 text-muted-foreground">
										<Trans>Kernel version</Trans>
									</td>
									<td className="px-3 py-2 font-mono">{kernel || "—"}</td>
								</tr>
								<tr className="border-b">
									<td className="px-3 py-2 text-muted-foreground">
										<Trans>Status</Trans>
									</td>
									<td className="px-3 py-2">
										{isStale ? (
											<span className="text-yellow-500 font-medium">
												<Trans>Kernel changed, rescan required</Trans>
											</span>
										) : !kernelVuln ? (
											<span className="text-muted-foreground">
												<Trans>Not scanned</Trans>
											</span>
										) : kernelVuln.status === "vulnerable" ? (
											<span className="text-red-500 font-medium">
												<Trans>Vulnerabilities found</Trans> ({kernelVuln.vulns?.length ?? 0})
											</span>
										) : (
											<span className="text-green-500">
												<Trans>Safe</Trans>
											</span>
										)}
									</td>
								</tr>
								<tr>
									<td className="px-3 py-2 text-muted-foreground">
										<Trans>Scanned at</Trans>
									</td>
									<td className="px-3 py-2">{scannedAt ? new Date(scannedAt).toLocaleString() : "—"}</td>
								</tr>
								{scannedKernelVersion && (
									<tr className="border-t">
										<td className="px-3 py-2 text-muted-foreground">
											<Trans>Scanned kernel</Trans>
										</td>
										<td className="px-3 py-2 font-mono">{scannedKernelVersion}</td>
									</tr>
								)}
							</tbody>
						</table>
					</div>

					{!isStale && kernelVuln?.status === "vulnerable" && kernelVuln.vulns && kernelVuln.vulns.length > 0 && (
						<div className="border rounded-md overflow-hidden">
							<table className="w-full text-sm">
								<thead>
									<tr className="border-b bg-muted dark:bg-muted/40">
										<th className="px-3 py-2 text-left font-medium">
											<Trans>Severity</Trans>
										</th>
										<th className="px-3 py-2 text-left font-medium">
											<Trans>ID</Trans>
										</th>
										<th className="px-3 py-2 text-left font-medium">
											<Trans>Summary</Trans>
										</th>
									</tr>
								</thead>
								<tbody>
									{kernelVuln.vulns.map((v) => (
										<tr key={v.id} className="border-b last:border-b-0">
											<td className="px-3 py-2 whitespace-nowrap">
												<KernelSeverityBadge score={v.score} severity={v.severity} />
											</td>
											<td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
												<a
													href={`https://osv.dev/vulnerability/${v.id}`}
													target="_blank"
													rel="noopener noreferrer"
													className="text-blue-500 hover:underline inline-flex items-center gap-1"
												>
													{v.id}
													<ExternalLinkIcon className="size-3" />
												</a>
											</td>
											<td className="px-3 py-2 text-xs">{v.summary || "—"}</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
			</SheetContent>
		</Sheet>
	)
}

function KernelSeverityBadge({ score, severity }: { score?: number; severity?: string }) {
	if (!score && !severity) {
		return <span className="text-xs text-muted-foreground">—</span>
	}
	const colors: Record<string, string> = {
		CRITICAL: "bg-red-600 text-white",
		HIGH: "bg-orange-500 text-white",
		MEDIUM: "bg-yellow-500 text-black",
		LOW: "bg-blue-400 text-white",
	}
	const colorClass = colors[severity ?? ""] ?? "bg-zinc-400 text-white"
	return (
		<span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold leading-none", colorClass)}>
			{score ? score.toFixed(1) : "?"} <span className="font-normal text-[10px] opacity-85">{severity ?? ""}</span>
		</span>
	)
}
