import { i18n } from "@lingui/core"
import { memo } from "react"
import { copyToClipboard, getHubURL } from "@/lib/utils"
import { DropdownMenuContent, DropdownMenuItem } from "./ui/dropdown-menu"

const FALLBACK_AGENT_SCRIPT =
	"https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent.sh"
const FALLBACK_AGENT_BREW_SCRIPT =
	"https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent-brew.sh"
const FALLBACK_AGENT_WINDOWS_SCRIPT =
	"https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent.ps1"
const FALLBACK_AGENT_DOCKER_IMAGE = "ghcr.io/ahmetmakal/beszel/beszel-agent"

function getAgentScriptUrl(brew = false) {
	if (brew) {
		return globalThis.BESZEL?.AGENT_BREW_SCRIPT_URL || FALLBACK_AGENT_BREW_SCRIPT
	}
	return globalThis.BESZEL?.AGENT_INSTALL_SCRIPT_URL || FALLBACK_AGENT_SCRIPT
}

function getAgentWindowsScriptUrl() {
	return globalThis.BESZEL?.AGENT_WINDOWS_SCRIPT_URL || FALLBACK_AGENT_WINDOWS_SCRIPT
}

function getAgentDockerImage() {
	return globalThis.BESZEL?.AGENT_DOCKER_IMAGE || FALLBACK_AGENT_DOCKER_IMAGE
}

export function copyDockerCompose(port = "45876", publicKey: string, token: string) {
	const image = getAgentDockerImage()
	copyToClipboard(`services:
  beszel-agent:
    image: ${image}
    container_name: beszel-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./beszel_agent_data:/var/lib/beszel-agent
      # monitor other disks / partitions by mounting a folder in /extra-filesystems
      # - /mnt/disk/.beszel:/extra-filesystems/sda1:ro
    environment:
      LISTEN: ${port}
      KEY: '${publicKey}'
      TOKEN: ${token}
      HUB_URL: ${getHubURL()}`)
}

export function copyDockerRun(port = "45876", publicKey: string, token: string) {
	const image = getAgentDockerImage()
	copyToClipboard(
		`docker run -d --name beszel-agent --network host --restart unless-stopped -v /var/run/docker.sock:/var/run/docker.sock:ro -v beszel_agent_data:/var/lib/beszel-agent -e KEY="${publicKey}" -e LISTEN=${port} -e TOKEN="${token}" -e HUB_URL="${getHubURL()}" ${image}`
	)
}

export function copyLinuxCommand(port = "45876", publicKey: string, token: string, brew = false) {
	let cmd = `curl -sL ${getAgentScriptUrl(brew)} -o /tmp/install-agent.sh && chmod +x /tmp/install-agent.sh && /tmp/install-agent.sh -p ${port} -k "${publicKey}" -t "${token}" -url "${getHubURL()}"`
	// brew script does not support --china-mirrors
	if (!brew && (i18n.locale + navigator.language).includes("zh-CN")) {
		cmd += ` --china-mirrors`
	}
	copyToClipboard(cmd)
}

export function copyWindowsCommand(port = "45876", publicKey: string, token: string) {
	copyToClipboard(
		`& iwr -useb ${getAgentWindowsScriptUrl()} -OutFile "$env:TEMP\\install-agent.ps1"; & Powershell -ExecutionPolicy Bypass -File "$env:TEMP\\install-agent.ps1" -Key "${publicKey}" -Port ${port} -Token "${token}" -Url "${getHubURL()}"`
	)
}

export interface DropdownItem {
	text: string
	onClick?: () => void
	url?: string
	icons?: React.ComponentType<React.SVGProps<SVGSVGElement>>[]
}

export const InstallDropdown = memo(({ items }: { items: DropdownItem[] }) => {
	return (
		<DropdownMenuContent align="end">
			{items.map((item, index) => {
				const className = "cursor-pointer flex items-center gap-1.5"
				return item.url ? (
					<DropdownMenuItem key={index} asChild>
						<a href={item.url} className={className} target="_blank" rel="noopener noreferrer">
							{item.text}{" "}
							{item.icons?.map((Icon, iconIndex) => (
								<Icon key={iconIndex} className="size-4" />
							))}
						</a>
					</DropdownMenuItem>
				) : (
					<DropdownMenuItem key={index} onClick={item.onClick} className={className}>
						{item.text}{" "}
						{item.icons?.map((Icon, iconIndex) => (
							<Icon key={iconIndex} className="size-4" />
						))}
					</DropdownMenuItem>
				)
			})}
		</DropdownMenuContent>
	)
})
