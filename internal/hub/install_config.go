package hub

import (
	"strings"

	"github.com/henrygd/beszel/internal/hub/utils"
)

const (
	defaultAgentInstallScriptURL = "https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent.sh"
	defaultAgentBrewScriptURL    = "https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent-brew.sh"
	defaultAgentWindowsScriptURL = "https://raw.githubusercontent.com/ahmetmakal/beszel/main/supplemental/scripts/install-agent.ps1"
	defaultAgentDockerImage      = "ghcr.io/ahmetmakal/beszel/beszel-agent"
)

func agentInstallScriptURL() string {
	if v, ok := utils.GetEnv("AGENT_INSTALL_SCRIPT_URL"); ok && v != "" {
		return v
	}
	return defaultAgentInstallScriptURL
}

func agentBrewScriptURL() string {
	if v, ok := utils.GetEnv("AGENT_BREW_SCRIPT_URL"); ok && v != "" {
		return v
	}
	return defaultAgentBrewScriptURL
}

func agentWindowsScriptURL() string {
	if v, ok := utils.GetEnv("AGENT_WINDOWS_SCRIPT_URL"); ok && v != "" {
		return v
	}
	return defaultAgentWindowsScriptURL
}

func agentDockerImage() string {
	if v, ok := utils.GetEnv("AGENT_DOCKER_IMAGE"); ok && v != "" {
		return v
	}
	return defaultAgentDockerImage
}

func injectInstallConfig(html string) string {
	replacements := map[string]string{
		"{{AGENT_INSTALL_SCRIPT_URL}}":  agentInstallScriptURL(),
		"{{AGENT_BREW_SCRIPT_URL}}":     agentBrewScriptURL(),
		"{{AGENT_WINDOWS_SCRIPT_URL}}":  agentWindowsScriptURL(),
		"{{AGENT_DOCKER_IMAGE}}":        agentDockerImage(),
	}
	for old, new := range replacements {
		html = strings.Replace(html, old, new, 1)
	}
	return html
}
