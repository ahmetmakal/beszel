#!/usr/bin/env bash
# Build and deploy beszel-agent to a remote Linux host (systemd).
#
# Setup:
#   cp .deploy-agent.env.example .deploy-agent.env
#   # set DEPLOY_AGENT_REMOTE, DEPLOY_AGENT_BIN, DEPLOY_SSH_PORT, ...
#
# Usage:
#   ./supplemental/scripts/deploy-agent.sh
#   ./supplemental/scripts/deploy-agent.sh --no-restart
#   ./supplemental/scripts/deploy-agent.sh --verify-only
#   ./supplemental/scripts/deploy-agent.sh --env /path/to/custom.env
#   ./supplemental/scripts/deploy-agent.sh --help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
# shellcheck disable=SC1091
. "$ROOT_DIR/supplemental/scripts/deploy-load-env.sh"

NO_RESTART=0
VERIFY_ONLY=0
OS="${DEPLOY_AGENT_OS:-linux}"
ARCH="${DEPLOY_AGENT_ARCH:-amd64}"

usage() {
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--no-restart) NO_RESTART=1 ;;
	--verify-only) VERIFY_ONLY=1 ;;
	--os)
		OS="$2"
		shift
		;;
	--arch)
		ARCH="$2"
		shift
		;;
	--env)
		DEPLOY_ENV_OVERRIDE="$2"
		shift
		;;
	-h | --help) usage 0 ;;
	*)
		echo "Unknown option: $1" >&2
		usage 1
		;;
	esac
	shift
done

deploy_load_env "$ROOT_DIR/.deploy-agent.env"

DEPLOY_AGENT_REMOTE="${DEPLOY_AGENT_REMOTE:-}"
DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
DEPLOY_AGENT_BIN="${DEPLOY_AGENT_BIN:-/usr/bin/beszel-agent}"
DEPLOY_AGENT_SERVICE="${DEPLOY_AGENT_SERVICE:-beszel-agent}"
OS="${DEPLOY_AGENT_OS:-$OS}"
ARCH="${DEPLOY_AGENT_ARCH:-$ARCH}"

if [ -z "$DEPLOY_AGENT_REMOTE" ]; then
	echo "DEPLOY_AGENT_REMOTE is not set. Copy .deploy-agent.env.example to .deploy-agent.env and configure it." >&2
	exit 1
fi

REMOTE_HOST="${DEPLOY_AGENT_REMOTE#*@}"
REMOTE_USER="${DEPLOY_AGENT_REMOTE%@*}"
if [ "$REMOTE_USER" = "$DEPLOY_AGENT_REMOTE" ] || [ -z "$REMOTE_USER" ]; then
	REMOTE_USER="root"
fi
SSH_TARGET="${REMOTE_USER}@${REMOTE_HOST}"

SSH_ARGS=()
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	SSH_ARGS=(-p "$DEPLOY_SSH_PORT")
fi
if [ -n "${DEPLOY_SSH_OPTS:-}" ]; then
	# shellcheck disable=SC2206
	extra=($DEPLOY_SSH_OPTS)
	SSH_ARGS+=("${extra[@]}")
fi

SCP_ARGS=()
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	SCP_ARGS=(-P "$DEPLOY_SSH_PORT")
fi
if [ -n "${DEPLOY_SSH_OPTS:-}" ]; then
	# shellcheck disable=SC2206
	extra=($DEPLOY_SSH_OPTS)
	SCP_ARGS+=("${extra[@]}")
fi

run_ssh() {
	ssh "${SSH_ARGS[@]}" "$@"
}

run_scp() {
	scp "${SCP_ARGS[@]}" "$@"
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Required command not found: $1" >&2
		exit 1
	fi
}

local_binary() {
	printf '%s/build/beszel-agent_%s_%s' "$ROOT_DIR" "$OS" "$ARCH"
}

verify_remote() {
	echo "==> Checking remote service configuration"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		service='$DEPLOY_AGENT_SERVICE'
		bin='$DEPLOY_AGENT_BIN'
		if ! systemctl cat \"\$service\" >/dev/null 2>&1; then
			echo \"Service not found: \$service\" >&2
			exit 1
		fi
		exec_line=\$(systemctl show \"\$service\" -p ExecStart --value)
		exec_bin=\$(printf '%s' \"\$exec_line\" | awk '{print \$1}')
		echo \"systemd ExecStart: \$exec_line\"
		echo \"Deploy target:     \$bin\"
		if [ \"\$exec_bin\" != \"\$bin\" ]; then
			echo \"WARNING: systemd runs '\$exec_bin' but you deploy to '\$bin'\" >&2
			echo \"Fix: update unit file, symlink, or set DEPLOY_AGENT_BIN in .deploy.env\" >&2
		fi
		if [ -x \"\$exec_bin\" ]; then
			echo \"Running binary version: \$(\"\$exec_bin\" --version 2>/dev/null || true)\"
		fi
		readonly_paths=\$(systemctl show \"\$service\" -p ReadOnlyPaths --value)
		echo \"ReadOnlyPaths:       \$readonly_paths\"
		if [ -n \"\$readonly_paths\" ] && ! printf '%s' \"\$readonly_paths\" | grep -q '/sys/class/net'; then
			echo \"WARNING: ReadOnlyPaths missing /sys/class/net — VM network metrics stay at 0 under ProtectSystem=strict\" >&2
			echo \"Fix: add ReadOnlyPaths=/sys/class/net to the unit, then daemon-reload && restart\" >&2
		fi
	"
	echo
	echo "==> Recent libvirt logs"
	run_ssh "$SSH_TARGET" "journalctl -u '$DEPLOY_AGENT_SERVICE' --since '30 min ago' --no-pager 2>/dev/null | grep -i libvirt || echo '(no libvirt lines)'"
}

build_agent() {
	require_cmd make
	require_cmd go
	echo "==> Building agent (OS=$OS ARCH=$ARCH)"
	make build-agent OS="$OS" ARCH="$ARCH"
	local bin
	bin="$(local_binary)"
	if [ ! -f "$bin" ]; then
		echo "Build output not found: $bin" >&2
		exit 1
	fi
	echo "Built: $bin ($(wc -c <"$bin" | tr -d ' ') bytes)"
}

deploy_agent() {
	local bin tmp
	bin="$(local_binary)"
	tmp="${DEPLOY_AGENT_BIN}.new"

	require_cmd scp
	require_cmd ssh

	echo "==> Stopping $DEPLOY_AGENT_SERVICE on $SSH_TARGET"
	run_ssh "$SSH_TARGET" "systemctl stop '$DEPLOY_AGENT_SERVICE' || true"

	echo "==> Uploading binary to $SSH_TARGET:$tmp"
	run_ssh "$SSH_TARGET" "mkdir -p \"\$(dirname '$DEPLOY_AGENT_BIN')\""
	run_scp "$bin" "${SSH_TARGET}:${tmp}"

	echo "==> Installing binary at $DEPLOY_AGENT_BIN"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		chmod 755 '$tmp'
		if [ -f '$DEPLOY_AGENT_BIN' ]; then
			cp -a '$DEPLOY_AGENT_BIN' '${DEPLOY_AGENT_BIN}.bak'
		fi
		mv '$tmp' '$DEPLOY_AGENT_BIN'
	"

	if [ "$NO_RESTART" -eq 1 ]; then
		echo "==> Skipping service restart (--no-restart)"
		return
	fi

	echo "==> Starting $DEPLOY_AGENT_SERVICE"
	run_ssh "$SSH_TARGET" "systemctl start '$DEPLOY_AGENT_SERVICE' && systemctl is-active '$DEPLOY_AGENT_SERVICE'"

	if run_ssh "$SSH_TARGET" "[ -d /run/libvirt/qemu ] || [ -d /var/run/libvirt/qemu ]"; then
		echo "==> Libvirt: grant agent read access to runtime XML"
		run_scp "$ROOT_DIR/supplemental/scripts/libvirt-agent-perms.sh" "${SSH_TARGET}:/tmp/libvirt-agent-perms.sh"
		run_ssh "$SSH_TARGET" "chmod +x /tmp/libvirt-agent-perms.sh && /tmp/libvirt-agent-perms.sh && systemctl restart '$DEPLOY_AGENT_SERVICE'"
	fi

	sleep 2
	verify_remote
}

echo "Agent deploy target: $SSH_TARGET"
if [ -n "${DEPLOY_ENV_FILE:-}" ]; then
	echo "Env file:            $DEPLOY_ENV_FILE"
fi
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	echo "SSH port:            $DEPLOY_SSH_PORT"
fi
echo "Binary path:         $DEPLOY_AGENT_BIN"
echo "Service:             $DEPLOY_AGENT_SERVICE"
echo "Build:               $OS/$ARCH"
echo

if [ "$VERIFY_ONLY" -eq 1 ]; then
	verify_remote
	exit 0
fi

build_agent
deploy_agent

echo
echo "Agent deploy finished."
