#!/usr/bin/env bash
# Libvirt VMMonitoring debug checklist (run on agent host as root).
#
# Usage:
#   ./supplemental/scripts/debug-libvirt.sh              # local libvirt host
#   ./supplemental/scripts/debug-libvirt.sh --remote     # SSH via .deploy-agent.env
#   ./supplemental/scripts/debug-libvirt.sh --remote --fix-perms

set -u

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE=0
FIX_PERMS=0

while [ $# -gt 0 ]; do
	case "$1" in
	--remote) REMOTE=1 ;;
	--fix-perms) FIX_PERMS=1 ;;
	-h | --help)
		sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) echo "Unknown option: $1" >&2; exit 1 ;;
	esac
	shift
done

run_checks() {
	echo "=== Libvirt debug ($(hostname)) ==="
	echo

	if [ ! -d /run/libvirt/qemu ] && [ ! -d /sys/fs/cgroup/machine.slice ]; then
		echo "NOTE: This machine does not look like a libvirt/KVM host."
		echo "      Run on the agent host, or use: $0 --remote"
		echo
	fi

	echo "--- 1) Agent service ---"
	if systemctl is-active beszel-agent >/dev/null 2>&1; then
		echo "beszel-agent: active"
		systemctl show beszel-agent -p ExecStart,User,ReadOnlyPaths --no-pager
	else
		echo "beszel-agent: NOT running (or not systemd-managed)"
	fi
	echo

	echo "--- 2) Recent agent libvirt logs ---"
	journalctl -u beszel-agent --no-pager -n 100 2>/dev/null | grep -iE 'libvirt|network interface' | tail -15 || echo "(no libvirt log lines)"
	echo

	echo "--- 3) Libvirt runtime ---"
	if [ -d /run/libvirt/qemu ]; then
		echo "OK  /run/libvirt/qemu ($(ls -1 /run/libvirt/qemu 2>/dev/null | wc -l | tr -d ' ') files)"
		ls -la /run/libvirt/qemu 2>/dev/null | head -5
	else
		echo "MISS /run/libvirt/qemu"
	fi
	echo

	echo "--- 4) VM cgroups ---"
	for p in \
		/sys/fs/cgroup/machine.slice \
		/sys/fs/cgroup/system.slice/libvirtd.service/machine.slice \
		/sys/fs/cgroup/system.slice/virtqemud.service/machine.slice; do
		if [ -d "$p" ]; then
			count=$(ls -1 "$p" 2>/dev/null | grep -c '^machine-qemu' || true)
			echo "OK  $p ($count machine-qemu entries)"
		else
			echo "MISS $p"
		fi
	done
	echo

	AGENT_user="${BESZEL_AGENT_user:-beszel}"
	echo "--- 5) beszel: runtime XML + tap stats (VM network requires both) ---"
	if id "$AGENT_user" >/dev/null 2>&1; then
		xml=$(ls /run/libvirt/qemu/*.xml 2>/dev/null | head -1)
		if [ -n "$xml" ]; then
			if sudo -u "$AGENT_user" test -r "$xml"; then
				echo "OK  can read runtime XML: $(basename "$xml")"
			else
				echo "FAIL cannot read runtime XML ($(basename "$xml")) — VM network stays 0"
				echo "     Fix: supplemental/scripts/libvirt-agent-perms.sh (as root on this host)"
			fi
		else
			echo "(no runtime XML files)"
		fi
		vnet=$(ls /sys/class/net 2>/dev/null | grep -E '^vnet[0-9]+$' | head -1)
		if [ -n "$vnet" ]; then
			if sudo -u "$AGENT_user" test -r "/sys/class/net/$vnet/statistics/rx_bytes"; then
				echo "OK  can read /sys/class/net/$vnet/statistics/rx_bytes"
			else
				echo "WARN cannot read tap stats for $vnet"
			fi
		fi
	else
		echo "User $AGENT_user not found"
	fi
	echo

	echo "--- 6) systemd sandbox ---"
	if command -v systemd-run >/dev/null 2>&1 && id "$AGENT_user" >/dev/null 2>&1; then
		vnet=$(ls /sys/class/net 2>/dev/null | grep -E '^vnet[0-9]+$' | head -1)
		if [ -n "$vnet" ]; then
			if systemd-run --wait --pipe --uid="$AGENT_user" \
				-p ProtectSystem=strict \
				-p ReadOnlyPaths=/run/libvirt \
				-p ReadOnlyPaths=/sys/fs/cgroup \
				-p ReadOnlyPaths=/sys/class/net \
				cat "/sys/class/net/$vnet/statistics/rx_bytes" >/dev/null 2>&1; then
				echo "OK  sandbox can read tap stats (ReadOnlyPaths includes /sys/class/net)"
			else
				echo "FAIL sandbox blocks tap stats"
			fi
		fi
	else
		echo "(skip — macOS or no systemd-run)"
	fi
	echo

	echo "=== Expected after XML + agent fix ==="
	echo "  libvirt_vm_stats JSON includes \"b\":[tx,rx] per VM (~60s after restart)"
}

if [ "$REMOTE" -eq 1 ]; then
	# shellcheck disable=SC1091
	. "$ROOT_DIR/supplemental/scripts/deploy-load-env.sh"
	deploy_load_env "$ROOT_DIR/.deploy-agent.env"
	DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
	SSH_ARGS=()
	[ "$DEPLOY_SSH_PORT" != "22" ] && SSH_ARGS=(-p "$DEPLOY_SSH_PORT")
	REMOTE_HOST="${DEPLOY_AGENT_REMOTE#*@}"
	REMOTE_user="${DEPLOY_AGENT_REMOTE%@*}"
	[ "$REMOTE_user" = "$DEPLOY_AGENT_REMOTE" ] && REMOTE_user=root
	SSH_TARGET="${REMOTE_user}@${REMOTE_HOST}"

	if [ "$FIX_PERMS" -eq 1 ]; then
		echo "==> Applying libvirt XML permissions on $SSH_TARGET"
		scp "${SSH_ARGS[@]}" "$ROOT_DIR/supplemental/scripts/libvirt-agent-perms.sh" "${SSH_TARGET}":/tmp/libvirt-agent-perms.sh
		ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "chmod +x /tmp/libvirt-agent-perms.sh && /tmp/libvirt-agent-perms.sh && systemctl restart beszel-agent"
	fi

	ssh "${SSH_ARGS[@]}" "$SSH_TARGET" 'bash -s' <<'REMOTE'
# inlined checks (same as run_checks, no bash export of function)
echo "=== Libvirt debug ($(hostname)) ==="
AGENT_user="${BESZEL_AGENT_user:-beszel}"
systemctl is-active beszel-agent 2>/dev/null && systemctl show beszel-agent -p ReadOnlyPaths --value
xml=$(ls /run/libvirt/qemu/*.xml 2>/dev/null | head -1)
if [ -n "$xml" ]; then
  sudo -u "$AGENT_user" test -r "$xml" && echo "OK XML readable: $(basename "$xml")" || echo "FAIL XML not readable: $(basename "$xml")"
fi
journalctl -u beszel-agent --no-pager -n 20 | grep -iE 'libvirt|network interface' || true
REMOTE
	exit 0
fi

if [ "$FIX_PERMS" -eq 1 ]; then
	bash "$ROOT_DIR/supplemental/scripts/libvirt-agent-perms.sh"
	systemctl restart beszel-agent 2>/dev/null || true
fi

run_checks
