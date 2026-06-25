#!/usr/bin/env bash
# Grant beszel-agent read access to libvirt QEMU runtime XML (vnet target dev).
# Run on the libvirt host as root. Safe to re-run after deploy or libvirt upgrade.
#
# Usage:
#   ./supplemental/scripts/libvirt-agent-perms.sh
#   BESZEL_AGENT_user=beszel ./supplemental/scripts/libvirt-agent-perms.sh

set -euo pipefail

AGENT_user="${BESZEL_AGENT_user:-beszel}"
QEMU_DIR="/run/libvirt/qemu"
DEFINED_DIR="/etc/libvirt/qemu"

if [ ! -d "$QEMU_DIR" ] && [ -d "/var/run/libvirt/qemu" ]; then
	QEMU_DIR="/var/run/libvirt/qemu"
fi

if ! id "$AGENT_user" >/dev/null 2>&1; then
	echo "User not found: $AGENT_user" >&2
	exit 1
fi

if [ ! -d "$QEMU_DIR" ]; then
	echo "No libvirt runtime dir ($QEMU_DIR); nothing to do."
	exit 0
fi

apply_acl() {
	local path="$1"
	local perms="$2"
	if command -v setfacl >/dev/null 2>&1; then
		setfacl -m "u:${AGENT_user}:${perms}" "$path"
	else
		echo "WARN: setfacl not found; install acl package for persistent libvirt XML access" >&2
		return 1
	fi
}

echo "==> Libvirt XML permissions for $AGENT_user"

# Directory traverse + default ACL so new VM xml/pid files stay readable
apply_acl "$QEMU_DIR" "rx"
setfacl -d -m "u:${AGENT_user}:r" "$QEMU_DIR" 2>/dev/null || true
find "$QEMU_DIR" -type f -exec setfacl -m "u:${AGENT_user}:r" {} + 2>/dev/null || true
# -R above must not strip directory execute; ensure traverse bit remains
apply_acl "$QEMU_DIR" "rx"

if [ -d "$DEFINED_DIR" ]; then
	apply_acl "$DEFINED_DIR" "rx" || true
	find "$DEFINED_DIR" -type f -exec setfacl -m "u:${AGENT_user}:r" {} + 2>/dev/null || true
	apply_acl "$DEFINED_DIR" "rx" || true
fi

sample=$(ls "$QEMU_DIR"/*.xml 2>/dev/null | head -1 || true)
if [ -n "$sample" ]; then
	if sudo -u "$AGENT_user" test -r "$sample"; then
		echo "OK  $AGENT_user can read $(basename "$sample")"
	else
		echo "FAIL $AGENT_user still cannot read $sample" >&2
		exit 1
	fi
fi

echo "Done. Restart beszel-agent if it was already running."
