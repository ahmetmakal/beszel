#!/usr/bin/env bash
# Build Beszel hub locally and deploy to a remote Docker host without git push.
#
# Setup (once):
#   cp .deploy-hub.env.example .deploy-hub.env
#   # edit .deploy-hub.env
#   # on server: copy supplemental/docker/hub/docker-compose.override.example.yml
#   #   to $DEPLOY_COMPOSE_DIR/docker-compose.override.yml
#
# Usage:
#   ./supplemental/scripts/deploy-hub.sh              # rsync + build on server (default)
#   ./supplemental/scripts/deploy-hub.sh --load       # build locally, docker save | ssh load
#   ./supplemental/scripts/deploy-hub.sh --skip-frontend
#   ./supplemental/scripts/deploy-hub.sh --frontend-remote  # build UI on server (no local bun/npm)
#   ./supplemental/scripts/deploy-hub.sh --no-restart # build/tag only
#   ./supplemental/scripts/deploy-hub.sh --env /path/to/custom.env
#   ./supplemental/scripts/deploy-hub.sh --help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
# shellcheck disable=SC1091
. "$ROOT_DIR/supplemental/scripts/deploy-load-env.sh"

MODE="remote"
FRONTEND="auto"
NO_RESTART=0

usage() {
	sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--load) MODE="load" ;;
	--remote) MODE="remote" ;;
	--skip-frontend) FRONTEND="skip" ;;
	--frontend-local) FRONTEND="local" ;;
	--frontend-remote) FRONTEND="remote" ;;
	--no-restart) NO_RESTART=1 ;;
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

deploy_load_env "$ROOT_DIR/.deploy-hub.env"

DEPLOY_REMOTE="${DEPLOY_REMOTE:-}"
DEPLOY_COMPOSE_DIR="${DEPLOY_COMPOSE_DIR:-~/beszel}"
DEPLOY_SRC_DIR="${DEPLOY_SRC_DIR:-~/beszel/src}"
DEPLOY_HUB_IMAGE="${DEPLOY_HUB_IMAGE:-ghcr.io/ahmetmakal/beszel/beszel:dev}"
DEPLOY_PLATFORM="${DEPLOY_PLATFORM:-linux/amd64}"
DEPLOY_FRONTEND="${DEPLOY_FRONTEND:-$FRONTEND}"
FRONTEND="$DEPLOY_FRONTEND"
DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"

SSH_ARGS=()
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	SSH_ARGS=(-p "$DEPLOY_SSH_PORT")
fi
if [ -n "${DEPLOY_SSH_OPTS:-}" ]; then
	# shellcheck disable=SC2206
	extra=($DEPLOY_SSH_OPTS)
	SSH_ARGS+=("${extra[@]}")
fi

RSYNC_RSH="ssh"
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	RSYNC_RSH="ssh -p $DEPLOY_SSH_PORT"
fi
if [ -n "${DEPLOY_SSH_OPTS:-}" ]; then
	RSYNC_RSH="$RSYNC_RSH $DEPLOY_SSH_OPTS"
fi

run_ssh() {
	ssh "${SSH_ARGS[@]}" "$@"
}

run_rsync() {
	rsync -e "$RSYNC_RSH" "$@"
}

if [ -z "$DEPLOY_REMOTE" ]; then
	echo "DEPLOY_REMOTE is not set. Copy .deploy-hub.env.example to .deploy-hub.env and configure it." >&2
	exit 1
fi

REMOTE_HOST="${DEPLOY_REMOTE#*@}"
REMOTE_USER="${DEPLOY_REMOTE%@*}"
if [ "$REMOTE_USER" = "$DEPLOY_REMOTE" ] || [ -z "$REMOTE_USER" ]; then
	REMOTE_USER="root"
fi
SSH_TARGET="${REMOTE_USER}@${REMOTE_HOST}"

expand_remote_path() {
	local path="$1"
	if [ "${path#\~/}" != "$path" ]; then
		if [ "$REMOTE_USER" = "root" ]; then
			path="/root/${path#~/}"
		else
			path="/home/${REMOTE_USER}/${path#~/}"
		fi
	fi
	printf '%s' "$path"
}

COMPOSE_DIR="$(expand_remote_path "$DEPLOY_COMPOSE_DIR")"
SRC_DIR="$(expand_remote_path "$DEPLOY_SRC_DIR")"

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Required command not found: $1" >&2
		exit 1
	fi
}

local_pm() {
	if command -v bun >/dev/null 2>&1; then
		echo bun
	elif command -v npm >/dev/null 2>&1; then
		echo npm
	fi
}

run_site_build() {
	local pm="$1"
	local site_dir="$2"
	cd "$site_dir"
	case "$pm" in
	bun)
		bun install --no-save
		bun run build
		;;
	npm)
		if [ -f package-lock.json ]; then
			npm ci --no-audit --no-fund
		else
			npm install --no-audit --no-fund
		fi
		npm run build
		;;
	*)
		return 1
		;;
	esac
}

build_frontend_local() {
	if [ "$FRONTEND" = "skip" ]; then
		if [ ! -d "$ROOT_DIR/internal/site/dist" ]; then
			echo "internal/site/dist missing. Run without --skip-frontend or build manually." >&2
			exit 1
		fi
		echo "==> Skipping frontend build (using existing dist/)"
		return 0
	fi

	local pm
	pm="$(local_pm || true)"
	if [ -z "$pm" ]; then
		return 1
	fi

	echo "==> Building frontend locally ($pm)"
	run_site_build "$pm" "$ROOT_DIR/internal/site"
}

build_frontend_remote() {
	require_cmd ssh
	echo "==> Building frontend on ${SSH_TARGET} (Docker + bun)"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		site_dir='$SRC_DIR/internal/site'
		if [ ! -f \"\$site_dir/package.json\" ]; then
			echo 'package.json not found in '\$site_dir >&2
			exit 1
		fi
		docker run --rm \\
			-v \"\$site_dir:/site\" \\
			-w /site \\
			oven/bun:1-alpine \\
			sh -c 'bun install --no-save && bun run build'
	"
}

resolve_frontend_plan() {
	if [ "$FRONTEND" = "skip" ] || [ "$FRONTEND" = "remote" ] || [ "$FRONTEND" = "local" ]; then
		return
	fi
	if [ "$FRONTEND" != "auto" ]; then
		echo "Unknown DEPLOY_FRONTEND: $FRONTEND (use auto, local, remote, or skip)" >&2
		exit 1
	fi
	if local_pm >/dev/null; then
		FRONTEND="local"
	elif [ "$MODE" = "remote" ]; then
		FRONTEND="remote"
		echo "==> No local bun/npm found; will build frontend on server after sync"
	else
		echo "No bun or npm found locally. Options:" >&2
		echo "  - Install bun:  curl -fsSL https://bun.sh/install | bash" >&2
		echo "  - Install Node.js/npm" >&2
		echo "  - Use remote mode (default): ./supplemental/scripts/deploy-hub.sh" >&2
		echo "  - Force remote UI build:     ./supplemental/scripts/deploy-hub.sh --frontend-remote" >&2
		exit 1
	fi
}

rsync_source() {
	require_cmd rsync
	require_cmd ssh

	echo "==> Syncing source to ${SSH_TARGET}:${SRC_DIR}"
	run_ssh "$SSH_TARGET" "mkdir -p '$SRC_DIR'"

	run_rsync -az --delete \
		--exclude '.git/' \
		--exclude '.deploy.env' \
		--exclude '.deploy-hub.env' \
		--exclude '.deploy-agent.env' \
		--exclude 'beszel_data/' \
		--exclude 'beszel_data*/' \
		--exclude 'pb_data/' \
		--exclude 'node_modules/' \
		--exclude 'internal/site/node_modules/' \
		--exclude '.idea/' \
		--exclude '.vscode/' \
		--exclude '*.exe' \
		--exclude 'internal/cmd/hub/hub' \
		--exclude 'internal/cmd/agent/agent' \
		"$ROOT_DIR/" "${SSH_TARGET}:${SRC_DIR}/"
}

remote_build_and_restart() {
	echo "==> Building image on ${SSH_TARGET}"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		docker build -f '$SRC_DIR/internal/dockerfile_hub' -t '$DEPLOY_HUB_IMAGE' '$SRC_DIR'
	"

	if [ "$NO_RESTART" -eq 1 ]; then
		echo "==> Done (image tagged as $DEPLOY_HUB_IMAGE on server)"
		return
	fi

	echo "==> Restarting hub container"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		cd '$COMPOSE_DIR'
		if [ ! -f docker-compose.yml ]; then
			echo 'docker-compose.yml not found in $COMPOSE_DIR' >&2
			exit 1
		fi
		export BESZEL_HUB_IMAGE='$DEPLOY_HUB_IMAGE'
		compose_files='-f docker-compose.yml'
		if [ -f docker-compose.override.yml ]; then
			compose_files=\"\$compose_files -f docker-compose.override.yml\"
		fi
		docker compose \$compose_files up -d --force-recreate --no-deps beszel
		docker compose \$compose_files ps beszel
	"
}

local_build_and_load() {
	require_cmd docker
	require_cmd ssh

	echo "==> Building image locally ($DEPLOY_PLATFORM)"
	docker buildx build \
		--platform "$DEPLOY_PLATFORM" \
		-f "$ROOT_DIR/internal/dockerfile_hub" \
		-t "$DEPLOY_HUB_IMAGE" \
		--load \
		"$ROOT_DIR"

	if [ "$NO_RESTART" -eq 1 ]; then
		echo "==> Done (local image $DEPLOY_HUB_IMAGE)"
		return
	fi

	echo "==> Loading image on ${SSH_TARGET}"
	docker save "$DEPLOY_HUB_IMAGE" | run_ssh "$SSH_TARGET" "docker load"

	echo "==> Restarting hub container"
	run_ssh "$SSH_TARGET" "set -euo pipefail
		cd '$COMPOSE_DIR'
		export BESZEL_HUB_IMAGE='$DEPLOY_HUB_IMAGE'
		compose_files='-f docker-compose.yml'
		if [ -f docker-compose.override.yml ]; then
			compose_files=\"\$compose_files -f docker-compose.override.yml\"
		fi
		docker compose \$compose_files up -d --force-recreate --no-deps beszel
		docker compose \$compose_files ps beszel
	"
}

echo "Deploy target: $SSH_TARGET"
if [ -n "${DEPLOY_ENV_FILE:-}" ]; then
	echo "Env file:      $DEPLOY_ENV_FILE"
fi
if [ "$DEPLOY_SSH_PORT" != "22" ]; then
	echo "SSH port:      $DEPLOY_SSH_PORT"
fi
echo "Compose dir:   $COMPOSE_DIR"
echo "Image tag:     $DEPLOY_HUB_IMAGE"
echo "Mode:          $MODE"
echo

resolve_frontend_plan
echo "Frontend:      $FRONTEND"
echo

if [ "$FRONTEND" = "local" ] || [ "$FRONTEND" = "skip" ]; then
	if [ "$FRONTEND" = "local" ] && ! build_frontend_local; then
		if [ "$MODE" = "remote" ]; then
			echo "==> Local frontend build unavailable; falling back to remote"
			FRONTEND="remote"
		else
			exit 1
		fi
	fi
	if [ "$FRONTEND" = "skip" ]; then
		build_frontend_local
	fi
fi

case "$MODE" in
remote)
	rsync_source
	if [ "$FRONTEND" = "remote" ]; then
		build_frontend_remote
	fi
	remote_build_and_restart
	;;
load)
	if [ "$FRONTEND" = "remote" ]; then
		echo "--frontend-remote is not supported with --load (build the UI locally or rsync first)." >&2
		exit 1
	fi
	local_build_and_load
	;;
*)
	echo "Unknown mode: $MODE" >&2
	exit 1
	;;
esac

echo
echo "Hub deploy finished."
