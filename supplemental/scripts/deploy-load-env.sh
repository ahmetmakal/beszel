# Shared env loader for deploy scripts. Source from deploy-hub.sh / deploy-agent.sh.
# Sets DEPLOY_ENV_FILE to the path that was loaded (or empty).

deploy_load_env() {
	local default_file="$1"
	DEPLOY_ENV_FILE=""

	if [ -n "${DEPLOY_ENV_OVERRIDE:-}" ]; then
		if [ ! -f "$DEPLOY_ENV_OVERRIDE" ]; then
			echo "Env file not found: $DEPLOY_ENV_OVERRIDE" >&2
			exit 1
		fi
		# shellcheck disable=SC1090
		. "$DEPLOY_ENV_OVERRIDE"
		DEPLOY_ENV_FILE="$DEPLOY_ENV_OVERRIDE"
		return
	fi

	if [ -f "$default_file" ]; then
		# shellcheck disable=SC1090
		. "$default_file"
		DEPLOY_ENV_FILE="$default_file"
		return
	fi

	# Legacy fallback (deprecated)
	local legacy="$ROOT_DIR/.deploy.env"
	if [ "$default_file" != "$legacy" ] && [ -f "$legacy" ]; then
		echo "Note: using legacy .deploy.env — prefer $(basename "$default_file")" >&2
		# shellcheck disable=SC1091
		. "$legacy"
		DEPLOY_ENV_FILE="$legacy"
	fi
}
