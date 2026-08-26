#!/usr/bin/env bash
# Polls PostgreSQL and Redis until both accept connections, or times out.
# Useful after `make dev-up` in scripts/CI where you can't wait on Docker's
# own healthchecks directly (e.g. before running `go run ./cmd/migrate up`).
#
# Usage: scripts/dev/wait-for-services.sh [timeout_seconds]

set -euo pipefail

TIMEOUT="${1:-60}"
DB_HOST="${AI_RECON_DATABASE_HOST:-localhost}"
DB_PORT="${AI_RECON_DATABASE_PORT:-5432}"
REDIS_ADDRESS="${AI_RECON_REDIS_ADDRESS:-localhost:6379}"
REDIS_HOST="${REDIS_ADDRESS%%:*}"
REDIS_PORT="${REDIS_ADDRESS##*:}"

wait_for_port() {
	local name="$1" host="$2" port="$3" deadline
	deadline=$((SECONDS + TIMEOUT))
	echo "waiting for ${name} at ${host}:${port} (timeout ${TIMEOUT}s)..."
	until (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			echo "timed out waiting for ${name} at ${host}:${port}" >&2
			exit 1
		fi
		sleep 1
	done
	exec 3>&- 3<&- 2>/dev/null || true
	echo "${name} is accepting connections"
}

wait_for_port "PostgreSQL" "$DB_HOST" "$DB_PORT"
wait_for_port "Redis" "$REDIS_HOST" "$REDIS_PORT"
