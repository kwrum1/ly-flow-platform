#!/bin/sh
# Prune transport_reliability:* hashes by message-ID timestamp.
#
# The hashes store "<unix-ms>-<seq>" message IDs. Entries older than the
# retention are no longer needed because the Redis streams only keep 2 hours.
# Defaults to 24 hours and a dry-run unless RUN=1 is set:
#
#   sudo RUN=1 TRANSPORT_DEDUP_RETENTION_HOURS=24 \
#     /opt/ly-flow-platform/scripts/prune-transport-reliability.sh
#
# Install with the lyflow-redis-prune.timer for a daily run.
set -eu

PLATFORM_DIR=${LYFLOW_PLATFORM_DIR:-/opt/ly-flow-platform}
ENV_FILE="$PLATFORM_DIR/.env"
CONTAINER=${LYFLOW_REDIS_CONTAINER:-ly-flow-platform-redis-1}
HOURS=${TRANSPORT_DEDUP_RETENTION_HOURS:-24}
RUN=${RUN:-0}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LUA="$SCRIPT_DIR/prune-transport.lua"

[ -f "$LUA" ] || { echo "missing $LUA" >&2; exit 1; }
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

case "$HOURS" in
    ''|*[!0-9]*) echo "invalid retention hours: $HOURS" >&2; exit 2;;
esac
[ "$HOURS" -ge 2 ] || { echo "retention must be >= 2 hours (stream retention)" >&2; exit 2; }

now_ms=$(date +%s)
cutoff=$(( (now_ms - HOURS * 3600) * 1000 ))
dry=1
[ "$RUN" = "1" ] && dry=0

sudo docker cp "$LUA" "$CONTAINER:/tmp/prune-transport.lua" >/dev/null
trap 'sudo docker exec "$CONTAINER" rm -f /tmp/prune-transport.lua >/dev/null 2>&1 || true' EXIT

keys=$(sudo docker exec "$CONTAINER" sh -c 'redis-cli -a "$REDIS_PASSWORD" --scan --pattern "transport_reliability:*" 2>/dev/null')
for key in $keys; do
    case "$key" in
        transport_reliability:producers|transport_reliability:retirement_horizon)
            continue;;
    esac
    type=$(sudo docker exec "$CONTAINER" sh -c 'redis-cli -a "$REDIS_PASSWORD" TYPE "$1" 2>/dev/null' sh "$key")
    [ "$type" = "hash" ] || continue
    deleted=$(sudo docker exec "$CONTAINER" sh -c 'redis-cli -a "$REDIS_PASSWORD" --eval /tmp/prune-transport.lua "$1" , "$2" "$3" 2>/dev/null' sh "$key" "$cutoff" "$dry")
    printf '%s: %s entries older than %sh%s\n' "$key" "$deleted" "$HOURS" "$( [ "$dry" = "1" ] && printf ' (dry-run)' || true )"
done

if [ "$dry" = "1" ]; then
    echo "dry-run only; set RUN=1 to delete"
fi
