#!/bin/sh
# Sync the reverse-proxy allowlist into xdr_trusted_proxies.
#
# The server reads this table at startup. Add or move proxies by editing
# .env, then run this script (and optionally restart ly-server):
#
#   XDR_TRUSTED_PROXY_CIDRS="10.1.18.251/32 10.1.18.252/32"
#   XDR_TRUSTED_PROXY_FILE=/opt/ly-flow-platform/trusted-proxies.txt
#
# No image rebuild or code change is required.
set -eu

PLATFORM_DIR=${LYFLOW_PLATFORM_DIR:-/opt/ly-flow-platform}
ENV_FILE="$PLATFORM_DIR/.env"
PSQL_CONTAINER=${LYFLOW_POSTGRES_CONTAINER:-ly-flow-platform-postgres-1}
TENANT=${XDR_DEFAULT_TENANT:-default}
RESTART=0

if [ "${1:-}" = "--restart" ]; then
    RESTART=1
fi

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

list="${XDR_TRUSTED_PROXY_CIDRS:-}"
file="${XDR_TRUSTED_PROXY_FILE:-}"
if [ -n "$file" ] && [ -r "$file" ]; then
    list="$list $(tr '\n' ' ' <"$file")"
fi

list=$(printf '%s' "$list" | tr ',' ' ')
values=""
for cidr in $list; do
    [ -n "$cidr" ] || continue
    case "$cidr" in
        */*) ;;
        *) echo "skip invalid CIDR: $cidr" >&2; continue ;;
    esac
    values="$values${values:+,}('$TENANT','$cidr','reverse proxy',100)"
done

if [ -z "$values" ]; then
    echo "no XDR_TRUSTED_PROXY_CIDRS / XDR_TRUSTED_PROXY_FILE entries; nothing to sync"
    exit 0
fi

sql="INSERT INTO xdr_trusted_proxies (tenant_id, cidr, description, priority)
VALUES $values
ON CONFLICT (tenant_id, cidr) DO UPDATE
SET description=EXCLUDED.description, priority=EXCLUDED.priority;
SELECT tenant_id || ' | ' || cidr || ' | ' || description || ' | ' || priority
FROM xdr_trusted_proxies ORDER BY priority DESC, cidr;"

printf '%s\n' "$sql" | sudo docker exec -i "$PSQL_CONTAINER" psql -U lyflow -d lyflow -v ON_ERROR_STOP=1

if [ "$RESTART" -eq 1 ]; then
    (cd "$PLATFORM_DIR" && sudo docker compose up -d --no-deps --force-recreate ly-server)
    echo "ly-server restarted to reload trusted proxies"
fi
