#!/bin/sh
# Refresh the ET Open ruleset used by the local Suricata sensor.
#
# Runs from a systemd timer. The upstream is fetched with a long timeout: this
# network throttles rules.emergingthreats.net to ~50 KB/s, so a 46 MB ruleset
# needs 15-20 minutes.
#
# Offline / mirror support:
#   ET_OPEN_LOCAL_FILE=/path/et-open.rules   use this file, no download
#   ET_OPEN_MIRROR_URL=https://...           try the mirror first
#
# Signatures this Suricata build cannot parse (disabled app-layer protocols such
# as ssh/smb) are removed automatically by SID, so one bad rule never blocks the
# whole refresh. A failed refresh keeps the previous ruleset.
set -eu

PROFILE=/opt/ly-flow-platform/suricata/lyflow-suricata-profile.yaml
CONTAINER_PROFILE=/etc/suricata/lyflow-suricata-profile.yaml
RULES_DIR=/opt/ly-flow-platform/suricata/rules
TARGET="$RULES_DIR/et-open.rules"
CONTAINER=ly-flow-platform-ly-suricata-sensor-1
PRIMARY="${ET_OPEN_URL:-https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules}"
MIRROR="${ET_OPEN_MIRROR_URL:-}"
LOCAL="${ET_OPEN_LOCAL_FILE:-}"
TIMEOUT="${ET_OPEN_TIMEOUT:-2400}"
VALIDATE_LOG=/tmp/et-open-validate.log

log() { printf '%s et-open-refresh: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ -d "$RULES_DIR" ] || die "rules dir missing: $RULES_DIR"
STAGE="$(mktemp "$RULES_DIR/.et-open.XXXXXX")"
trap 'rm -f "$STAGE" "$STAGE.filtered"' EXIT

if [ -n "$LOCAL" ]; then
    [ -r "$LOCAL" ] || die "ET_OPEN_LOCAL_FILE not readable: $LOCAL"
    log "importing local ruleset $LOCAL"
    cp "$LOCAL" "$STAGE"
else
    URL="$PRIMARY"
    [ -n "$MIRROR" ] && URL="$MIRROR"
    log "downloading $URL (timeout ${TIMEOUT}s)"
    curl -fsS --max-time "$TIMEOUT" --retry 2 --retry-delay 5 -o "$STAGE" "$URL" \
        || die "download failed"
    if [ -n "$MIRROR" ] && [ "$(wc -c <"$STAGE")" -lt 1000000 ]; then
        log "mirror returned a short file, retrying upstream"
        curl -fsS --max-time "$TIMEOUT" --retry 2 --retry-delay 5 -o "$STAGE" "$PRIMARY" \
            || die "upstream download failed"
    fi
fi

# Drop low-value rule families before validation. ET INFO/POLICY/HUNTING
# fire on ordinary traffic and drown the attack signatures.
DROP_PREFIXES="${ET_OPEN_DROP_PREFIXES:-ET INFO,ET POLICY,ET HUNTING,ET USER_AGENTS,ET CURRENT_EVENTS,ET GAMES,ET P2P,ET CHAT,ET SNMP}"
old_ifs=$IFS
IFS=','
for prefix in $DROP_PREFIXES; do
    [ -n "$prefix" ] || continue
    dropped=$(grep -c "msg:\"$prefix" "$STAGE" || true)
    if [ "$dropped" -gt 0 ]; then
        grep -v "msg:\"$prefix" "$STAGE" >"$STAGE.filtered"
        cat "$STAGE.filtered" >"$STAGE"
        rm -f "$STAGE.filtered"
        log "dropped $dropped rules from family '$prefix'"
    fi
done
IFS=$old_ifs
SIZE=$(wc -c <"$STAGE")
COUNT=$(grep -c '^alert' "$STAGE" || true)
log "staged size=$SIZE alert_rules=$COUNT"
[ "$SIZE" -gt 1000000 ] || die "ruleset too small ($SIZE bytes)"
[ "$COUNT" -gt 10000 ] || die "ruleset has too few alert rules ($COUNT)"

validate() {
    docker cp "$STAGE" "$CONTAINER:/var/lib/suricata/rules/et-open/et-open.rules.new" >/dev/null 2>&1 || return 1
    docker exec "$CONTAINER" suricata -T -c "$CONTAINER_PROFILE" \
        -S /var/lib/suricata/rules/et-open/et-open.rules.new >"$VALIDATE_LOG" 2>&1
}

validated=0
attempt=1
while [ "$attempt" -le 4 ]; do
    if validate; then
        validated=1
        break
    fi
    sids=$(grep -oE 'sid:[0-9]+' "$VALIDATE_LOG" | cut -d: -f2 | sort -u | paste -sd'|' - || true)
    if [ -z "$sids" ]; then
        tail -n 8 "$VALIDATE_LOG" >&2 || true
        break
    fi
    dropped=$(printf '%s\n' "$sids" | tr '|' '\n' | wc -l)
    log "attempt $attempt: removing $dropped signatures this build rejects"
    grep -vE "sid:(${sids});" "$STAGE" >"$STAGE.filtered"
    cat "$STAGE.filtered" >"$STAGE"
    rm -f "$STAGE.filtered"
    attempt=$((attempt + 1))
done
if [ "$validated" -ne 1 ]; then
    docker exec "$CONTAINER" rm -f /var/lib/suricata/rules/et-open/et-open.rules.new >/dev/null 2>&1 || true
    die "suricata -T rejected the ruleset; keeping current rules"
fi

mv "$STAGE" "$TARGET"
trap - EXIT
chmod 0644 "$TARGET"
docker exec "$CONTAINER" rm -f /var/lib/suricata/rules/et-open/et-open.rules.new >/dev/null 2>&1 || true
CUSTOM=$(grep -c '^alert' /opt/ly-flow-platform/rules/compiled/server-zone/suricata.rules 2>/dev/null || echo 0)
TOTAL=$(grep -c '^alert' "$TARGET" || true)
MANIFEST=/opt/ly-flow-platform/.sisyphus/runtime/engine-outputs/suricata-profile/ruleset.json
mkdir -p "$(dirname "$MANIFEST")"
printf '{"et_open_rules":%s,"custom_rules":%s,"total_rules":%s,"updated_at":"%s","source":"et-open"}\n' \
    "$TOTAL" "$CUSTOM" "$((TOTAL + CUSTOM))" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$MANIFEST"
log "installed $TARGET ($TOTAL rules), manifest $MANIFEST"

if ! docker exec "$CONTAINER" suricatasc -c reload-rules >/dev/null 2>&1; then
    log "reload socket unavailable, restarting sensor"
    docker restart "$CONTAINER" >/dev/null
fi
log "sensor reloaded"
