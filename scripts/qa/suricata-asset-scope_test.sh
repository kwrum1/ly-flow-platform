#!/usr/bin/env bash
# Acceptance test for P0-1 asset scope.
#
# The contract: HOME_NET is the set of protected assets, so a direction-specific
# signature must fire when the protected web tier is hit, and must not fire when
# the identical payload is sent between two hosts that are not protected.
#
# This is the test that distinguishes the two wrong profiles from the right one:
#   HOME_NET = any        -> alerts on all four sessions (no direction at all)
#   HOME_NET = RFC1918    -> alerts on none of the four (attacker is "home")
#   HOME_NET = server zone + NAT -> alerts on exactly the two protected sessions
#
# Requires: docker, python3, and a Suricata image.
#   SURICATA_IMAGE=ly-flow/suricata-profile:v67 scripts/qa/suricata-asset-scope_test.sh
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=${SURICATA_IMAGE:-ly-flow/suricata-profile:v67}
renderer="$root/deploy/suricata/render-profile.sh"
template="$root/deploy/suricata/lyflow-suricata-profile.tmpl.yaml"
pcapgen="$root/scripts/qa/suricata-asset-scope-pcap.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

for command in docker python3; do
    command -v "$command" >/dev/null 2>&1 || { printf 'missing required command: %s\n' "$command" >&2; exit 2; }
done
for path in "$renderer" "$template" "$pcapgen"; do
    [ -f "$path" ] || { printf 'missing required file: %s\n' "$path" >&2; exit 2; }
done

# The real signature from this deployment (ET Open sid 2049400), verbatim shape:
# an inbound-only rule guarded by $EXTERNAL_NET -> $HTTP_SERVERS.
cat >"$work/scope.rules" <<'RULES'
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER /etc/passwd Detected in URI"; flow:established,to_server; http.uri; content:"/etc/passwd"; nocase; classtype:attempted-recon; sid:2049400; rev:1;)
RULES

python3 "$pcapgen" "$work/scope.pcap" >/dev/null || { printf 'pcap generation failed\n' >&2; exit 2; }

run_variant() {
    local name="$1" home="$2"
    local dir="$work/$name"
    mkdir -p "$dir"
    if [ "$home" = any ]; then
        # The renderer refuses "any" by design, so the broken baseline is built by
        # patching a correct render. This mirrors how the regression actually got in:
        # a hand edit that collapsed the two direction variables.
        SURICATA_TEMPLATE="$template" SURICATA_HOME_NET='[10.1.18.0/24]' \
            SURICATA_INTERFACE=mirror0 SURICATA_THREADS=1 \
            bash "$renderer" --output "$dir/profile.yaml" >"$dir/render.log" 2>&1 || return 1
        sed -i -e 's|^    HOME_NET: .*|    HOME_NET: "any"|' \
               -e 's|^    EXTERNAL_NET: .*|    EXTERNAL_NET: "any"|' "$dir/profile.yaml"
    else
        SURICATA_TEMPLATE="$template" SURICATA_HOME_NET="$home" \
            SURICATA_INTERFACE=mirror0 SURICATA_THREADS=1 \
            bash "$renderer" --output "$dir/profile.yaml" >"$dir/render.log" 2>&1 || {
                printf 'render failed for %s: %s\n' "$name" "$(cat "$dir/render.log")" >&2
                return 1
            }
    fi
    docker run --rm --network none --pull never --entrypoint suricata \
        -v "$dir/profile.yaml:/evidence/profile.yaml:ro" \
        -v "$work/scope.rules:/evidence/scope.rules:ro" \
        -v "$work/scope.pcap:/evidence/scope.pcap:ro" \
        -v "$dir:/var/log/suricata" \
        "$image" -c /evidence/profile.yaml -S /evidence/scope.rules \
        -r /evidence/scope.pcap -l /var/log/suricata --runmode single \
        >"$dir/suricata.log" 2>&1
    [ -f "$dir/eve.json" ] || {
        { printf '%s\n' "no eve output for $name"; tail -n 20 "$dir/suricata.log" || true; ls -la "$dir" || true; } >&2
        return 1
    }
}

# Which destination IPs alerted?
alerted_dsts() {
    python3 - "$1" <<'PY'
import json, sys
seen = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if record.get("event_type") == "alert":
            seen.add(record.get("dest_ip"))
print(",".join(sorted(seen)))
PY
}

ZONE='[10.1.18.0/24,113.194.3.11/32]'
BROAD='[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]'

if run_variant zone "$ZONE" && run_variant broad "$BROAD" && run_variant any 'any'; then
    pass "all three profiles replay the same capture"
else
    fail "replay failed for at least one profile"
    printf '\n%d asset-scope checks failed\n' "$failures" >&2
    exit 1
fi

zone_dsts=$(alerted_dsts "$work/zone/eve.json")
broad_dsts=$(alerted_dsts "$work/broad/eve.json")
any_dsts=$(alerted_dsts "$work/any/eve.json")

printf 'zone  alerted dests: [%s]\n' "$zone_dsts"
printf 'broad alerted dests: [%s]\n' "$broad_dsts"
printf 'any   alerted dests: [%s]\n' "$any_dsts"

# 1. The protected web tier must still be covered.
if printf '%s' "$zone_dsts" | grep -q '10.1.18.253'; then
    pass "server-zone scope still catches the attack on the protected reverse proxy"
else
    fail "server-zone scope lost the attack on 10.1.18.253"
fi
if printf '%s' "$zone_dsts" | grep -q '113.194.3.11'; then
    pass "server-zone scope still catches the attack on the protected public NAT"
else
    fail "server-zone scope lost the attack on 113.194.3.11"
fi

# 2. Non-protected internal hosts must not be treated as inbound targets.
if printf '%s' "$zone_dsts" | grep -qE '10\.(1\.2\.52|20\.215\.161)'; then
    fail "server-zone scope still fires on a non-protected internal host"
else
    pass "server-zone scope ignores the same payload between unprotected hosts"
fi

# 3. any/any over-fires: it is the regression being fixed.
any_count=$(printf '%s' "$any_dsts" | tr ',' '\n' | grep -c . || true)
zone_count=$(printf '%s' "$zone_dsts" | tr ',' '\n' | grep -c . || true)
if [ "$any_count" -gt "$zone_count" ]; then
    pass "any/any over-fires compared with real asset scope ($any_count vs $zone_count targets)"
else
    fail "any/any did not over-fire ($any_count vs $zone_count), the replay is not exercising direction"
fi

# 4. Broad RFC1918 is the other failure mode: the attacker becomes "home".
if [ -z "$broad_dsts" ]; then
    pass "RFC1918-wide HOME_NET loses every detection (documented as unacceptable)"
else
    fail "RFC1918-wide HOME_NET still alerted on [$broad_dsts]; expected the attacker to be classified as home"
fi

printf '\n{"zone_dsts":"%s","broad_dsts":"%s","any_dsts":"%s"}\n' "$zone_dsts" "$broad_dsts" "$any_dsts"

if [ "$failures" -ne 0 ]; then
    printf '\n%d asset-scope checks failed\n' "$failures" >&2
    exit 1
fi
printf '\nsuricata-asset-scope: all checks passed\n'
