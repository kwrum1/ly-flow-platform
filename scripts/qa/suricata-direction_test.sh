#!/usr/bin/env bash
# Proves that HOME_NET/EXTERNAL_NET actually gate rule direction.
#
# The regression this guards: a profile with HOME_NET/EXTERNAL_NET = "any" makes
# every inbound-only signature match internal-to-internal and outbound traffic.
# The same synthetic capture is replayed against two profiles that differ only in
# those two values, and the per-direction alert counts must differ.
#
# Requires: docker, a Suricata image, python3.
#   SURICATA_IMAGE=ly-flow/suricata-profile:v67 scripts/qa/suricata-direction_test.sh
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=${SURICATA_IMAGE:-ly-flow/suricata-profile:v67}
template="$root/deploy/suricata/lyflow-suricata-profile.tmpl.yaml"
renderer="$root/deploy/suricata/render-profile.sh"
pcapgen="$root/scripts/qa/suricata-direction-pcap.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

for command in docker python3; do
    command -v "$command" >/dev/null 2>&1 || { printf 'missing required command: %s\n' "$command" >&2; exit 2; }
done
for path in "$template" "$renderer" "$pcapgen"; do
    [ -f "$path" ] || { printf 'missing required file: %s\n' "$path" >&2; exit 2; }
done

# Direction rules: sid 9900001 is inbound-only, 9900002 is outbound-only,
# 9900003 is direction-agnostic. Keeping them in a dedicated rule file means the
# test does not depend on the ET Open content.
cat >"$work/direction.rules" <<'RULES'
alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"DIRTEST inbound only"; content:"public"; sid:9900001; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 5353 (msg:"DIRTEST outbound only"; content:"dirprobe"; sid:9900002; rev:1;)
alert udp any any -> any 9999 (msg:"DIRTEST direction agnostic"; content:"neutral"; sid:9900003; rev:1;)
RULES

# A profile with only the variables and output config the test needs. The
# address-groups block is rewritten per variant; everything else stays identical
# so the only difference between the two runs is direction semantics.
make_profile() {
    local direction="$1" destination="$2"
    local home external
    if [ "$direction" = any ]; then
        home='any'
        external='any'
    else
        home='[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]'
        external='!$HOME_NET'
    fi
    {
        printf '%%YAML 1.1\n---\n'
        printf 'vars:\n  address-groups:\n    HOME_NET: "%s"\n    EXTERNAL_NET: "%s"\n' "$home" "$external"
        printf 'default-log-dir: /var/log/suricata\n'
        printf 'default-rule-path: /var/lib/suricata/rules\n'
        printf 'rule-files:\n  - direction.rules\n'
        printf 'outputs:\n  - eve-log:\n      enabled: yes\n      filename: eve.json\n      types:\n        - alert\n'
    } >"$destination"
}

python3 "$pcapgen" "$work/direction.pcap" >/dev/null || { printf 'pcap generation failed\n' >&2; exit 2; }

run_variant() {
    local name="$1" profile="$2"
    local outdir="$work/$name"
    mkdir -p "$outdir"
    docker run --rm --network none --pull never --entrypoint suricata \
        -v "$profile:/evidence/profile.yaml:ro" \
        -v "$work/direction.rules:/var/lib/suricata/rules/direction.rules:ro" \
        -v "$work/direction.pcap:/evidence/direction.pcap:ro" \
        -v "$outdir:/var/log/suricata" \
        "$image" -c /evidence/profile.yaml -r /evidence/direction.pcap -l /var/log/suricata --runmode single \
        >"$outdir/suricata.log" 2>&1
    [ -f "$outdir/eve.json" ] || { printf 'no eve output for %s\n' "$name" >&2; return 1; }
}

count_alert() {
    local eve="$1" sid="$2"
    python3 - "$eve" "$sid" <<'PY'
import json, sys
path, sid = sys.argv[1], int(sys.argv[2])
total = 0
with open(path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if record.get("event_type") != "alert":
            continue
        if (record.get("alert") or {}).get("signature_id") == sid:
            total += 1
print(total)
PY
}

make_profile any "$work/profile-any.yaml"
make_profile cidr "$work/profile-cidr.yaml"

if run_variant any "$work/profile-any.yaml" && run_variant cidr "$work/profile-cidr.yaml"; then
    pass "both profiles replay the same capture"
else
    fail "replay failed for at least one profile"
    printf '\n%d direction checks failed\n' "$failures" >&2
    exit 1
fi

inbound_any=$(count_alert "$work/any/eve.json" 9900001)
inbound_cidr=$(count_alert "$work/cidr/eve.json" 9900001)
outbound_any=$(count_alert "$work/any/eve.json" 9900002)
outbound_cidr=$(count_alert "$work/cidr/eve.json" 9900002)
agnostic_any=$(count_alert "$work/any/eve.json" 9900003)
agnostic_cidr=$(count_alert "$work/cidr/eve.json" 9900003)

printf 'inbound-only  alerts: any=%s cidr=%s\n' "$inbound_any" "$inbound_cidr"
printf 'outbound-only alerts: any=%s cidr=%s\n' "$outbound_any" "$outbound_cidr"
printf 'any->any      alerts: any=%s cidr=%s\n' "$agnostic_any" "$agnostic_cidr"

# With any/any an inbound-only rule also matches internal->internal, so it must
# fire strictly more often than with real direction semantics.
if [ "$inbound_any" -gt "$inbound_cidr" ]; then
    pass "inbound-only rule fires more with any/any (direction is enforced)"
else
    fail "HOME_NET/EXTERNAL_NET do not gate direction (any=$inbound_any cidr=$inbound_cidr)"
fi
if [ "$inbound_cidr" -ge 1 ]; then
    pass "inbound-only rule still catches genuine inbound traffic"
else
    fail "inbound-only rule stopped matching genuine inbound traffic"
fi
if [ "$outbound_any" -ge "$outbound_cidr" ] && [ "$outbound_cidr" -ge 1 ]; then
    pass "outbound-only rule keeps matching genuine egress"
else
    fail "outbound-only rule regressed (any=$outbound_any cidr=$outbound_cidr)"
fi
if [ "$agnostic_any" -eq "$agnostic_cidr" ] && [ "$agnostic_any" -ge 1 ]; then
    pass "any->any rules stay direction-agnostic"
else
    fail "any->any behaviour changed (any=$agnostic_any cidr=$agnostic_cidr)"
fi

printf '\n{"inbound_any":%s,"inbound_cidr":%s,"outbound_any":%s,"outbound_cidr":%s,"agnostic_any":%s,"agnostic_cidr":%s}\n' \
    "$inbound_any" "$inbound_cidr" "$outbound_any" "$outbound_cidr" "$agnostic_any" "$agnostic_cidr"

if [ "$failures" -ne 0 ]; then
    printf '\n%d direction checks failed\n' "$failures" >&2
    exit 1
fi
printf '\nsuricata-direction: all checks passed\n'
