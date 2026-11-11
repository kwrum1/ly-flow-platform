#!/usr/bin/env bash
# Tests for deploy/suricata/render-profile.sh.
#
# The contract under test: the renderer must always produce a profile where
# HOME_NET is a real CIDR list and EXTERNAL_NET is derived from it. The direction
# collapse (HOME_NET/EXTERNAL_NET = "any") that produced 8,000+ misfires must be
# impossible to reintroduce through this path.
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
renderer="$root/deploy/suricata/render-profile.sh"
template="$root/deploy/suricata/lyflow-suricata-profile.tmpl.yaml"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

for required in "$renderer" "$template"; do
    [ -f "$required" ] || { printf 'missing required file: %s\n' "$required" >&2; exit 2; }
done

# 1. default render produces real direction semantics
out="$work/profile.yaml"
if SURICATA_HOME_NET="[10.0.0.0/8,10.1.18.0/24]" SURICATA_INTERFACE=mirror0 SURICATA_THREADS=4 \
    bash "$renderer" --output "$out" >"$work/render.log" 2>&1; then
    home=$(grep -m1 '^[[:space:]]*HOME_NET:' "$out")
    external=$(grep -m1 '^[[:space:]]*EXTERNAL_NET:' "$out")
    if printf '%s' "$home" | grep -q '10.0.0.0/8' && printf '%s' "$external" | grep -q '!\$HOME_NET'; then
        pass "render emits explicit HOME_NET and derived EXTERNAL_NET"
    else
        fail "render emitted wrong direction vars: $home / $external"
    fi
    if grep -q '\${' "$out"; then
        fail "render left an unsubstituted placeholder"
    else
        pass "render substitutes every placeholder"
    fi
else
    fail "default render failed: $(cat "$work/render.log")"
fi

# 2. HOME_NET=any is refused (the exact historical regression)
if SURICATA_HOME_NET="any" bash "$renderer" --output "$work/should-not-exist.yaml" >"$work/any.log" 2>&1; then
    fail "renderer accepted HOME_NET=any"
else
    pass "renderer rejects HOME_NET=any"
fi
[ -f "$work/should-not-exist.yaml" ] && fail "renderer wrote output for rejected HOME_NET" || pass "no output on rejected HOME_NET"

# 3. an empty HOME_NET is refused, and so is an unset one: scope is a decision
if SURICATA_HOME_NET="" bash "$renderer" --output "$work/empty.yaml" >"$work/empty.log" 2>&1; then
    fail "renderer accepted empty HOME_NET"
else
    pass "renderer rejects empty HOME_NET"
fi
if env -u SURICATA_HOME_NET bash "$renderer" --output "$work/unset.yaml" >"$work/unset.log" 2>&1; then
    fail "renderer invented a default HOME_NET"
else
    pass "renderer requires HOME_NET to be set explicitly"
fi

# 4. --check catches a hand-edited profile that collapsed direction semantics
cat >"$work/collapsed.yaml" <<'YAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
YAML
if bash "$renderer" --check "$work/collapsed.yaml" >"$work/check-collapsed.log" 2>&1; then
    fail "--check accepted collapsed direction semantics"
else
    pass "--check rejects collapsed direction semantics"
fi

# 5. --check accepts the freshly rendered profile
if bash "$renderer" --check "$out" >"$work/check-ok.log" 2>&1; then
    pass "--check accepts a correctly rendered profile"
else
    fail "--check rejected a correctly rendered profile: $(cat "$work/check-ok.log")"
fi

# 6. render is atomic: a failed render must not clobber the existing target
cp "$out" "$work/atomic.yaml"
before=$(sha256sum "$work/atomic.yaml" | cut -d' ' -f1)
SURICATA_HOME_NET="any" bash "$renderer" --output "$work/atomic.yaml" >/dev/null 2>&1 || true
after=$(sha256sum "$work/atomic.yaml" | cut -d' ' -f1)
if [ "$before" = "$after" ]; then
    pass "failed render leaves the previous profile intact"
else
    fail "failed render modified the previous profile"
fi

# 6b. an existing file keeps its inode. The sensor profile is a single-file bind
# mount, so replacing the inode would silently freeze the container on old content.
inode_before=$(stat -c %i "$work/atomic.yaml")
SURICATA_HOME_NET="[10.0.0.0/8]" bash "$renderer" --output "$work/atomic.yaml" >/dev/null 2>&1 || true
inode_after=$(stat -c %i "$work/atomic.yaml")
if [ "$inode_before" = "$inode_after" ] && grep -q '10.0.0.0/8' "$work/atomic.yaml"; then
    pass "render rewrites in place so bind mounts keep seeing updates"
else
    fail "render replaced the inode (bind-mounted consumers would read stale content)"
fi

# 7. threads must be a positive integer
if SURICATA_HOME_NET="[10.0.0.0/8]" SURICATA_THREADS=0 bash "$renderer" --output "$work/threads.yaml" >/dev/null 2>&1; then
    fail "renderer accepted zero threads"
else
    pass "renderer rejects zero threads"
fi

if [ "$failures" -ne 0 ]; then
    printf '\n%d render-profile checks failed\n' "$failures" >&2
    exit 1
fi
printf '\nrender-profile: all checks passed\n'
