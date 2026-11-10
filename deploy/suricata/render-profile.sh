#!/bin/sh
# Render the Suricata sensor profile from deploy/suricata/lyflow-suricata-profile.tmpl.yaml.
#
# Why this exists: the sensor profile used to be a hand-edited YAML on the host.
# Every hand edit risked collapsing direction semantics (HOME_NET/EXTERNAL_NET)
# to "any", which silently turns every inbound-only signature into a match for
# internal-to-internal and internal-to-outbound traffic. This renderer keeps the
# direction vars explicit, refuses "any", and can validate the result before the
# file is swapped in.
#
# Usage:
#   deploy/suricata/render-profile.sh --output /path/to/lyflow-suricata-profile.yaml
#   deploy/suricata/render-profile.sh --check /path/to/lyflow-suricata-profile.yaml
#
# Environment (all optional except HOME_NET which has a private-range default):
#   SURICATA_HOME_NET      CIDR list, e.g. "[10.0.0.0/8,10.1.18.0/24]"
#   SURICATA_INTERFACE     capture interface (default: mirror0)
#   SURICATA_THREADS       af-packet threads (default: 4)
#   SURICATA_BPF_FILTER    BPF filter (default: not ( host 10.1.18.125))
#   SURICATA_TEMPLATE      template path override
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEMPLATE=${SURICATA_TEMPLATE:-$SCRIPT_DIR/lyflow-suricata-profile.tmpl.yaml}

log() { printf 'render-profile: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

mode=
target=
while [ $# -gt 0 ]; do
    case "$1" in
        --output) mode=output; target=${2:-}; shift 2 ;;
        --check)  mode=check;  target=${2:-}; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$mode" ] || die "one of --output or --check is required"
[ -n "$target" ] || die "--$mode needs a path"
[ -f "$TEMPLATE" ] || die "template not found: $TEMPLATE"

if [ "$mode" = output ]; then
    # SURICATA_HOME_NET has no default on purpose. Only the operator knows which
    # assets this sensor protects, and both plausible defaults are actively harmful:
    #   "any"        -> no direction at all (90.4% of alerts were direction misfires)
    #   all RFC1918  -> the real attackers get classified as "home", losing detections
    # Requiring an explicit value makes the scope a decision, not an accident.
    if [ -z "${SURICATA_HOME_NET:-}" ]; then
        die "SURICATA_HOME_NET must be set to the assets this sensor protects, e.g. '[10.1.18.0/24,203.0.113.10/32]'"
    fi
fi
SURICATA_INTERFACE=${SURICATA_INTERFACE:-mirror0}
SURICATA_THREADS=${SURICATA_THREADS:-4}
SURICATA_BPF_FILTER=${SURICATA_BPF_FILTER:-"not ( host 10.1.18.125)"}

# Direction semantics guard. "any" is the exact value that broke detection, so it
# is rejected here rather than being caught later by a human reading alerts.
# Only applies when rendering: --check reports on whatever the target file says.
if [ "$mode" = output ]; then
    normalized_home=$(printf '%s' "$SURICATA_HOME_NET" | tr -d '[:space:]')
    case "$normalized_home" in
        any|ANY|'') die "SURICATA_HOME_NET must be a CIDR list, not '$SURICATA_HOME_NET'" ;;
        \[*\]) : ;;
        *) log "warning: SURICATA_HOME_NET is not bracketed; Suricata treats it as a single value: $SURICATA_HOME_NET" ;;
    esac
fi
[ "$SURICATA_THREADS" -ge 1 ] 2>/dev/null || die "SURICATA_THREADS must be a positive integer"
[ -n "$SURICATA_INTERFACE" ] || die "SURICATA_INTERFACE must not be empty"

render() {
    sed \
        -e "s|\${SURICATA_HOME_NET}|$SURICATA_HOME_NET|g" \
        -e "s|\${SURICATA_INTERFACE}|$SURICATA_INTERFACE|g" \
        -e "s|\${SURICATA_THREADS}|$SURICATA_THREADS|g" \
        -e "s|\${SURICATA_BPF_FILTER}|$SURICATA_BPF_FILTER|g" \
        "$TEMPLATE"
}

# verify_direction reads a rendered profile and asserts the direction contract.
# Kept separate from rendering so --check can be run against a deployed file.
verify_direction() {
    file=$1
    [ -r "$file" ] || die "profile not readable: $file"
    home_line=$(grep -m1 '^[[:space:]]*HOME_NET:' "$file" || true)
    external_line=$(grep -m1 '^[[:space:]]*EXTERNAL_NET:' "$file" || true)
    [ -n "$home_line" ] || die "profile has no HOME_NET: $file"
    [ -n "$external_line" ] || die "profile has no EXTERNAL_NET: $file"

    home_value=$(printf '%s' "$home_line" | sed -e 's/^[^:]*://' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')
    external_value=$(printf '%s' "$external_line" | sed -e 's/^[^:]*://' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')

    case "$home_value" in
        any|ANY|'') die "HOME_NET must not be '$home_value' (direction semantics collapse)" ;;
    esac
    case "$external_value" in
        any|ANY|'') die "EXTERNAL_NET must not be '$external_value' (direction semantics collapse)" ;;
    esac
    case "$home_value" in
        \[*\]|\$*) : ;;
        *) die "HOME_NET must be a bracketed CIDR list or a variable, got '$home_value'" ;;
    esac
    printf 'direction-ok HOME_NET=%s EXTERNAL_NET=%s\n' "$home_value" "$external_value"
}

if [ "$mode" = check ]; then
    verify_direction "$target"
    if command -v suricata >/dev/null 2>&1; then
        suricata -T -c "$target" -S /dev/null >/dev/null 2>&1 || log "warning: suricata -T rejected $target"
    fi
    exit 0
fi

destination_dir=$(dirname -- "$target")
[ -d "$destination_dir" ] || die "destination directory missing: $destination_dir"
staged="$target.tmp.$$"
trap 'rm -f "$staged"' EXIT INT TERM
render >"$staged"
verify_direction "$staged" >/dev/null
chmod 0644 "$staged"

# Write in place instead of renaming. The sensor profile is a single-file bind
# mount, and a bind mount pins the inode: `mv` would leave the container reading
# the old file forever. Overwriting the existing inode keeps the mount live.
if [ -f "$target" ]; then
    cat "$staged" >"$target"
    rm -f "$staged"
else
    mv "$staged" "$target"
fi
trap - EXIT INT TERM
log "rendered $target (HOME_NET=$SURICATA_HOME_NET interface=$SURICATA_INTERFACE threads=$SURICATA_THREADS)"
verify_direction "$target"
