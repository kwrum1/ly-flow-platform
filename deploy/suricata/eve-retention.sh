#!/bin/sh
# LyFlow Suricata EVE retention.
#
# Single owner of the EVE log lifecycle on the sensor host:
#   1. rotate the active eve.json once it exceeds a per-file size cap
#      (copytruncate, so Suricata's open file descriptor stays valid);
#   2. delete rotated files older than EVE_RETENTION_DAYS;
#   3. gzip rotated files;
#   4. delete the oldest rotated files until the directory fits
#      EVE_MAX_TOTAL_BYTES;
#   5. alert through syslog (logger) when the filesystem is above
#      EVE_DISK_WARN_PCT / EVE_DISK_CRIT_PCT.
#
# Why not logrotate: logrotate cannot bound the total size of a directory, cannot
# emit disk-usage alerts, and cannot take runtime environment overrides. The old
# setup used `logrotate -f` hourly with `rotate 48`/`delaycompress`, which forced
# one rotation per hour regardless of size, kept 48 of them (~2.1 GB), and left a
# full uncompressed hour behind (observed eve.json.1 = 278 MB).
#
# Thresholds (all overridable, environment wins over the config file):
#   EVE_DIR               directory holding the EVE files
#   EVE_ACTIVE_FILE       active file name (default: eve.json)
#   EVE_MAX_FILE_BYTES    per-file cap; accepts bytes or K/M/G/T suffix (200M)
#   EVE_MAX_TOTAL_BYTES   total directory cap (2G)
#   EVE_RETENTION_DAYS    days to keep rotated files (3)
#   EVE_COMPRESS          1 = gzip rotated files (default 1)
#   EVE_GZIP_LEVEL        gzip level 1-9 (default 6)
#   EVE_DISK_WARN_PCT     80
#   EVE_DISK_CRIT_PCT     90
#   EVE_ALERT_REPEAT_SECONDS  re-alert an unchanged level (3600)
#   EVE_ALERT_STATE       watermark rate-limit state file
#   EVE_SYSLOG            1 = send alerts to syslog via logger (default 1)
#   EVE_LOCK_FILE         lock file used to serialize runs
#   EVE_ROTATE_CONF       config file (default /etc/lyflow/eve-rotate.conf)
#
# Usage:
#   eve-retention.sh [--dir DIR] [--dry-run] [--print-config]
#                    [--watermark-check PERCENT]
#
# Requires GNU coreutils + GNU findutils (find -printf, stat -c, flock, gzip).
# The sensor hosts are Ubuntu; nothing else is assumed.
set -eu

TAG=lyflow-eve-retention
DEFAULT_CONF=/etc/lyflow/eve-rotate.conf
DRY_RUN=0
MODE=run
WM_PCT=
CONF=${EVE_ROTATE_CONF:-$DEFAULT_CONF}

usage() {
    cat <<'EOF'
Usage: eve-retention.sh [options]

  --dir DIR               operate on DIR instead of EVE_DIR
  --dry-run               report what would happen, change nothing
  --print-config          print the effective thresholds and exit
  --watermark-check PCT   print ok|warn|crit for disk usage PCT and exit
  -h, --help              show this help
EOF
}

log() {
    printf '%s %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$*"
}

# POSIX sh has no guaranteed `local`, so every helper that assigns variables
# prefixes them with `_` to avoid clobbering a caller's state. This is not
# theoretical: an earlier version let alert() overwrite the caller's `level`
# ("warn" became "warning") and silently broke alert rate-limiting.
alert() {
    _alert_level=$1
    shift
    _alert_message=$*
    printf '%s %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$_alert_message" >&2
    if [ "${SYSLOG:-1}" = "1" ] && command -v logger >/dev/null 2>&1; then
        logger -t "$TAG" -p "user.$_alert_level" "$_alert_message" || true
    fi
}

die() {
    alert err "$*"
    exit 2
}

# Load KEY=VALUE defaults from the config file, never overriding variables that
# are already present in the environment (a systemd drop-in wins over the file).
# Only known keys are accepted: the file is parsed as data, never evaluated, so a
# stray backtick or $(...) in it cannot execute anything.
CONFIG_KEYS="EVE_DIR EVE_ACTIVE_FILE EVE_MAX_FILE_BYTES EVE_MAX_TOTAL_BYTES EVE_RETENTION_DAYS EVE_COMPRESS EVE_GZIP_LEVEL EVE_DISK_WARN_PCT EVE_DISK_CRIT_PCT EVE_SYSLOG EVE_LOCK_FILE EVE_ROTATE_CONF EVE_ALERT_REPEAT_SECONDS EVE_ALERT_STATE"

config_key_known() {
    for _known in $CONFIG_KEYS; do
        [ "$_known" = "$1" ] && return 0
    done
    return 1
}

load_config() {
    [ -r "$CONF" ] || return 0
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            ''|'#'*) continue ;;
        esac
        _line=${_line#export }
        case "$_line" in
            *=*) ;;
            *) continue ;;
        esac
        _key=${_line%%=*}
        _value=${_line#*=}
        config_key_known "$_key" || continue
        case "$_value" in
            \"*\") _value=${_value#\"}; _value=${_value%\"} ;;
            \'*\') _value=${_value#\'}; _value=${_value%\'} ;;
        esac
        eval "_present=\${$_key+x}"
        if [ -z "$_present" ]; then
            export "$_key=$_value"
        fi
    done <"$CONF"
}

# Convert "200M" / "2G" / "1048576" to bytes.
parse_bytes() {
    _raw=$1
    case "$_raw" in
        ''|*[!0-9kKmMgGtT]*) return 1 ;;
    esac
    case "$_raw" in
        *[kK]) _mult=1024; _num=${_raw%?} ;;
        *[mM]) _mult=1048576; _num=${_raw%?} ;;
        *[gG]) _mult=1073741824; _num=${_raw%?} ;;
        *[tT]) _mult=1099511627776; _num=${_raw%?} ;;
        *) _mult=1; _num=$_raw ;;
    esac
    case "$_num" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' $((_num * _mult))
}

# Size in bytes, always an integer. A file can vanish between the caller's check
# and this call (Suricata rotates/truncates concurrently), so an unreadable file
# reports 0 instead of aborting the run under `set -e`.
file_size() {
    if stat -c %s "$1" 2>/dev/null; then
        return 0
    fi
    _size=$(wc -c <"$1" 2>/dev/null | tr -d ' ')
    case "$_size" in
        ''|*[!0-9]*) printf '0\n' ;;
        *) printf '%s\n' "$_size" ;;
    esac
}

dir_bytes() {
    find "$1" -maxdepth 1 -type f -name "$ACTIVE.*" -printf '%s\n' 2>/dev/null |
        awk '{ total += $1 } END { printf "%d", total + 0 }'
}

human() {
    _bytes=$1
    if [ "$_bytes" -ge 1073741824 ]; then
        printf '%d.%dG' $((_bytes / 1073741824)) $(((_bytes % 1073741824) / 107374182))
    elif [ "$_bytes" -ge 1048576 ]; then
        printf '%d.%dM' $((_bytes / 1048576)) $(((_bytes % 1048576) / 104858))
    elif [ "$_bytes" -ge 1024 ]; then
        printf '%dK' $((_bytes / 1024))
    else
        printf '%dB' "$_bytes"
    fi
}

# Disk watermark decision, kept as a pure function so it can be tested without
# touching a real filesystem.
watermark_level() {
    _pct=$1
    _warn=$2
    _crit=$3
    case "$_pct" in
        ''|*[!0-9]*) printf 'invalid\n'; return 0 ;;
    esac
    if [ "$_pct" -ge "$_crit" ]; then
        printf 'crit\n'
    elif [ "$_pct" -ge "$_warn" ]; then
        printf 'warn\n'
    else
        printf 'ok\n'
    fi
}

disk_used_pct() {
    df -P "$1" 2>/dev/null | awk 'NR == 2 { value = $5; sub(/%/, "", value); print value }'
}

# Watermark alerts are emitted on level transitions and then repeated at most
# once per EVE_ALERT_REPEAT_SECONDS. Without this the 10-minute timer would write
# 144 identical syslog lines a day and the alert would be filtered out by hand.
watermark_state_file() {
    printf '%s' "${EVE_ALERT_STATE:-/run/lock/lyflow-eve-retention.level}"
}

# Sets the globals WM_PREV_LEVEL and WM_PREV_TS (the only intended outputs).
read_watermark_state() {
    _state=$(watermark_state_file)
    WM_PREV_LEVEL=
    WM_PREV_TS=0
    [ -r "$_state" ] || return 0
    # Format: "<level> <unix-seconds>"
    read -r WM_PREV_LEVEL WM_PREV_TS <"$_state" 2>/dev/null || true
    case "${WM_PREV_TS:-}" in
        ''|*[!0-9]*) WM_PREV_TS=0 ;;
    esac
    case "${WM_PREV_LEVEL:-}" in
        ok|warn|crit) ;;
        *) WM_PREV_LEVEL= ;;
    esac
}

write_watermark_state() {
    _state=$(watermark_state_file)
    [ -n "$_state" ] || return 0
    _dir=$(dirname "$_state")
    [ -d "$_dir" ] || mkdir -p "$_dir" 2>/dev/null || return 0
    printf '%s %s\n' "$1" "$2" >"$_state" 2>/dev/null || true
}

check_disk_watermark() {
    _pct=$(disk_used_pct "$EVE_DIR")
    [ -n "$_pct" ] || return 0
    _level=$(watermark_level "$_pct" "$EVE_DISK_WARN_PCT" "$EVE_DISK_CRIT_PCT")
    if [ "$_level" = invalid ]; then
        return 0
    fi

    # A dry run reports what a real run would consider and never touches the
    # rate-limit state, so it cannot silence the next real alert.
    if [ "$DRY_RUN" = "1" ]; then
        if [ "$_level" = crit ]; then
            printf '%s %s: CRIT EVE disk usage %s%% >= %s%% on %s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$_pct" "$EVE_DISK_CRIT_PCT" "$EVE_DIR" >&2
        elif [ "$_level" = warn ]; then
            printf '%s %s: WARN EVE disk usage %s%% >= %s%% on %s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$_pct" "$EVE_DISK_WARN_PCT" "$EVE_DIR" >&2
        fi
        return 0
    fi

    read_watermark_state
    _now=$(date +%s)

    if [ "$_level" = ok ]; then
        if [ "$WM_PREV_LEVEL" = warn ] || [ "$WM_PREV_LEVEL" = crit ]; then
            _message="RECOVERED EVE disk usage ${_pct}% is below ${EVE_DISK_WARN_PCT}% on ${EVE_DIR}"
            printf '%s %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$_message" >&2
            if [ "$SYSLOG" = "1" ] && command -v logger >/dev/null 2>&1; then
                logger -t "$TAG" -p user.info "$_message" || true
            fi
        fi
        write_watermark_state ok "$_now"
        return 0
    fi

    _should_alert=0
    if [ "$_level" != "$WM_PREV_LEVEL" ]; then
        _should_alert=1
    elif [ $((_now - WM_PREV_TS)) -ge "$EVE_ALERT_REPEAT_SECONDS" ]; then
        _should_alert=1
    fi
    [ "$_should_alert" = "1" ] || return 0

    _dir_size=$(human "$(dir_bytes "$EVE_DIR")")
    if [ "$_level" = crit ]; then
        alert crit "CRIT EVE disk usage ${_pct}% >= ${EVE_DISK_CRIT_PCT}% on ${EVE_DIR} (dir=${_dir_size}, total_cap=$(human "$MAX_TOTAL"))"
    else
        alert warning "WARN EVE disk usage ${_pct}% >= ${EVE_DISK_WARN_PCT}% on ${EVE_DIR} (dir=${_dir_size}, total_cap=$(human "$MAX_TOTAL"))"
    fi
    write_watermark_state "$_level" "$_now"
}

# ---------------------------------------------------------------------------
# argument parsing (before config load so CLI/env values stay authoritative)
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            [ $# -ge 2 ] || die "--dir needs a value"
            EVE_DIR=$2
            shift 2
            ;;
        --dir=*)
            EVE_DIR=${1#*=}
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --print-config)
            MODE=print
            shift
            ;;
        --watermark-check)
            [ $# -ge 2 ] || die "--watermark-check needs a percentage"
            MODE=watermark
            WM_PCT=$2
            shift 2
            ;;
        --watermark-check=*)
            MODE=watermark
            WM_PCT=${1#*=}
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
done

load_config

EVE_DIR=${EVE_DIR:-/opt/ly-flow-platform/.sisyphus/runtime/engine-outputs/suricata-profile}
ACTIVE=${EVE_ACTIVE_FILE:-eve.json}
EVE_MAX_FILE_BYTES=${EVE_MAX_FILE_BYTES:-200M}
EVE_MAX_TOTAL_BYTES=${EVE_MAX_TOTAL_BYTES:-2G}
EVE_RETENTION_DAYS=${EVE_RETENTION_DAYS:-3}
EVE_COMPRESS=${EVE_COMPRESS:-1}
EVE_GZIP_LEVEL=${EVE_GZIP_LEVEL:-6}
EVE_DISK_WARN_PCT=${EVE_DISK_WARN_PCT:-80}
EVE_DISK_CRIT_PCT=${EVE_DISK_CRIT_PCT:-90}
EVE_ALERT_REPEAT_SECONDS=${EVE_ALERT_REPEAT_SECONDS:-3600}
SYSLOG=${EVE_SYSLOG:-1}

case "$EVE_ALERT_REPEAT_SECONDS" in
    ''|*[!0-9]*) die "invalid EVE_ALERT_REPEAT_SECONDS: $EVE_ALERT_REPEAT_SECONDS" ;;
esac
case "$EVE_GZIP_LEVEL" in
    ''|*[!0-9]*) die "invalid EVE_GZIP_LEVEL: $EVE_GZIP_LEVEL" ;;
esac
[ "$EVE_GZIP_LEVEL" -ge 1 ] && [ "$EVE_GZIP_LEVEL" -le 9 ] ||
    die "EVE_GZIP_LEVEL must be between 1 and 9"

MAX_FILE=$(parse_bytes "$EVE_MAX_FILE_BYTES") || die "invalid EVE_MAX_FILE_BYTES: $EVE_MAX_FILE_BYTES"
MAX_TOTAL=$(parse_bytes "$EVE_MAX_TOTAL_BYTES") || die "invalid EVE_MAX_TOTAL_BYTES: $EVE_MAX_TOTAL_BYTES"
case "$EVE_RETENTION_DAYS" in
    ''|*[!0-9]*) die "invalid EVE_RETENTION_DAYS: $EVE_RETENTION_DAYS" ;;
esac
[ "$EVE_RETENTION_DAYS" -ge 1 ] || die "EVE_RETENTION_DAYS must be >= 1"
case "$EVE_DISK_WARN_PCT" in ''|*[!0-9]*) die "invalid EVE_DISK_WARN_PCT: $EVE_DISK_WARN_PCT" ;; esac
case "$EVE_DISK_CRIT_PCT" in ''|*[!0-9]*) die "invalid EVE_DISK_CRIT_PCT: $EVE_DISK_CRIT_PCT" ;; esac
[ "$EVE_DISK_WARN_PCT" -lt "$EVE_DISK_CRIT_PCT" ] || die "EVE_DISK_WARN_PCT must be below EVE_DISK_CRIT_PCT"
[ "$EVE_DISK_CRIT_PCT" -le 100 ] || die "EVE_DISK_CRIT_PCT must be <= 100"

if [ "$MODE" = watermark ]; then
    watermark_level "$WM_PCT" "$EVE_DISK_WARN_PCT" "$EVE_DISK_CRIT_PCT"
    exit 0
fi

if [ "$MODE" = print ]; then
    printf 'dir=%s\n' "$EVE_DIR"
    printf 'active_file=%s\n' "$ACTIVE"
    printf 'max_file_bytes=%s\n' "$MAX_FILE"
    printf 'max_total_bytes=%s\n' "$MAX_TOTAL"
    printf 'retention_days=%s\n' "$EVE_RETENTION_DAYS"
    printf 'compress=%s\n' "$EVE_COMPRESS"
    printf 'gzip_level=%s\n' "$EVE_GZIP_LEVEL"
    printf 'disk_warn_pct=%s\n' "$EVE_DISK_WARN_PCT"
    printf 'disk_crit_pct=%s\n' "$EVE_DISK_CRIT_PCT"
    printf 'alert_repeat_seconds=%s\n' "$EVE_ALERT_REPEAT_SECONDS"
    exit 0
fi

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
[ -d "$EVE_DIR" ] || {
    log "directory missing, nothing to do: $EVE_DIR"
    exit 0
}

# Serialize runs: a slow gzip must not overlap with the next timer tick.
if [ "$DRY_RUN" = "0" ] && command -v flock >/dev/null 2>&1; then
    LOCK=${EVE_LOCK_FILE:-/run/lock/lyflow-eve-retention.lock}
    if ! ( : >>"$LOCK" ) 2>/dev/null; then
        LOCK="$EVE_DIR/.eve-retention.lock"
    fi
    if ( : >>"$LOCK" ) 2>/dev/null; then
        exec 9>>"$LOCK"
        if ! flock -n 9; then
            log "another run holds $LOCK, skipping"
            exit 0
        fi
    else
        log "cannot open a lock file, continuing without serialization"
    fi
fi

log "start dir=$EVE_DIR file_cap=$(human "$MAX_FILE") total_cap=$(human "$MAX_TOTAL") days=$EVE_RETENTION_DAYS compress=$EVE_COMPRESS dry_run=$DRY_RUN"

# A total cap smaller than two rotated files cannot keep history: the previous
# rotation is deleted as soon as the next one happens. Not fatal (that may be
# exactly what a tiny volume wants), but it must be visible in the log.
if [ "$MAX_TOTAL" -lt $((MAX_FILE * 2)) ]; then
    alert warning "EVE_MAX_TOTAL_BYTES ($EVE_MAX_TOTAL_BYTES) is below 2x EVE_MAX_FILE_BYTES ($EVE_MAX_FILE_BYTES); rotated history will be pruned aggressively"
fi

# 1. size-triggered rotation of the active file
ACTIVE_PATH="$EVE_DIR/$ACTIVE"
if [ -f "$ACTIVE_PATH" ]; then
    active_size=$(file_size "$ACTIVE_PATH")
    if [ "$active_size" -ge "$MAX_FILE" ]; then
        stamp=$(date -u +%Y%m%dT%H%M%SZ)
        target="$ACTIVE_PATH.$stamp"
        if [ "$DRY_RUN" = "1" ]; then
            log "would rotate $ACTIVE ($(human "$active_size") >= $(human "$MAX_FILE")) -> $(basename "$target")"
        else
            # copytruncate: Suricata keeps writing to the same inode, which the
            # EVE ingester detects as a truncation (size < offset) and re-reads
            # from 0. Lines written between the copy and the truncate are lost;
            # the previous logrotate config used copytruncate too, so this is not
            # a regression. The window is sub-millisecond at most in practice and
            # only affects raw EVE history, not the ingested threat_events.
            if cp -p "$ACTIVE_PATH" "$target" && : >"$ACTIVE_PATH"; then
                log "rotated $ACTIVE ($(human "$active_size") >= $(human "$MAX_FILE")) -> $(basename "$target")"
            else
                alert err "rotation failed for $ACTIVE_PATH; leaving the active file in place"
                rm -f "$target" 2>/dev/null || true
            fi
            sync "$ACTIVE_PATH" 2>/dev/null || true
        fi
    fi
fi

# 2. age-based retention, before compression: never spend CPU gzipping a file
# that is about to be deleted.
cutoff_minutes=$((EVE_RETENTION_DAYS * 1440))
aged=$(find "$EVE_DIR" -maxdepth 1 -type f -name "$ACTIVE.*" -mmin +"$cutoff_minutes" -print 2>/dev/null || true)
if [ -n "$aged" ]; then
    printf '%s\n' "$aged" | while IFS= read -r old; do
        [ -n "$old" ] || continue
        if [ "$DRY_RUN" = "1" ]; then
            log "would delete (age > ${EVE_RETENTION_DAYS}d) $(basename "$old")"
        elif rm -f "$old"; then
            log "deleted (age > ${EVE_RETENTION_DAYS}d) $(basename "$old")"
        else
            alert warning "failed to delete $old"
        fi
    done
fi

# 3. compress rotated files (copytruncate copies are complete, no delaycompress)
if [ "$EVE_COMPRESS" = "1" ]; then
    find "$EVE_DIR" -maxdepth 1 -type f -name "$ACTIVE.*" ! -name '*.gz' -print 2>/dev/null |
        while IFS= read -r rotated; do
            if [ "$DRY_RUN" = "1" ]; then
                log "would compress $(basename "$rotated") (level $EVE_GZIP_LEVEL)"
            elif nice -n 10 gzip "-$EVE_GZIP_LEVEL" "$rotated" 2>/dev/null; then
                log "compressed $(basename "$rotated") (level $EVE_GZIP_LEVEL)"
            else
                alert warning "failed to compress $rotated"
            fi
        done
fi

# 4. total-size retention, oldest first. The active file is never deleted.
total=$(dir_bytes "$EVE_DIR")
if [ -f "$ACTIVE_PATH" ]; then
    total=$((total + $(file_size "$ACTIVE_PATH")))
fi
if [ "$total" -gt "$MAX_TOTAL" ]; then
    log "directory holds $(human "$total") > cap $(human "$MAX_TOTAL"), pruning oldest"
    listing=$(mktemp "${TMPDIR:-/tmp}/eve-retention-list.XXXXXX")
    trap 'rm -f "$listing"' EXIT INT TERM
    find "$EVE_DIR" -maxdepth 1 -type f -name "$ACTIVE.*" -printf '%T@\t%s\t%p\n' 2>/dev/null |
        sort -k1,1n >"$listing"
    while IFS="$(printf '\t')" read -r _mtime _fsize _fpath; do
        [ -n "${_fpath:-}" ] || continue
        [ "$total" -gt "$MAX_TOTAL" ] || break
        [ "$_fpath" = "$ACTIVE_PATH" ] && continue
        if [ "$DRY_RUN" = "1" ]; then
            log "would delete (total cap) $(basename "$_fpath") ($(human "$_fsize"))"
        elif rm -f "$_fpath"; then
            log "deleted (total cap) $(basename "$_fpath") ($(human "$_fsize"))"
        else
            alert warning "failed to delete $_fpath"
            break
        fi
        total=$((total - _fsize))
    done <"$listing"
    rm -f "$listing"
    trap - EXIT INT TERM
fi

total=$(dir_bytes "$EVE_DIR")
if [ -f "$ACTIVE_PATH" ]; then
    total=$((total + $(file_size "$ACTIVE_PATH")))
fi
log "done files=$(find "$EVE_DIR" -maxdepth 1 -type f -name "$ACTIVE*" | wc -l | tr -d ' ') size=$(human "$total")"

# Disk watermark is evaluated after cleanup so the alert describes the state the
# next run will start from, not the pre-prune peak.
check_disk_watermark

if [ "$total" -gt "$MAX_TOTAL" ] && [ -f "$ACTIVE_PATH" ] && [ "$(file_size "$ACTIVE_PATH")" -gt "$MAX_TOTAL" ]; then
    alert warning "active $ACTIVE alone exceeds the total cap; lower EVE_MAX_FILE_BYTES or raise EVE_MAX_TOTAL_BYTES"
fi
