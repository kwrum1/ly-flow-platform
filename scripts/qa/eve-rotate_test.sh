#!/usr/bin/env bash
# Tests for deploy/suricata/eve-retention.sh.
#
# Everything runs inside a mktemp -d sandbox. The real EVE directory
# (/var/log/suricata or the engine-outputs bind mount) is never touched: the
# script under test is always invoked with --dir pointing into the sandbox and
# with EVE_SYSLOG=0 so it cannot write to the host syslog.
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
script="$root/deploy/suricata/eve-retention.sh"
conf="$root/deploy/suricata/eve-rotate.conf"
timer="$root/deploy/suricata/lyflow-eve-rotate.timer"
service="$root/deploy/suricata/lyflow-eve-rotate.service"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

# Under `set -o pipefail`, piping anything into `grep -q` is a hazard: grep exits
# at the first match and the writer can take SIGPIPE (141), turning a successful
# check into a random failure. These two helpers write to a scratch file first.
contains() { # contains TEXT REGEX
    printf '%s\n' "$1" >"$work/.contains"
    grep -qE -- "$2" "$work/.contains"
}
has_line() { # has_line TEXT EXACT-LINE
    printf '%s\n' "$1" >"$work/.contains"
    grep -qxF -- "$2" "$work/.contains"
}

for required in "$script" "$conf" "$timer" "$service"; do
    [ -f "$required" ] || { printf 'missing required file: %s\n' "$required" >&2; exit 2; }
done

# The suite runs under `set -o pipefail`. Never pipe a *program* into `grep -q`:
# grep exits at the first match, the writer takes SIGPIPE (141), and pipefail
# turns a successful check into a random failure. Capture into a variable and
# grep that, or use tests that do not short-circuit the pipeline.
#
# Run the script with a sandboxed config path and syslog disabled. The watermark
# rate-limit state and the flock file are redirected into the sandbox: a test
# must never write to /run/lock on the host.
run() {
    EVE_ROTATE_CONF="$work/no-such.conf" EVE_SYSLOG=0 \
        EVE_ALERT_STATE="$work/watermark.state" EVE_LOCK_FILE="$work/ev.lock" \
        sh "$script" "$@"
}

new_dir() {
    d=$(mktemp -d "$work/dir.XXXXXX")
    printf '%s\n' "$d"
}

# make_file DIR NAME BYTES MTIME(YYYYMMDDhhmm) -> creates exactly BYTES bytes
make_file() {
    dir=$1
    name=$2
    bytes=$3
    when=$4
    head -c "$bytes" /dev/urandom >"$dir/$name" 2>/dev/null || : >"$dir/$name"
    touch -t "$when" "$dir/$name"
    printf '%s\n' "$dir/$name"
}

# Hours-ago timestamp in the touch(1) format, so fixtures stay inside the
# retention window regardless of the day the test runs.
hours_ago() {
    date -u -d "$1 hours ago" +%Y%m%d%H%M
}

# ---------------------------------------------------------------------------
# 0. structure: the config and units must agree with the script
# ---------------------------------------------------------------------------
for key in EVE_DIR EVE_ACTIVE_FILE EVE_MAX_FILE_BYTES EVE_MAX_TOTAL_BYTES \
    EVE_RETENTION_DAYS EVE_COMPRESS EVE_DISK_WARN_PCT EVE_DISK_CRIT_PCT; do
    if grep -q "^[[:space:]]*$key=" "$conf"; then
        pass "eve-rotate.conf defines $key"
    else
        fail "eve-rotate.conf is missing $key"
    fi
done
if grep -q 'EVE_ROTATE_CONF=/etc/lyflow/eve-rotate.conf' "$service"; then
    pass "service points the script at /etc/lyflow/eve-rotate.conf"
else
    fail "service does not point the script at the threshold config file"
fi
if grep -q '^EnvironmentFile' "$service"; then
    fail "service uses EnvironmentFile, which would beat drop-in Environment= overrides"
else
    pass "service leaves threshold precedence to the environment"
fi
printed_gzip=$(run --print-config 2>&1)
if has_line "$printed_gzip" 'gzip_level=6'; then
    pass "default gzip level is 6 (CPU/space tradeoff measured on the sensor)"
else
    fail "default gzip level is not 6"
fi
if EVE_GZIP_LEVEL=0 run --print-config >"$work/badgz.log" 2>&1; then
    fail "EVE_GZIP_LEVEL=0 was accepted"
else
    pass "EVE_GZIP_LEVEL=0 is rejected"
fi
if EVE_GZIP_LEVEL=10 run --print-config >"$work/badgz2.log" 2>&1; then
    fail "EVE_GZIP_LEVEL=10 was accepted"
else
    pass "EVE_GZIP_LEVEL=10 is rejected"
fi
if grep -q 'ExecStart=.*eve-retention.sh' "$service"; then
    pass "service runs eve-retention.sh"
else
    fail "service does not run eve-retention.sh"
fi
if grep -q '^OnCalendar=.*' "$timer"; then
    pass "timer has a schedule"
else
    fail "timer has no OnCalendar"
fi
if grep -qE '^[[:space:]]*(delaycompress|copytruncate|rotate[[:space:]]+[0-9]+)' "$conf"; then
    fail "eve-rotate.conf still carries logrotate directives"
else
    pass "eve-rotate.conf is not a logrotate config"
fi

# ---------------------------------------------------------------------------
# 1. total-size cap: oldest rotated file goes first, newest is kept
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
make_file "$d" eve.json.20260101T000000Z 92160 "$(hours_ago 5)" >/dev/null   # oldest
make_file "$d" eve.json.20260101T010000Z 92160 "$(hours_ago 4)" >/dev/null   # middle
make_file "$d" eve.json.20260101T020000Z 10240 "$(hours_ago 3)" >/dev/null   # newest
before=$(find "$d" -maxdepth 1 -type f | wc -l | tr -d ' ')
if EVE_MAX_TOTAL_BYTES=120K EVE_MAX_FILE_BYTES=1G EVE_RETENTION_DAYS=30 EVE_COMPRESS=0 \
    run --dir "$d" >"$work/total.log" 2>&1; then
    # Match the base name so a compressed copy still counts as "present".
    if [ -n "$(find "$d" -maxdepth 1 -name 'eve.json.20260101T000000Z*')" ]; then
        fail "total cap kept the oldest rotated file"
    else
        pass "total cap deletes the oldest rotated file"
    fi
    if [ -n "$(find "$d" -maxdepth 1 -name 'eve.json.20260101T020000Z*')" ] && [ -e "$d/eve.json" ]; then
        pass "total cap keeps the newest rotated file and the active file"
    else
        fail "total cap deleted the newest rotated file or the active file"
    fi
    after=$(find "$d" -maxdepth 1 -type f | wc -l | tr -d ' ')
    if [ "$after" -lt "$before" ]; then
        pass "total cap removed at least one file"
    else
        fail "total cap removed no file (before=$before after=$after)"
    fi
    remaining=$(find "$d" -maxdepth 1 -type f -printf '%s\n' | awk '{ t += $1 } END { print t + 0 }')
    if [ "$remaining" -le $((120 * 1024)) ] || [ "$after" -le 2 ]; then
        pass "total cap ends at or below the cap (remaining=${remaining}B, files=$after)"
    else
        fail "total cap left ${remaining}B in $after files"
    fi
    if grep -q 'deleted (total cap)' "$work/total.log"; then
        pass "total cap deletion is logged with a reason"
    else
        fail "total cap deletion was not logged with a reason"
    fi
else
    fail "script failed on the total-cap case: $(cat "$work/total.log")"
fi
# ---------------------------------------------------------------------------
# 2. age cap: files older than EVE_RETENTION_DAYS are deleted, recent kept
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
old_stamp=$(date -u -d '5 days ago' +%Y%m%d%H%M)
new_stamp=$(date -u -d '1 day ago' +%Y%m%d%H%M)
make_file "$d" eve.json.old.gz 4096 "$old_stamp" >/dev/null
make_file "$d" eve.json.recent.gz 4096 "$new_stamp" >/dev/null
if EVE_MAX_TOTAL_BYTES=1G EVE_MAX_FILE_BYTES=1G EVE_RETENTION_DAYS=3 EVE_COMPRESS=0 \
    run --dir "$d" >"$work/age.log" 2>&1; then
    if [ ! -e "$d/eve.json.old.gz" ]; then
        pass "age cap deletes a file older than the retention window"
    else
        fail "age cap kept a file older than the retention window"
    fi
    if [ -e "$d/eve.json.recent.gz" ]; then
        pass "age cap keeps a file inside the retention window"
    else
        fail "age cap deleted a file inside the retention window"
    fi
    if grep -q 'deleted (total cap)' "$work/age.log"; then
        fail "age cap case also triggered total-cap pruning (test is not isolated)"
    else
        pass "age cap case is isolated from the total cap"
    fi
    if grep -q 'deleted (age' "$work/age.log"; then
        pass "age deletion is logged with a reason"
    else
        fail "age deletion was not logged"
    fi
else
    fail "script failed on the age case: $(cat "$work/age.log")"
fi

# ---------------------------------------------------------------------------
# 3. below both caps: every file survives
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
make_file "$d" eve.json.20260101T000000Z.gz 2048 "$(hours_ago 5)" >/dev/null
make_file "$d" eve.json.20260101T010000Z.gz 2048 "$(hours_ago 4)" >/dev/null
make_file "$d" eve.json.20260101T020000Z.gz 2048 "$(hours_ago 3)" >/dev/null
if EVE_MAX_TOTAL_BYTES=10M EVE_MAX_FILE_BYTES=10M EVE_RETENTION_DAYS=30 EVE_COMPRESS=0 \
    run --dir "$d" >"$work/under.log" 2>&1; then
    count=$(find "$d" -maxdepth 1 -type f | wc -l | tr -d ' ')
    if [ "$count" -eq 4 ]; then
        pass "files under both caps are all retained"
    else
        fail "files under both caps were removed (count=$count, expected 4)"
    fi
else
    fail "script failed on the under-cap case: $(cat "$work/under.log")"
fi

# ---------------------------------------------------------------------------
# 3b. unrelated files in the directory are never touched
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
make_file "$d" eve.json.$(hours_ago 5) 92160 "$(hours_ago 5)" >/dev/null
printf '{}\n' >"$d/ruleset.json"
printf 'keep\n' >"$d/notes.txt"
if EVE_MAX_TOTAL_BYTES=1K EVE_MAX_FILE_BYTES=1K EVE_RETENTION_DAYS=1 EVE_COMPRESS=1 \
    run --dir "$d" >"$work/unrelated.log" 2>&1; then
    if [ -e "$d/ruleset.json" ] && [ -e "$d/notes.txt" ]; then
        pass "unrelated files survive rotation and pruning"
    else
        fail "retention deleted a file it does not own"
    fi
else
    fail "script failed on the unrelated-file case: $(cat "$work/unrelated.log")"
fi

# ---------------------------------------------------------------------------
# 4. per-file cap rotates the active file and compresses the copy
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 4096 "$(hours_ago 1)" >/dev/null
active_before=$(wc -c <"$d/eve.json")
if EVE_MAX_TOTAL_BYTES=1G EVE_MAX_FILE_BYTES=2048 EVE_RETENTION_DAYS=30 EVE_COMPRESS=1 \
    run --dir "$d" >"$work/rotate.log" 2>&1; then
    rotated=$(find "$d" -maxdepth 1 -type f -name 'eve.json.2*' | wc -l | tr -d ' ')
    if [ "$rotated" -ge 1 ]; then
        pass "file cap rotates the active file"
    else
        fail "file cap did not rotate the active file"
    fi
    if [ -e "$d/eve.json" ] && [ "$(wc -c <"$d/eve.json")" -eq 0 ]; then
        pass "rotation truncates (copytruncate) the active file to zero bytes"
    else
        fail "rotation left data in the active file (Suricata would keep appending)"
    fi
    if [ -n "$(find "$d" -maxdepth 1 -type f -name 'eve.json.2*.gz')" ]; then
        pass "rotated file is gzip-compressed"
    else
        fail "rotated file was not compressed"
    fi
    if [ "$active_before" -gt 0 ]; then
        pass "active file had data before rotation (test is meaningful)"
    fi
else
    fail "script failed during rotation: $(cat "$work/rotate.log")"
fi

# active file below the cap must not be rotated
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
if EVE_MAX_TOTAL_BYTES=1G EVE_MAX_FILE_BYTES=1M EVE_RETENTION_DAYS=30 EVE_COMPRESS=0 \
    run --dir "$d" >"$work/norotate.log" 2>&1; then
    if [ -e "$d/eve.json" ] && [ "$(wc -c <"$d/eve.json")" -eq 1024 ]; then
        pass "active file below the cap is left untouched"
    else
        fail "active file below the cap was rotated or truncated"
    fi
else
    fail "script failed on the no-rotate case: $(cat "$work/norotate.log")"
fi

# ---------------------------------------------------------------------------
# 5. disk watermark thresholds
# ---------------------------------------------------------------------------
wm() { run --watermark-check "$1" 2>/dev/null; }
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 10)" = ok ]; then
    pass "watermark 10% -> ok"
else
    fail "watermark 10% -> $(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 10) (expected ok)"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 79)" = ok ]; then
    pass "watermark 79% -> ok"
else
    fail "watermark 79% is not ok"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 80)" = warn ]; then
    pass "watermark 80% -> warn (warn boundary is inclusive)"
else
    fail "watermark 80% -> $(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 80) (expected warn)"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 89)" = warn ]; then
    pass "watermark 89% -> warn"
else
    fail "watermark 89% is not warn"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 90)" = crit ]; then
    pass "watermark 90% -> crit (crit boundary is inclusive)"
else
    fail "watermark 90% -> $(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 90) (expected crit)"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm 100)" = crit ]; then
    pass "watermark 100% -> crit"
else
    fail "watermark 100% is not crit"
fi
if [ "$(EVE_DISK_WARN_PCT=70 EVE_DISK_CRIT_PCT=75 wm 72)" = warn ]; then
    pass "watermark honours overridden thresholds"
else
    fail "watermark ignored overridden thresholds"
fi
if [ "$(EVE_DISK_WARN_PCT=80 EVE_DISK_CRIT_PCT=90 wm notanumber)" = invalid ]; then
    pass "watermark rejects a non-numeric percentage"
else
    fail "watermark accepted a non-numeric percentage"
fi

# the alert path is rate-limited: once per level transition (dry runs exempt)
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
state="$work/rate.state"
rm -f "$state"
first=$(EVE_DISK_WARN_PCT=1 EVE_DISK_CRIT_PCT=100 EVE_ALERT_STATE="$state" \
    EVE_ROTATE_CONF="$work/no-such.conf" EVE_SYSLOG=0 sh "$script" --dir "$d" 2>&1 >/dev/null)
second=$(EVE_DISK_WARN_PCT=1 EVE_DISK_CRIT_PCT=100 EVE_ALERT_STATE="$state" \
    EVE_ROTATE_CONF="$work/no-such.conf" EVE_SYSLOG=0 sh "$script" --dir "$d" 2>&1 >/dev/null)
if contains "$first" 'WARN EVE disk usage'; then
    pass "first run in a new level emits an alert"
else
    fail "first run at warn emitted no alert"
fi
if contains "$second" 'WARN EVE disk usage'; then
    fail "repeated alert was not rate-limited"
else
    pass "the same level is not re-alerted on the next run"
fi
recovered=$(EVE_DISK_WARN_PCT=99 EVE_DISK_CRIT_PCT=100 EVE_ALERT_STATE="$state" \
    EVE_ROTATE_CONF="$work/no-such.conf" EVE_SYSLOG=0 sh "$script" --dir "$d" 2>&1 >/dev/null)
if contains "$recovered" 'RECOVERED EVE disk usage'; then
    pass "dropping below the warn threshold emits a recovery notice"
else
    fail "recovery notice was not emitted: $recovered"
fi
if [ ! -e "$state" ] || ! grep -q '^ok ' "$state"; then
    fail "rate-limit state did not record the recovered level"
else
    pass "rate-limit state records the recovered level"
fi
# an unchanged level re-alerts once the repeat interval has elapsed
repeat=$(EVE_DISK_WARN_PCT=1 EVE_DISK_CRIT_PCT=100 EVE_ALERT_REPEAT_SECONDS=0 \
    EVE_ALERT_STATE="$state" EVE_ROTATE_CONF="$work/no-such.conf" EVE_SYSLOG=0 \
    sh "$script" --dir "$d" 2>&1 >/dev/null)
if contains "$repeat" 'WARN EVE disk usage'; then
    pass "the same level re-alerts after EVE_ALERT_REPEAT_SECONDS"
else
    fail "repeat interval did not re-alert: $repeat"
fi

# ---------------------------------------------------------------------------
# 6. thresholds are overridable and reported back
# ---------------------------------------------------------------------------
printed=$(EVE_MAX_FILE_BYTES=123M EVE_MAX_TOTAL_BYTES=456M EVE_RETENTION_DAYS=7 \
    EVE_DISK_WARN_PCT=75 EVE_DISK_CRIT_PCT=85 run --print-config 2>&1)
for expected in 'max_file_bytes=128974848' 'max_total_bytes=478150656' \
    'retention_days=7' 'disk_warn_pct=75' 'disk_crit_pct=85'; do
    if has_line "$printed" "$expected"; then
        pass "print-config reports $expected"
    else
        fail "print-config did not report $expected (got: $(printf '%s' "$printed" | tr '\n' ' '))"
    fi
done
printed_default=$(run --print-config 2>&1)
if has_line "$printed_default" 'max_file_bytes=209715200'; then
    pass "default file cap is 200M"
else
    fail "default file cap is not 200M"
fi
if has_line "$printed_default" 'max_total_bytes=2147483648'; then
    pass "default total cap is 2G"
else
    fail "default total cap is not 2G"
fi

# config file supplies defaults, environment still wins
cat >"$work/conf" <<'EOF'
EVE_MAX_FILE_BYTES=64M
EVE_MAX_TOTAL_BYTES=512M
EVE_RETENTION_DAYS=5
EVE_DISK_WARN_PCT=70
EVE_DISK_CRIT_PCT=85
EOF
from_conf=$(EVE_ROTATE_CONF="$work/conf" EVE_SYSLOG=0 sh "$script" --print-config 2>&1)
if has_line "$from_conf" 'retention_days=5'; then
    pass "config file supplies defaults"
else
    fail "config file was not loaded"
fi
env_wins=$(EVE_ROTATE_CONF="$work/conf" EVE_SYSLOG=0 EVE_RETENTION_DAYS=2 \
    sh "$script" --print-config 2>&1)
if has_line "$env_wins" 'retention_days=2'; then
    pass "environment overrides the config file"
else
    fail "environment did not override the config file"
fi

# the config file is parsed as data, never evaluated
cat >"$work/evil.conf" <<'EOF'
UNKNOWN_KEY=$(touch /tmp/lyflow-eve-retention-pwned)
EVE_RETENTION_DAYS=4
EOF
evil_out=$(EVE_ROTATE_CONF="$work/evil.conf" EVE_SYSLOG=0 sh "$script" --print-config 2>&1)
if has_line "$evil_out" 'retention_days=4'; then
    pass "config parser accepts a known key next to an unknown one"
else
    fail "config parser failed on a file with an unknown key: $(printf '%s' "$evil_out" | tr '\n' ' ')"
fi
if [ -e /tmp/lyflow-eve-retention-pwned ]; then
    fail "config file contents were executed as shell"
    rm -f /tmp/lyflow-eve-retention-pwned
else
    pass "config file contents are not executed as shell"
fi

# ---------------------------------------------------------------------------
# 6b. watermark alerts reach stderr with the right level word
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
warn_err=$(EVE_DISK_WARN_PCT=1 EVE_DISK_CRIT_PCT=100 run --dir "$d" --dry-run 2>&1 >/dev/null)
if contains "$warn_err" 'WARN EVE disk usage'; then
    pass "warn watermark emits a WARN alert"
else
    fail "warn watermark did not emit a WARN alert: $warn_err"
fi
crit_err=$(EVE_DISK_WARN_PCT=1 EVE_DISK_CRIT_PCT=2 run --dir "$d" --dry-run 2>&1 >/dev/null)
if contains "$crit_err" 'CRIT EVE disk usage'; then
    pass "crit watermark emits a CRIT alert"
else
    fail "crit watermark did not emit a CRIT alert: $crit_err"
fi
quiet_err=$(EVE_DISK_WARN_PCT=99 EVE_DISK_CRIT_PCT=100 run --dir "$d" --dry-run 2>&1 >/dev/null)
if contains "$quiet_err" 'EVE disk usage'; then
    fail "a healthy filesystem still produced a watermark alert"
else
    pass "no watermark alert below the warn threshold"
fi

# ---------------------------------------------------------------------------
# 7. dry run changes nothing
# ---------------------------------------------------------------------------
d=$(new_dir)
make_file "$d" eve.json 4096 "$(hours_ago 1)" >/dev/null
make_file "$d" eve.json.20260101T000000Z 92160 "$(hours_ago 5)" >/dev/null
snapshot_before=$(find "$d" -maxdepth 1 -type f -printf '%f %s\n' | sort)
if EVE_MAX_TOTAL_BYTES=1K EVE_MAX_FILE_BYTES=1K EVE_RETENTION_DAYS=1 EVE_COMPRESS=1 \
    run --dir "$d" --dry-run >"$work/dry.log" 2>&1; then
    snapshot_after=$(find "$d" -maxdepth 1 -type f -printf '%f %s\n' | sort)
    if [ "$snapshot_before" = "$snapshot_after" ]; then
        pass "dry run leaves the directory unchanged"
    else
        fail "dry run modified the directory"
    fi
    if grep -q 'would rotate\|would delete\|would compress' "$work/dry.log"; then
        pass "dry run reports the planned actions"
    else
        fail "dry run reported no planned actions"
    fi
else
    fail "dry run failed: $(cat "$work/dry.log")"
fi

# ---------------------------------------------------------------------------
# 8. invalid configuration is rejected instead of silently disabling retention
# ---------------------------------------------------------------------------
if EVE_MAX_TOTAL_BYTES=lots run --print-config >"$work/bad.log" 2>&1; then
    fail "invalid EVE_MAX_TOTAL_BYTES was accepted"
else
    pass "invalid EVE_MAX_TOTAL_BYTES is rejected"
fi
if EVE_RETENTION_DAYS=0 run --print-config >"$work/bad2.log" 2>&1; then
    fail "EVE_RETENTION_DAYS=0 was accepted"
else
    pass "EVE_RETENTION_DAYS=0 is rejected"
fi
if EVE_DISK_WARN_PCT=95 EVE_DISK_CRIT_PCT=90 run --print-config >"$work/bad3.log" 2>&1; then
    fail "warn >= crit was accepted"
else
    pass "warn >= crit is rejected"
fi

# a total cap smaller than two rotated files is allowed but must be reported
d=$(new_dir)
make_file "$d" eve.json 1024 "$(hours_ago 1)" >/dev/null
warn_out=$(EVE_MAX_TOTAL_BYTES=1K EVE_MAX_FILE_BYTES=1K EVE_RETENTION_DAYS=30 \
    EVE_COMPRESS=0 run --dir "$d" --dry-run 2>&1)
if contains "$warn_out" 'below 2x EVE_MAX_FILE_BYTES'; then
    pass "a total cap below 2x the file cap is reported"
else
    fail "a total cap below 2x the file cap was not reported"
fi
quiet_out=$(EVE_MAX_TOTAL_BYTES=2G EVE_MAX_FILE_BYTES=200M EVE_RETENTION_DAYS=30 \
    EVE_COMPRESS=0 run --dir "$d" --dry-run 2>&1)
if contains "$quiet_out" 'below 2x EVE_MAX_FILE_BYTES'; then
    fail "a sane cap ratio still produced the misconfiguration warning"
else
    pass "a sane cap ratio produces no misconfiguration warning"
fi

# ---------------------------------------------------------------------------
# 9. missing directory is a no-op, not a failure
# ---------------------------------------------------------------------------
if run --dir "$work/does-not-exist" >"$work/missing.log" 2>&1; then
    pass "missing directory is a no-op"
else
    fail "missing directory caused a failure"
fi

# ---------------------------------------------------------------------------
# 10. the script is POSIX sh and has no CRLF line endings
# ---------------------------------------------------------------------------
if command -v sh >/dev/null 2>&1; then
    if sh -n "$script"; then
        pass "eve-retention.sh parses as POSIX sh"
    else
        fail "eve-retention.sh is not valid POSIX sh"
    fi
fi
crlf=$(tr -cd '\r' <"$script" | wc -c | tr -d ' ')
if [ "$crlf" = "0" ]; then
    pass "eve-retention.sh has LF line endings"
else
    fail "eve-retention.sh has $crlf CR bytes (CRLF breaks backslash continuations on Linux)"
fi
crlf_bad=0
for f in "$timer" "$service" "$conf"; do
    count=$(tr -cd '\r' <"$f" | wc -c | tr -d ' ')
    if [ "$count" != "0" ]; then
        fail "$(basename "$f") has $count CR bytes"
        crlf_bad=1
    fi
done
[ "$crlf_bad" = "0" ] && pass "service, timer and conf are LF"

if [ "$failures" -ne 0 ]; then
    printf '\n%d eve-rotate checks failed\n' "$failures" >&2
    exit 1
fi
printf '\neve-rotate: all checks passed\n'
