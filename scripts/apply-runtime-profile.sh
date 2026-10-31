#!/bin/sh
# Pick capture/Redis defaults for the host and apply them.
#
# Two defaults:
#   x86_64 : large-memory assumption -> more threads, bigger AF_PACKET ring,
#            Redis up to 8 GB, 2h stream retention
#   aarch64: 4-8 GB assumption       -> fewer threads, small ring, Redis 1 GB,
#            1h stream retention
#
# Both are capped by the real CPU count and RAM so a small x86 box does not get
# an 8 GB Redis limit.
#
# Usage: scripts/apply-runtime-profile.sh [--dry-run]
set -eu

dry_run=0
[ "${1:-}" = "--dry-run" ] && dry_run=1

platform_dir=${LYFLOW_PLATFORM_DIR:-/opt/ly-flow-platform}
profile="$platform_dir/suricata/lyflow-suricata-profile.yaml"
env_file="$platform_dir/.env"
nproc=$(nproc 2>/dev/null || echo 2)
mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)
mem_gb=$((mem_kb / 1024 / 1024))

case "$(uname -m)" in
  x86_64|amd64)
    profile_name="x86-large"
    threads=6; ring_size=8192; buffer_size=32768
    redis_max="8gb"; retention_hours=2
    ;;
  aarch64|arm64)
    profile_name="arm-small"
    threads=2; ring_size=2048; buffer_size=32768
    redis_max="1gb"; retention_hours=1
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  aarch64|arm64) [ "$mem_gb" -ge 8 ] && ring_size=4096 ;;
esac
[ "$threads" -gt "$nproc" ] && threads=$nproc
[ "$threads" -lt 1 ] && threads=1

# Keep Redis at 60% of RAM; noeviction aborts writes rather than OOM.
max_redis_gb=$((mem_gb * 3 / 5))
[ "$max_redis_gb" -lt 1 ] && max_redis_gb=1
case "$redis_max" in
  8gb) [ "$max_redis_gb" -lt 8 ] && redis_max="${max_redis_gb}gb" ;;
  1gb) [ "$max_redis_gb" -lt 1 ] && redis_max="1gb" ;;
esac

printf 'profile=%s arch=%s cpus=%s mem=%sGB threads=%s ring=%s buffer=%s redis=%s retention=%sh\n' \
  "$profile_name" "$(uname -m)" "$nproc" "$mem_gb" "$threads" "$ring_size" "$buffer_size" "$redis_max" "$retention_hours"

[ "$dry_run" -eq 1 ] && exit 0

[ -f "$profile" ] || { echo "missing profile: $profile" >&2; exit 1; }
cp -a "$profile" "$profile.bak.$(date +%s)"

python3 - "$profile" "$threads" "$ring_size" "$buffer_size" <<'PY'
import io, re, sys
path, threads, ring, buf = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = io.open(path, encoding="utf-8").read()
start = text.find("af-packet:")
if start < 0:
    raise SystemExit("af-packet block not found")
# Rewrite only the first af-packet entry.
end = len(text)
next_key = re.search(r"\n[a-zA-Z0-9_-]+:", text[start + 1 :])
if next_key:
    end = start + 1 + next_key.start() + 1
block = (
    "af-packet:\n"
    "  - interface: __IFACE__\n"
    "    cluster-type: cluster_flow\n"
    "    cluster-id: 99\n"
    f"    threads: {threads}\n"
    "    defrag: yes\n"
    f"    ring-size: {ring}\n"
    f"    buffer-size: {buf}\n"
    "    bpf-filter: \"not (src net 10.0.0.0/8 and dst net 10.0.0.0/8)\"\n"
)
iface = re.search(r"interface:\s*(\S+)", text[start:end])
iface = iface.group(1) if iface else "mirror0"
block = block.replace("__IFACE__", iface)
io.open(path, "w", encoding="utf-8", newline="").write(text[:start] + block + text[end:])
print("profile rewritten")
PY

if [ -f "$env_file" ]; then
  sed -i -e "s|^REDIS_MAXMEMORY=.*|REDIS_MAXMEMORY=$redis_max|" "$env_file"
  grep -q '^REDIS_MAXMEMORY=' "$env_file" || echo "REDIS_MAXMEMORY=$redis_max" >>"$env_file"
  sed -i -e "s|^REDIS_STREAM_RETENTION_HOURS=.*|REDIS_STREAM_RETENTION_HOURS=$retention_hours|" "$env_file"
  grep -q '^REDIS_STREAM_RETENTION_HOURS=' "$env_file" || echo "REDIS_STREAM_RETENTION_HOURS=$retention_hours" >>"$env_file"
fi

cd "$platform_dir"
docker compose up -d --no-deps --force-recreate ly-suricata-sensor redis
echo "applied profile=$profile_name"
