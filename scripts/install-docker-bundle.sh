#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
install_dir="${LYFLOW_INSTALL_DIR:-/opt/ly-flow-platform}"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null || { echo "docker compose plugin is required" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
bundle_arch=$(tr -d '[:space:]' < "$root/images/architecture")
[ "$host_arch" = "$bundle_arch" ] || {
  echo "package architecture is $bundle_arch, but this host is $host_arch" >&2
  exit 1
}

mkdir -p "$install_dir"
cp -a "$root/." "$install_dir/"
cd "$install_dir"
docker load < images/lyflow-images.tar.gz

if [ ! -f .env ]; then
  management="${MANAGEMENT_INTERFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
  mirror="${LOCAL_MIRROR_INTERFACE:-}"
  cat > .env <<EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-lyflow-postgres-$(openssl rand -hex 12)}
REDIS_ACL_USERNAME=${REDIS_ACL_USERNAME:-lyflow}
REDIS_ACL_PASSWORD=${REDIS_ACL_PASSWORD:-lyflow-redis-$(openssl rand -hex 12)}
REDIS_PASSWORD=${REDIS_PASSWORD:-lyflow-redis-$(openssl rand -hex 12)}
CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:-lyflow-clickhouse-$(openssl rand -hex 12)}
JWT_SECRET=${JWT_SECRET:-$(openssl rand -hex 32)}
SECURITY_ENGINE_CONTROL_TOKEN=${SECURITY_ENGINE_CONTROL_TOKEN:-$(openssl rand -hex 24)}
DEFAULT_ADMIN_PASSWORD=${DEFAULT_ADMIN_PASSWORD:-password}
LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE=true
MANAGEMENT_INTERFACE=${management:-ens33}
LOCAL_MIRROR_INTERFACE=${mirror:-}
POSTGRES_BIND_PORT=${POSTGRES_BIND_PORT:-5432}
REDIS_BIND_PORT=${REDIS_BIND_PORT:-6379}
CLICKHOUSE_HTTP_BIND_PORT=${CLICKHOUSE_HTTP_BIND_PORT:-8123}
CLICKHOUSE_NATIVE_BIND_PORT=${CLICKHOUSE_NATIVE_BIND_PORT:-9000}
SERVER_BIND_PORT=${SERVER_BIND_PORT:-8080}
HTTPS_BIND_PORT=${HTTPS_BIND_PORT:-443}
HTTP_BIND_PORT=${HTTP_BIND_PORT:-80}
AGENT_CENTER_BIND_PORT=${AGENT_CENTER_BIND_PORT:-8081}
EOF
  chmod 600 .env
fi

upsert_env() {
  key=$1
  value=$2
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

upsert_env LYFLOW_PACKAGE_ARCH "$bundle_arch"
upsert_env POSTGRES_IMAGE "ly-flow/vendor/postgres:16-alpine-${bundle_arch}"
upsert_env REDIS_IMAGE "ly-flow/vendor/redis:7-alpine-${bundle_arch}"
upsert_env CLICKHOUSE_IMAGE "ly-flow/vendor/clickhouse:24.8-alpine-${bundle_arch}"
upsert_env LY_SERVER_IMAGE "ly-flow/server:release-${bundle_arch}"
upsert_env LY_SECURITY_ENGINE_IMAGE "ly-flow/security-engine:release-${bundle_arch}"
upsert_env LY_FRONTEND_IMAGE "ly-flow/frontend:release-${bundle_arch}"
upsert_env LY_LOCAL_MIRROR_IMAGE "ly-flow/local-mirror:release-${bundle_arch}"
upsert_env LY_SURICATA_IMAGE "ly-flow/suricata-profile:release-${bundle_arch}"
if [ "$bundle_arch" = amd64 ]; then
  upsert_env LOCAL_MIRROR_CAPTURE_ENGINE pfring
else
  upsert_env LOCAL_MIRROR_CAPTURE_ENGINE af_packet
fi

docker compose up -d
for attempt in $(seq 1 12); do
  expected=$(docker compose config --services | wc -l | tr -d ' ')
  running=$(docker compose ps --status running -q | wc -l | tr -d ' ')
  [ "$running" = "$expected" ] && break
  sleep 5
  docker compose up -d
done
expected=$(docker compose config --services | wc -l | tr -d ' ')
running=$(docker compose ps --status running -q | wc -l | tr -d ' ')
if [ "$running" != "$expected" ]; then
  docker compose ps
  echo "LyFlow startup incomplete: running $running of $expected services" >&2
  exit 1
fi
docker compose ps
echo "LyFlow started: https://$(hostname -I | awk '{print $1}')/"
echo "First login: admin / password (forced password change)"
