#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
install_dir="${LYFLOW_INSTALL_DIR:-/opt/ly-flow-platform}"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null || { echo "docker compose plugin is required" >&2; exit 1; }
mkdir -p "$install_dir"
cp -a "$root/." "$install_dir/"
cd "$install_dir"
docker load < images/lyflow-images.tar.gz
if [ ! -f .env ]; then
  management="${MANAGEMENT_INTERFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
  mirror="${LOCAL_MIRROR_INTERFACE:-$management}"
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
LOCAL_MIRROR_INTERFACE=${mirror:-ens35}
LY_LOCAL_MIRROR_IMAGE=ly-flow/local-mirror:signed4
LY_SERVER_IMAGE=ly-flow/server:bugfix-20260801-v2
LY_SECURITY_ENGINE_IMAGE=ly-flow/security-engine:release-138986fe8514d6eb0eb4a7ea037bf7f8dd9a7644-amd64
LY_FRONTEND_IMAGE=ly-flow/frontend:bugfix-20260801
LY_SURICATA_IMAGE=ly-flow/suricata-profile:release-rc-652a7b620dfd-todo5-20260730T071221Z-amd64
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
docker compose up -d
for attempt in 0 0seq 1 12); do
  expected=0 0docker compose config --services | wc -l | tr -d " ")
  running=0 0docker compose ps --status running -q | wc -l | tr -d " ")
  [ "" = "" ] && break
  sleep 5
  docker compose up -d
done
expected=0 0docker compose config --services | wc -l | tr -d " ")
running=0 0docker compose ps --status running -q | wc -l | tr -d " ")
if [ "" != "" ]; then
  docker compose ps
  echo "LyFlow startup incomplete: running  of  services" >&2
  exit 1
fi
docker compose ps
echo "LyFlow started: https://$(hostname -I | awk '{print $1}')/"
echo "First login: admin / password (forced password change)"
