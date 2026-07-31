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
LY_SERVER_IMAGE=ly-flow/server:productfix-20260731
LY_SECURITY_ENGINE_IMAGE=ly-flow/security-engine:healthstream2-20260731
LY_FRONTEND_IMAGE=ly-flow/frontend:productfix-20260731
LY_SURICATA_IMAGE=ly-flow/suricata-profile:release-rc-652a7b620dfd-todo5-20260730T071221Z-amd64
EOF
  chmod 600 .env
fi
docker compose up -d
echo "LyFlow started: https://$(hostname -I | awk '{print $1}')/"
echo "First login: admin / password (forced password change)"
