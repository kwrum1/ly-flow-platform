#!/usr/bin/env bash
set -euo pipefail

APP_NAME="ly-flow-platform"
INSTALL_DIR="${LYFLOW_INSTALL_DIR:-/opt/ly-flow-platform}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_ARCHIVE="$PACKAGE_ROOT/images/lyflow-images.tar.gz"

log() { printf '[lyflow-install] %s\n' "$*"; }
fail() { printf '[lyflow-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "请使用 root 执行，或用 sudo bash scripts/install-offline.sh"
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    return
  fi
  log "未检测到 Docker，开始安装 Docker"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    . /etc/os-release
    codename="${VERSION_CODENAME:-$(lsb_release -cs)}"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID:-ubuntu} $codename stable" > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y dnf-plugins-core curl
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    yum install -y yum-utils curl
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    fail "不支持的系统：请先安装 Docker 和 docker compose plugin"
  fi
}

ensure_docker_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker
  else
    service docker start 2>/dev/null || true
  fi
  docker info >/dev/null 2>&1 || fail "Docker 未运行"
  docker compose version >/dev/null 2>&1 || fail "缺少 docker compose plugin"
}

copy_payload() {
  log "安装文件复制到 $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar --exclude='./images/lyflow-images.tar.gz' --exclude='./lyflow-offline-install-*.tar.gz' -C "$PACKAGE_ROOT" -cf - . | tar -C "$INSTALL_DIR" -xf -
  mkdir -p "$INSTALL_DIR/images"
  if [ -f "$IMAGE_ARCHIVE" ]; then
    cp "$IMAGE_ARCHIVE" "$INSTALL_DIR/images/"
  fi
  mkdir -p "$INSTALL_DIR/.sisyphus/runtime/engine-outputs"/{suricata,wazuh,yara,rasp,status}
}

write_env() {
  cd "$INSTALL_DIR"
  if [ -f .env ]; then
    log "保留已有 .env"
    return
  fi
  jwt_secret="$(openssl rand -hex 32 2>/dev/null || date +%s%N)"
  cat > .env <<EOF
POSTGRES_PASSWORD=lyflow_secret_password
CLICKHOUSE_PASSWORD=lyflow_clickhouse_password
JWT_SECRET=$jwt_secret
DEFAULT_ADMIN_PASSWORD=password
LYFLOW_RESET_ADMIN_PASSWORD=true
LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE=true
AGENT_SELF_ENROLL=true
LOCAL_MIRROR_INTERFACE=auto
ENGINE_LAB_EMIT_SAMPLE_EVENTS=false
EOF
}

load_images() {
  cd "$INSTALL_DIR"
  [ -f images/lyflow-images.tar.gz ] || fail "缺少 images/lyflow-images.tar.gz"
  log "导入离线镜像"
  gzip -dc images/lyflow-images.tar.gz | docker load
}

start_stack() {
  cd "$INSTALL_DIR"
  log "启动流影"
  docker compose up -d
  log "等待服务启动"
  sleep 5
  docker compose ps
  log "安装完成：浏览器访问 https://<本机IP>/ ，默认账号 admin / password"
}

require_root
install_docker
ensure_docker_running
copy_payload
write_env
load_images
start_stack
