#!/usr/bin/env bash
set -euo pipefail

APP_NAME="ly-flow-platform"
INSTALL_DIR="${LYFLOW_INSTALL_DIR:-/opt/ly-flow-platform}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_ARCHIVE="$PACKAGE_ROOT/images/lyflow-images.tar.gz"
TRUST_DIR="${LYFLOW_TRUST_DIR:-/etc/lyflow/trust}"
TRUST_ROOT=""
HEALTH_URL="${LYFLOW_HEALTH_URL:-https://127.0.0.1/api/v1/health}"
HEALTH_TIMEOUT_SECONDS="${LYFLOW_HEALTH_TIMEOUT_SECONDS:-300}"
HEALTH_INTERVAL_SECONDS="${LYFLOW_HEALTH_INTERVAL_SECONDS:-5}"
MIN_DISK_GB="${LYFLOW_MIN_DISK_GB:-10}"
BACKUP_DIR=""
UPGRADE=0
PREVIOUS_STACK_STOPPED=0
STACK_STARTED=0
ROLLBACK_ARMED=0
GENERATE_ADMIN_PASSWORD=0

log() { printf '[lyflow-install] %s\n' "$*"; }
fail() { printf '[lyflow-install] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  printf 'usage: %s --trust-root /external/path/release-root.pem --generate-admin-password\n' "$0" >&2
}

parse_args() {
  TRUST_ROOT=""
  GENERATE_ADMIN_PASSWORD=0
  while (( $# > 0 )); do
    case "$1" in
      --trust-root)
        (( $# >= 2 )) || { usage; return 2; }
        TRUST_ROOT=$2
        shift 2
        ;;
      --generate-admin-password)
        GENERATE_ADMIN_PASSWORD=1
        shift
        ;;
      *)
        usage
        return 2
        ;;
    esac
  done
  if [[ -z "$TRUST_ROOT" || $GENERATE_ADMIN_PASSWORD -ne 1 ]]; then
    usage
    return 2
  fi
}

validate_release_root() {
  command -v openssl >/dev/null 2>&1 || fail "缺少 openssl，无法验证离线发布根"
  local external_root package_root relative
  external_root=$(realpath -e "$TRUST_ROOT") || fail "无法读取外部发布根: $TRUST_ROOT"
  package_root=$(realpath -e "$PACKAGE_ROOT") || fail "无法解析安装包目录"
  relative=$(realpath --relative-to="$package_root" "$external_root") || fail "无法比较发布根与安装包路径"
  if [[ "$relative" != .. && "$relative" != ../* ]]; then
    fail "--trust-root 必须来自安装包之外"
  fi
  openssl pkey -pubin -in "$external_root" -noout >/dev/null 2>&1 || fail "发布根 PEM 无效"
  TRUST_ROOT=$external_root
}

persist_release_root() {
  install -d -m 0755 "$TRUST_DIR"
  install -m 0644 "$TRUST_ROOT" "$TRUST_DIR/release-root.pem"
  TRUST_ROOT="$TRUST_DIR/release-root.pem"
}

verify_signed_manifest() {
  local root=$1 manifest_name=$2
  local manifest="$root/$manifest_name"
  local signature="$manifest.sig"
  [[ ! -L "$manifest" && ! -L "$signature" ]] || fail "$manifest_name contains a symlink"
  [[ -f "$manifest" ]] || fail "缺少 $manifest_name"
  [[ -f "$signature" ]] || fail "缺少 $manifest_name.sig"
  openssl pkeyutl -verify -pubin -inkey "$TRUST_ROOT" -rawin -in "$manifest" -sigfile "$signature" >/dev/null 2>&1 || fail "$manifest_name 签名验证失败"
  local digest path
  while read -r digest path; do
    path=${path#\*}
    if [[ ! "$digest" =~ ^[0-9a-f]{64}$ || -z "$path" || "$path" == /* || "$path" == ../* || "$path" == */../* || -L "$root/$path" || ! -f "$root/$path" ]]; then
      fail "发布清单包含越界路径"
    fi
  done < "$manifest"
  (cd "$root" && sha256sum --check --strict "$manifest_name" >/dev/null) || fail "$manifest_name 校验失败"
}

verify_release_bundle() {
  verify_signed_manifest "$PACKAGE_ROOT" release-manifest.sha256
  verify_signed_manifest "$PACKAGE_ROOT/rules" rules-manifest.sha256
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "请使用 root 执行，或用 sudo bash scripts/install-offline.sh"
  fi
}

preflight_error() {
  printf '[lyflow-install] ERROR: preflight %s\n' "$*" >&2
  return 1
}

require_commands() {
  local command_name
  for command_name in realpath sha256sum tar gzip openssl install df du curl; do
    command -v "$command_name" >/dev/null 2>&1 || preflight_error "missing command: $command_name" || return
  done
}

require_docker() {
  command -v docker >/dev/null 2>&1 || preflight_error "missing command: docker; install Docker before running this offline installer" || return
  docker info >/dev/null 2>&1 || preflight_error "Docker daemon is not running" || return
  docker compose version >/dev/null 2>&1 || preflight_error "docker compose plugin is unavailable"
}

check_package_files() {
  local required
  for required in \
    ARCH \
    docker-compose.yml \
    release-manifest.sha256 \
    release-manifest.sha256.sig \
    rules/rules-manifest.sha256 \
    rules/rules-manifest.sha256.sig; do
    [[ -f "$PACKAGE_ROOT/$required" ]] || preflight_error "package file is missing: $required" || return
  done
  [[ -s "$IMAGE_ARCHIVE" ]] || preflight_error "package image archive is missing or empty: images/lyflow-images.tar.gz" || return
  gzip -t "$IMAGE_ARCHIVE" >/dev/null 2>&1 || preflight_error "package image archive is invalid: images/lyflow-images.tar.gz"
}

normalize_architecture() {
  case "$1" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) return 1 ;;
  esac
}

check_architecture() {
  [[ -f "$PACKAGE_ROOT/ARCH" ]] || preflight_error "architecture metadata ARCH is missing" || return
  local host_arch package_arch
  host_arch=$(normalize_architecture "${LYFLOW_HOST_ARCH:-$(uname -m)}") || preflight_error "unsupported host architecture" || return
  package_arch=$(normalize_architecture "$(tr -d '[:space:]' <"$PACKAGE_ROOT/ARCH")") || preflight_error "invalid package architecture" || return
  [[ "$host_arch" == "$package_arch" ]] || preflight_error "architecture mismatch: package=$package_arch host=$host_arch"
}

check_disk_space() {
  local parent available_kb package_kb required_kb
  parent=$(dirname "$INSTALL_DIR")
  while [[ ! -d "$parent" && "$parent" != / ]]; do
    parent=$(dirname "$parent")
  done
  read -r _ _ _ available_kb _ < <(df -Pk "$parent" | awk 'NR == 2 {print}')
  package_kb=$(du -sk "$PACKAGE_ROOT" | awk '{print $1}')
  required_kb=$((package_kb + MIN_DISK_GB * 1024 * 1024))
  (( available_kb >= required_kb )) || preflight_error "disk space insufficient: need ${required_kb}KB, available ${available_kb}KB"
}

detect_installation() {
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    UPGRADE=1
  fi
}

check_ports() {
  (( UPGRADE == 1 )) && return 0
  local listening_ports=${LYFLOW_LISTENING_PORTS:-} port
  if [[ -z "$listening_ports" ]]; then
    command -v ss >/dev/null 2>&1 || preflight_error "missing command: ss" || return
    listening_ports=$(ss -H -ltn | awk '{address=$4; sub(/^.*:/, "", address); print address}')
  fi
  for port in 443 8081; do
    if [[ " $listening_ports " == *" $port "* ]]; then
      preflight_error "required port $port is already listening"
      return
    fi
  done
}

run_preflight() {
  require_commands
  require_docker
  check_package_files
  check_architecture
  check_disk_space
  detect_installation
  check_ports
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

generate_secret() {
  openssl rand -hex 32
}

write_env() {
  cd "$INSTALL_DIR"
  if [ -f .env ]; then
    log "保留已有 .env"
    return
  fi
  local postgres_password clickhouse_password jwt_secret admin_password redis_password control_token
  postgres_password=$(generate_secret)
  clickhouse_password=$(generate_secret)
  jwt_secret=$(generate_secret)
  admin_password=$(generate_secret)
  redis_password=$(generate_secret)
  control_token=$(generate_secret)
  umask 077
  cat > .env <<EOF
POSTGRES_PASSWORD=$postgres_password
CLICKHOUSE_PASSWORD=$clickhouse_password
JWT_SECRET=$jwt_secret
DEFAULT_ADMIN_PASSWORD=$admin_password
REDIS_ACL_USERNAME=lyflow
REDIS_ACL_PASSWORD=$redis_password
REDIS_PASSWORD=
SECURITY_ENGINE_CONTROL_TOKEN=$control_token
LYFLOW_RESET_ADMIN_PASSWORD=false
LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE=true
AGENT_SELF_ENROLL=false
LOCAL_MIRROR_INTERFACE=auto
ENGINE_LAB_EMIT_SAMPLE_EVENTS=false
EOF
  cat > initial-admin-credentials <<EOF
username=admin
password=$admin_password
EOF
  chmod 0600 .env initial-admin-credentials
  log "初始管理员凭据已写入 $INSTALL_DIR/initial-admin-credentials"
}

load_images() {
  cd "$INSTALL_DIR"
  [ -f images/lyflow-images.tar.gz ] || fail "缺少 images/lyflow-images.tar.gz"
  log "导入离线镜像"
  gzip -dc images/lyflow-images.tar.gz | docker load
}

compose_at() {
  local directory=$1
  shift
  (cd "$directory" && docker compose "$@")
}

compose() {
  compose_at "$INSTALL_DIR" "$@"
}

health_probe() {
  curl --insecure --fail --silent --show-error --max-time 5 "$HEALTH_URL" >/dev/null
}

diagnose_stack() {
  log "服务启动诊断"
  compose ps >&2 || true
  compose logs --tail 100 >&2 || true
}

wait_for_health() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if health_probe; then
      log "服务健康检查通过"
      return 0
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
  done
  diagnose_stack
  printf '[lyflow-install] ERROR: health check timed out after %ss: %s\n' "$HEALTH_TIMEOUT_SECONDS" "$HEALTH_URL" >&2
  return 1
}

stop_existing_stack() {
  (( UPGRADE == 1 )) || return 0
  log "停止现有服务以执行升级"
  PREVIOUS_STACK_STOPPED=1
  compose_at "$INSTALL_DIR" down --remove-orphans
}

prepare_install() {
  mkdir -p "$(dirname "$INSTALL_DIR")"
  if [[ -e "$INSTALL_DIR" ]]; then
    BACKUP_DIR="${INSTALL_DIR}.backup.$(date +%s).$$"
    mv "$INSTALL_DIR" "$BACKUP_DIR"
  fi
  mkdir -p "$INSTALL_DIR"
  if [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/.env" ]]; then
    cp -p "$BACKUP_DIR/.env" "$INSTALL_DIR/.env"
  fi
  if [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/initial-admin-credentials" ]]; then
    cp -p "$BACKUP_DIR/initial-admin-credentials" "$INSTALL_DIR/initial-admin-credentials"
  fi
  ROLLBACK_ARMED=1
}

rollback_install() {
  log "安装失败，正在回滚"
  if (( ROLLBACK_ARMED == 1 )); then
    if (( STACK_STARTED == 1 )) && [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
      compose down --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -rf "$INSTALL_DIR"
    if [[ -n "$BACKUP_DIR" && -e "$BACKUP_DIR" ]]; then
      mv "$BACKUP_DIR" "$INSTALL_DIR"
    fi
  fi
  if (( PREVIOUS_STACK_STOPPED == 1 )) && [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    compose_at "$INSTALL_DIR" up -d >/dev/null 2>&1 || log "警告: 旧版本恢复后未能自动启动"
  fi
  ROLLBACK_ARMED=0
}

commit_install() {
  if [[ -n "$BACKUP_DIR" && -e "$BACKUP_DIR" ]]; then
    rm -rf "$BACKUP_DIR"
  fi
  ROLLBACK_ARMED=0
}

on_exit() {
  local status=$1
  trap - EXIT INT TERM
  if (( status != 0 )); then
    rollback_install
  fi
  exit "$status"
}

start_stack() {
  log "启动流影"
  STACK_STARTED=1
  if ! compose up -d; then
    return 1
  fi
  log "等待服务启动"
  wait_for_health
  compose ps
  log "安装完成：浏览器访问 https://<本机IP>/ ，管理员密码见 initial-admin-credentials"
}

main() {
  parse_args "$@"
  require_root
  run_preflight
  validate_release_root
  verify_release_bundle
  ensure_docker_running
  trap 'on_exit $?' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  stop_existing_stack
  prepare_install
  copy_payload
  write_env
  load_images
  start_stack
  persist_release_root
  commit_install
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
