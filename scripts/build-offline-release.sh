#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="$ROOT_DIR/release"
TARGET_ARCH="${TARGET_ARCH:-amd64}"
PLATFORM="linux/$TARGET_ARCH"
PACKAGE_NAME="lyflow-offline-install-${TARGET_ARCH}-$(date +%Y%m%d%H%M%S)"
PACKAGE_DIR="$RELEASE_DIR/$PACKAGE_NAME"
IMAGE_ARCHIVE="$PACKAGE_DIR/images/lyflow-images.tar.gz"
TAG_SUFFIX=""
if [[ "$TARGET_ARCH" != "amd64" ]]; then
  TAG_SUFFIX="-$TARGET_ARCH"
fi

IMAGES=(
  ${DB_POSTGRES_IMAGE:-postgres:16-alpine}
  ${DB_REDIS_IMAGE:-redis:7-alpine}
  ${DB_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:24.8-alpine}
  ly-flow/server:latest${TAG_SUFFIX}
  ly-flow/frontend:latest${TAG_SUFFIX}
  ly-flow/security-engine:latest${TAG_SUFFIX}
  ly-flow/security-engines:latest${TAG_SUFFIX}
  ly-flow/agent:latest${TAG_SUFFIX}
  ly-flow/dpi-engine:latest${TAG_SUFFIX}
)

log() { printf '[lyflow-release] %s\n' "$*"; }
run() { log "$*"; "$@"; }
run_in() { local dir="$1"; shift; log "cd $dir && $*"; (cd "$dir" && "$@"); }

cd "$ROOT_DIR"

log "building static Go binaries"
run_in "$ROOT_DIR/server" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -o ly-server ./cmd
run_in "$ROOT_DIR/server" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -o ly-agent-center ./agentcenter
mkdir -p "$ROOT_DIR/agent/dist/linux/amd64" "$ROOT_DIR/agent/dist/linux/arm64" "$ROOT_DIR/agent/dist/windows/amd64"
if [[ "$TARGET_ARCH" == "amd64" ]]; then
  run_in "$ROOT_DIR/agent" env GOOS=linux GOARCH="$TARGET_ARCH" GOWORK=off go build -o ly-agent ./cmd
  cp "$ROOT_DIR/agent/ly-agent" "$ROOT_DIR/agent/ly-agent-linux-amd64"
  cp "$ROOT_DIR/agent/ly-agent" "$ROOT_DIR/agent/dist/linux/amd64/ly-agent"
else
  if [[ -n "${ARM64_AGENT_BINARY:-}" && -f "${ARM64_AGENT_BINARY:-}" ]]; then
    log "using supplied ARM64 agent binary: $ARM64_AGENT_BINARY"
    cp "$ARM64_AGENT_BINARY" "$ROOT_DIR/agent/ly-agent"
    cp "$ARM64_AGENT_BINARY" "$ROOT_DIR/agent/ly-agent-linux-arm64"
    cp "$ARM64_AGENT_BINARY" "$ROOT_DIR/agent/dist/linux/arm64/ly-agent"
  else
    printf '[lyflow-release] ERROR: TARGET_ARCH=arm64 requires an ARM64 ly-agent binary because agent depends on CGO/libpcap. Set ARM64_AGENT_BINARY=/path/to/ly-agent built on ARM64 or install an ARM64 CGO cross toolchain.\n' >&2
    exit 1
  fi
fi
run_in "$ROOT_DIR/agent" env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go build -o ly-agent-windows-amd64.exe ./cmd
cp "$ROOT_DIR/agent/ly-agent-windows-amd64.exe" "$ROOT_DIR/agent/dist/windows/amd64/ly-agent.exe"
run_in "$ROOT_DIR/dpi-engine" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -o ly-dpi-engine ./cmd
run_in "$ROOT_DIR/security-engine" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -o ly-security-engine ./cmd

log "building frontend"
run npm --prefix frontend run build

ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "using local image $image"
    return
  fi
  if [[ "${LYFLOW_CI_LOCAL_CACHE:-}" == "1" ]]; then
    printf '[lyflow-release] ERROR: required image %s is missing from the local CI cache. Pre-pull it before running release workflow.
' "$image" >&2
    exit 1
  fi
  run docker pull --platform "$PLATFORM" "$image"
}

if [[ "${LYFLOW_CI_LOCAL_CACHE:-}" == "1" ]]; then
  export DOCKER_BUILDKIT=0
  export COMPOSE_DOCKER_CLI_BUILD=0
fi

log "checking runtime and base images"
ensure_image postgres:16-alpine
ensure_image redis:7-alpine
ensure_image clickhouse/clickhouse-server:24.8-alpine
ensure_image nginx:1.27-alpine

if [[ "${LYFLOW_CI_LOCAL_CACHE:-}" == "1" ]]; then
  log "using prebuilt local application images from CI cache"
  for image in "${IMAGES[@]}"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      printf '[lyflow-release] ERROR: required cached image %s is missing. Build or pull it before running with LYFLOW_CI_LOCAL_CACHE=1.
' "$image" >&2
      exit 1
    fi
  done
elif [[ "$TARGET_ARCH" == "amd64" ]]; then
  log "rebuilding application images without cache"
  run docker compose build --no-cache ly-server ly-vis
  run docker compose --profile legacy-dpi build --no-cache ly-dpi-engine
  run docker compose build --no-cache ly-security-engine ly-engine-lab ly-local-mirror
  run docker compose --profile container-agent build --no-cache ly-agent
else
  log "rebuilding application images without cache"
  run docker buildx build --platform "$PLATFORM" --load --no-cache -f server/Dockerfile.final -t "ly-flow/server:latest${TAG_SUFFIX}" .
  run docker buildx build --platform "$PLATFORM" --load --no-cache -f frontend/Dockerfile -t "ly-flow/frontend:latest${TAG_SUFFIX}" .
  run docker buildx build --platform "$PLATFORM" --load --no-cache -f dpi-engine/Dockerfile -t "ly-flow/dpi-engine:latest${TAG_SUFFIX}" .
  run docker buildx build --platform "$PLATFORM" --load --no-cache --build-arg "RUNTIME_IMAGE=ly-flow/dpi-engine:latest${TAG_SUFFIX}" -f security-engine/Dockerfile -t "ly-flow/security-engine:latest${TAG_SUFFIX}" .
  run docker buildx build --platform "$PLATFORM" --load --no-cache --build-arg "RUNTIME_IMAGE=ly-flow/server:latest${TAG_SUFFIX}" -f agent/Dockerfile -t "ly-flow/agent:latest${TAG_SUFFIX}" .
  run docker buildx build --platform "$PLATFORM" --load --no-cache --build-arg "RUNTIME_IMAGE=ly-flow/server:latest${TAG_SUFFIX}" -f containers/security-engines/Dockerfile -t "ly-flow/security-engines:latest${TAG_SUFFIX}" .
  mkdir -p /tmp/lyflow-arm64-base
  printf 'FROM --platform=%s postgres:16-alpine\n' "$PLATFORM" > /tmp/lyflow-arm64-base/Postgresfile
  printf 'FROM --platform=%s redis:7-alpine\n' "$PLATFORM" > /tmp/lyflow-arm64-base/Redisfile
  printf 'FROM --platform=%s clickhouse/clickhouse-server:24.8-alpine\n' "$PLATFORM" > /tmp/lyflow-arm64-base/Clickhousefile
  run docker buildx build --platform "$PLATFORM" --load -f /tmp/lyflow-arm64-base/Postgresfile -t "ly-flow/postgres:16-alpine${TAG_SUFFIX}" /tmp/lyflow-arm64-base
  run docker buildx build --platform "$PLATFORM" --load -f /tmp/lyflow-arm64-base/Redisfile -t "ly-flow/redis:7-alpine${TAG_SUFFIX}" /tmp/lyflow-arm64-base
  run docker buildx build --platform "$PLATFORM" --load -f /tmp/lyflow-arm64-base/Clickhousefile -t "ly-flow/clickhouse:24.8-alpine${TAG_SUFFIX}" /tmp/lyflow-arm64-base
fi

log "creating package directory $PACKAGE_DIR"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/images" "$PACKAGE_DIR/scripts" "$PACKAGE_DIR/rules" "$PACKAGE_DIR/server/sql"

cp docker-compose.yml "$PACKAGE_DIR/docker-compose.yml"
if [[ -n "$TAG_SUFFIX" ]]; then
  DB_POSTGRES_IMAGE="ly-flow/postgres:16-alpine${TAG_SUFFIX}"
  DB_REDIS_IMAGE="ly-flow/redis:7-alpine${TAG_SUFFIX}"
  DB_CLICKHOUSE_IMAGE="ly-flow/clickhouse:24.8-alpine${TAG_SUFFIX}"
  sed -i \
    -e "s#postgres:16-alpine#$DB_POSTGRES_IMAGE#g" \
    -e "s#redis:7-alpine#$DB_REDIS_IMAGE#g" \
    -e "s#clickhouse/clickhouse-server:24.8-alpine#$DB_CLICKHOUSE_IMAGE#g" \
    -e "s#ly-flow/server:latest#ly-flow/server:latest${TAG_SUFFIX}#g" \
    -e "s#ly-flow/frontend:latest#ly-flow/frontend:latest${TAG_SUFFIX}#g" \
    -e "s#ly-flow/security-engine:latest#ly-flow/security-engine:latest${TAG_SUFFIX}#g" \
    -e "s#ly-flow/security-engines:latest#ly-flow/security-engines:latest${TAG_SUFFIX}#g" \
    -e "s#ly-flow/agent:latest#ly-flow/agent:latest${TAG_SUFFIX}#g" \
    -e "s#ly-flow/dpi-engine:latest#ly-flow/dpi-engine:latest${TAG_SUFFIX}#g" \
    "$PACKAGE_DIR/docker-compose.yml"
fi
cp scripts/install-offline.sh "$PACKAGE_DIR/scripts/install-offline.sh"
chmod +x "$PACKAGE_DIR/scripts/install-offline.sh"
cp scripts/init-db.sql "$PACKAGE_DIR/scripts/init-db.sql"
cp server/sql/asset_tables.sql "$PACKAGE_DIR/server/sql/asset_tables.sql"
cp -a rules/. "$PACKAGE_DIR/rules/"
mkdir -p "$PACKAGE_DIR/.sisyphus/runtime/engine-outputs"/{suricata,wazuh,yara,rasp,status}

cat > "$PACKAGE_DIR/README.md" <<'EOF'
# 流影离线安装包

## 一键安装

```bash
sudo bash scripts/install-offline.sh
```

脚本会检查 Docker；如果未安装，会尝试通过系统包管理器安装 Docker 与 compose plugin，然后导入本包内镜像并启动流影。

默认访问地址：`https://<服务器IP>/`

默认账号：`admin / password`

首次登录会要求修改密码。
EOF
printf '%s\n' "$TARGET_ARCH" > "$PACKAGE_DIR/ARCH"

log "saving docker images"
docker save "${IMAGES[@]}" | gzip -c > "$IMAGE_ARCHIVE"

log "creating compressed installer archive"
tar -C "$RELEASE_DIR" -czf "$RELEASE_DIR/$PACKAGE_NAME.tar.gz" "$PACKAGE_NAME"

log "release package ready: $RELEASE_DIR/$PACKAGE_NAME.tar.gz"
