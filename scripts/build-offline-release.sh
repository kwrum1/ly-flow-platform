#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="$ROOT_DIR/release"
TARGET_ARCH="${TARGET_ARCH:-amd64}"
PLATFORM="linux/$TARGET_ARCH"
RELEASE_ID="${RELEASE_ID:-$(git -C "$ROOT_DIR" rev-parse --short=12 HEAD)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH
RELEASE_SIGNING_KEY="${RELEASE_SIGNING_KEY:-}"
[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { printf '[lyflow-release] ERROR: RELEASE_ID contains unsupported characters\n' >&2; exit 1; }
[[ -f "$RELEASE_SIGNING_KEY" ]] || { printf '[lyflow-release] ERROR: RELEASE_SIGNING_KEY must name an external Ed25519 private key\n' >&2; exit 1; }
signing_key_path=$(realpath -e "$RELEASE_SIGNING_KEY")
root_path=$(realpath -e "$ROOT_DIR")
if [[ "$signing_key_path" == "$root_path"/* ]]; then
  printf '[lyflow-release] ERROR: RELEASE_SIGNING_KEY must be stored outside the repository\n' >&2
  exit 1
fi
RELEASE_SIGNING_KEY=$signing_key_path
PACKAGE_NAME="lyflow-offline-install-${TARGET_ARCH}-${RELEASE_ID}"
PACKAGE_DIR="$RELEASE_DIR/$PACKAGE_NAME"
IMAGE_ARCHIVE="$PACKAGE_DIR/images/lyflow-images.tar.gz"
ARCHIVE="$RELEASE_DIR/$PACKAGE_NAME.tar.gz"
APP_TAG="release-${RELEASE_ID}-${TARGET_ARCH}"
TAG_SUFFIX=""
if [[ "$TARGET_ARCH" != "amd64" ]]; then
  TAG_SUFFIX="-$TARGET_ARCH"
fi

if [[ "$TARGET_ARCH" == "amd64" ]]; then
  DB_POSTGRES_IMAGE="${DB_POSTGRES_IMAGE:-postgres@sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50}"
  DB_REDIS_IMAGE="${DB_REDIS_IMAGE:-redis@sha256:9de71018be8413f419688ac34e19dbac432d1c6d9593d2ded99a82eebefeb18f}"
  DB_CLICKHOUSE_IMAGE="${DB_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5}"
else
  DB_POSTGRES_IMAGE="${DB_POSTGRES_IMAGE:-}"
  DB_REDIS_IMAGE="${DB_REDIS_IMAGE:-}"
  DB_CLICKHOUSE_IMAGE="${DB_CLICKHOUSE_IMAGE:-}"
fi
SERVER_BASE_IMAGE="${SERVER_BASE_IMAGE:-ly-flow/server@sha256:bdec70a7c0c9841f0404c1fb54967bc89660aed49d7e8cb2d1066fa35e9e061e}"
FRONTEND_BASE_IMAGE="${FRONTEND_BASE_IMAGE:-ly-flow/frontend@sha256:89d88f6ad4e2119d564394a413bf95e26e4ada5d3773169cbc5543f6daf52179}"
SURICATA_PROFILE_IMAGE="${SURICATA_PROFILE_IMAGE:-}"
SURICATA_BUILD_IMAGE="${SURICATA_BUILD_IMAGE:-ly-flow/suricata-profile:release-rc-652a7b620dfd-todo5-20260730T071221Z-amd64}"
: "${RASP_PYTHON_310_IMAGE:?RASP_PYTHON_310_IMAGE must be supplied as a local sha256 digest reference}"
: "${RASP_PYTHON_311_IMAGE:?RASP_PYTHON_311_IMAGE must be supplied as a local sha256 digest reference}"
: "${RASP_PYTHON_312_IMAGE:?RASP_PYTHON_312_IMAGE must be supplied as a local sha256 digest reference}"

validate_immutable_image_ref() {
  local name=$1 ref=$2
  [[ $ref =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
    printf '[lyflow-release] ERROR: %s must be an immutable repository@sha256:digest reference: %s\n' "$name" "$ref" >&2
    exit 1
  }
}

validate_immutable_image_ref RASP_PYTHON_310_IMAGE "$RASP_PYTHON_310_IMAGE"
validate_immutable_image_ref RASP_PYTHON_311_IMAGE "$RASP_PYTHON_311_IMAGE"
validate_immutable_image_ref RASP_PYTHON_312_IMAGE "$RASP_PYTHON_312_IMAGE"
if [[ "$TARGET_ARCH" != "amd64" && (-z "$DB_POSTGRES_IMAGE" || -z "$DB_REDIS_IMAGE" || -z "$DB_CLICKHOUSE_IMAGE") ]]; then
  printf '[lyflow-release] ERROR: non-amd64 releases require architecture-specific DB_POSTGRES_IMAGE, DB_REDIS_IMAGE, and DB_CLICKHOUSE_IMAGE digests\n' >&2
  exit 1
fi
for base in "$DB_POSTGRES_IMAGE" "$DB_REDIS_IMAGE" "$DB_CLICKHOUSE_IMAGE" "$SERVER_BASE_IMAGE" "$FRONTEND_BASE_IMAGE" "$SURICATA_PROFILE_IMAGE"; do
  [[ "$base" == *@sha256:* ]] || { printf '[lyflow-release] ERROR: every release base image must use a sha256 digest: %s\n' "$base" >&2; exit 1; }
done

log() { printf '[lyflow-release] %s\n' "$*"; }
run() { log "$*"; "$@"; }
run_in() { local dir="$1"; shift; log "cd $dir && $*"; (cd "$dir" && "$@"); }

ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "using local image $image"
    return
  fi
  printf '[lyflow-release] ERROR: required image %s is missing from the local cache; release builds never fetch mutable inputs\n' "$image" >&2
  exit 1
}

cd "$ROOT_DIR"

log "checking local RASP conformance images"
ensure_image "$RASP_PYTHON_310_IMAGE"
ensure_image "$RASP_PYTHON_311_IMAGE"
ensure_image "$RASP_PYTHON_312_IMAGE"

log "building static Go binaries"
run_in "$ROOT_DIR/server" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -o ly-server ./cmd
run_in "$ROOT_DIR/server" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -o ly-agent-center ./agentcenter
mkdir -p "$ROOT_DIR/server/dist/linux/$TARGET_ARCH"
cp "$ROOT_DIR/server/ly-server" "$ROOT_DIR/server/dist/linux/$TARGET_ARCH/ly-server"
cp "$ROOT_DIR/server/ly-agent-center" "$ROOT_DIR/server/dist/linux/$TARGET_ARCH/ly-agent-center"
mkdir -p "$ROOT_DIR/agent/dist/linux/amd64" "$ROOT_DIR/agent/dist/linux/arm64" "$ROOT_DIR/agent/dist/windows/amd64"
run_in "$ROOT_DIR/agent" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -o ly-agent ./cmd
cp "$ROOT_DIR/agent/ly-agent" "$ROOT_DIR/agent/ly-agent-linux-$TARGET_ARCH"
cp "$ROOT_DIR/agent/ly-agent" "$ROOT_DIR/agent/dist/linux/$TARGET_ARCH/ly-agent"
run env RELEASE_SIGNING_KEY="$RELEASE_SIGNING_KEY" "$ROOT_DIR/scripts/prepare-agent-release.sh"
run_in "$ROOT_DIR/agent" env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -ldflags=-H=windowsgui -o ly-agent-windows-amd64.exe ./cmd
cp "$ROOT_DIR/agent/ly-agent-windows-amd64.exe" "$ROOT_DIR/agent/dist/windows/amd64/ly-agent.exe"
run_in "$ROOT_DIR/dpi-engine" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -o ly-dpi-engine ./cmd
run_in "$ROOT_DIR/security-engine" env GOOS=linux GOARCH="$TARGET_ARCH" CGO_ENABLED=0 GOWORK=off go build -trimpath -buildvcs=false -o ly-security-engine ./cmd

log "building frontend"
run npm --prefix frontend run build

log "checking runtime and base images"
ensure_image "$DB_POSTGRES_IMAGE"
ensure_image "$DB_REDIS_IMAGE"
ensure_image "$DB_CLICKHOUSE_IMAGE"
ensure_image "$SERVER_BASE_IMAGE"
ensure_image "$FRONTEND_BASE_IMAGE"
ensure_image "$SURICATA_PROFILE_IMAGE"
ensure_image "$SURICATA_BUILD_IMAGE"
suricata_build_id=$(docker image inspect "$SURICATA_BUILD_IMAGE" --format '{{.Id}}')
[[ "$suricata_build_id" == "${SURICATA_PROFILE_IMAGE##*@}" ]] \
  || { printf '[lyflow-release] ERROR: local Suricata build alias does not match the pinned upstream digest\n' >&2; exit 1; }

build_alias() {
  local source=$1 alias=$2
  docker image tag "$source" "$alias"
  printf '%s\n' "$alias"
}
BUILD_SERVER_BASE=$(build_alias "$SERVER_BASE_IMAGE" "lyflow-release/server-base:$RELEASE_ID")
BUILD_FRONTEND_BASE=$(build_alias "$FRONTEND_BASE_IMAGE" "lyflow-release/frontend-base:$RELEASE_ID")
BUILD_REDIS_BASE=$(build_alias "$DB_REDIS_IMAGE" "lyflow-release/redis-base:$RELEASE_ID")
BUILD_SURICATA_BASE=$(build_alias "$SURICATA_BUILD_IMAGE" "lyflow-release/suricata-base:$RELEASE_ID")

log "rebuilding application images from pinned local bases without network access"
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "RUNTIME_IMAGE=$BUILD_SERVER_BASE" -f server/Dockerfile -t "ly-flow/server:$APP_TAG" .
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "RUNTIME_IMAGE=$BUILD_FRONTEND_BASE" -f frontend/Dockerfile -t "ly-flow/frontend:$APP_TAG" .
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "RUNTIME_IMAGE=$BUILD_REDIS_BASE" -f dpi-engine/Dockerfile -t "ly-flow/dpi-engine:$APP_TAG" .
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "RUNTIME_IMAGE=$BUILD_REDIS_BASE" -f security-engine/Dockerfile -t "ly-flow/security-engine:$APP_TAG" .
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "SURICATA_PROFILE_IMAGE=$BUILD_SURICATA_BASE" --target suricata-profile -f containers/security-engines/Dockerfile -t "ly-flow/suricata-profile:$APP_TAG" .
run docker buildx build --platform "$PLATFORM" --load --no-cache --network=none --provenance=false --build-arg "RUNTIME_IMAGE=$BUILD_SERVER_BASE" -f agent/Dockerfile -t "ly-flow/agent:$APP_TAG" .

image_digest_ref() {
  local image=$1 repository=$2 digest
  digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)
  if [[ -z "$digest" || "$digest" == '<no value>' ]]; then
    digest=$(docker image inspect "$image" --format '{{.Id}}')
    digest="$repository@${digest#sha256:}"
    digest="${digest/@/@sha256:}"
  fi
  printf '%s\n' "$digest"
}

SERVER_IMAGE=$(image_digest_ref "ly-flow/server:$APP_TAG" ly-flow/server)
FRONTEND_IMAGE=$(image_digest_ref "ly-flow/frontend:$APP_TAG" ly-flow/frontend)
SECURITY_ENGINE_IMAGE=$(image_digest_ref "ly-flow/security-engine:$APP_TAG" ly-flow/security-engine)
AGENT_IMAGE=$(image_digest_ref "ly-flow/agent:$APP_TAG" ly-flow/agent)
DPI_IMAGE=$(image_digest_ref "ly-flow/dpi-engine:$APP_TAG" ly-flow/dpi-engine)
SURICATA_SENSOR_IMAGE=$(image_digest_ref "ly-flow/suricata-profile:$APP_TAG" ly-flow/suricata-profile)
IMAGES=("$DB_POSTGRES_IMAGE" "$DB_REDIS_IMAGE" "$DB_CLICKHOUSE_IMAGE" "$SERVER_IMAGE" "$FRONTEND_IMAGE" "$SECURITY_ENGINE_IMAGE" "$AGENT_IMAGE" "$DPI_IMAGE" "$SURICATA_SENSOR_IMAGE")

rm -rf "$RELEASE_DIR/.task22-evidence-$RELEASE_ID"
TODO22_IMAGE_REFS=$(printf '%s\n' "${IMAGES[@]}" | paste -sd, -)
run env SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" TODO22_IMAGE_REFS="$TODO22_IMAGE_REFS" "$ROOT_DIR/scripts/qa/generate-release-evidence.sh" --output "$RELEASE_DIR/.task22-evidence-$RELEASE_ID"
run env \
  RASP_PYTHON_310_IMAGE="$RASP_PYTHON_310_IMAGE" \
  RASP_PYTHON_311_IMAGE="$RASP_PYTHON_311_IMAGE" \
  RASP_PYTHON_312_IMAGE="$RASP_PYTHON_312_IMAGE" \
  RASP_PILOT_IMAGE="$SERVER_IMAGE" "$ROOT_DIR/scripts/qa/run-rasp-conformance.sh"

log "creating package directory $PACKAGE_DIR"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/images" "$PACKAGE_DIR/scripts" "$PACKAGE_DIR/rules" "$PACKAGE_DIR/server/sql"

cat >"$PACKAGE_DIR/image-pins.tsv" <<EOF
postgres:16-alpine	$DB_POSTGRES_IMAGE
redis:7-alpine	$DB_REDIS_IMAGE
clickhouse/clickhouse-server:24.8-alpine	$DB_CLICKHOUSE_IMAGE
ly-flow/server:productfix-20260731	$SERVER_IMAGE
ly-flow/frontend:productfix-20260731	$FRONTEND_IMAGE
ly-flow/security-engine:healthstream2-20260731	$SECURITY_ENGINE_IMAGE
ly-flow/local-mirror:signed4	$AGENT_IMAGE
ly-flow/suricata-profile:release-rc-652a7b620dfd-todo5-20260730T071221Z-amd64	$SURICATA_SENSOR_IMAGE
EOF
run "$ROOT_DIR/scripts/release-provenance.sh" pin-compose --input docker-compose.yml --output "$PACKAGE_DIR/docker-compose.yml" --pins "$PACKAGE_DIR/image-pins.tsv"
cp scripts/install-offline.sh "$PACKAGE_DIR/scripts/install-offline.sh"
cp scripts/release-provenance.sh "$PACKAGE_DIR/scripts/release-provenance.sh"
chmod +x "$PACKAGE_DIR/scripts/install-offline.sh"
cp scripts/init-db.sql "$PACKAGE_DIR/scripts/init-db.sql"
cp server/sql/asset_tables.sql "$PACKAGE_DIR/server/sql/asset_tables.sql"
cp -a rules/. "$PACKAGE_DIR/rules/"
rm -f "$PACKAGE_DIR/rules/security-engine/.lifecycle.bootstrap.lock"
rm -rf "$PACKAGE_DIR/rules/security-engine/lifecycle"
mkdir -p "$PACKAGE_DIR/rules/security-engine/lifecycle"
find "$PACKAGE_DIR/rules/security-engine/lifecycle" -type d -exec chmod 0755 {} +
find "$PACKAGE_DIR/rules/security-engine/lifecycle" -type f -exec chmod 0644 {} +
cp -a "$RELEASE_DIR/.task22-evidence-$RELEASE_ID" "$PACKAGE_DIR/evidence"
cp scripts/qa/vulnerability-exceptions.json "$PACKAGE_DIR/evidence/vulnerability-exceptions.json"
run "$ROOT_DIR/scripts/release-provenance.sh" validate-exceptions --file "$PACKAGE_DIR/evidence/vulnerability-exceptions.json"
mkdir -p "$PACKAGE_DIR/.sisyphus/runtime/engine-outputs"/{suricata,wazuh,yara,rasp,status}

cat > "$PACKAGE_DIR/README.md" <<'EOF'
# 流影离线安装包

## 一键安装

本安装包仅用于全新安装。安装目标目录必须不存在或为空目录。
不支持覆盖现有安装或升级；升级迁移不在本版本范围内。

```bash
sudo bash scripts/install-offline.sh \
  --trust-root /path/outside/package/release-root.pem \
  --generate-admin-password
```

脚本会检查 Docker；如果未安装，会尝试通过系统包管理器安装 Docker 与 compose plugin，然后导入本包内镜像并启动流影。

默认访问地址：`https://<服务器IP>/`

管理员账号为 `admin`。安装器会生成随机初始密码并写入权限为 `0600` 的
`initial-admin-credentials`。

首次登录会要求修改密码。
EOF
printf '%s\n' "$TARGET_ARCH" > "$PACKAGE_DIR/ARCH"

log "saving docker images"
docker save "${IMAGES[@]}" | gzip -n -9 > "$IMAGE_ARCHIVE"

log "signing package manifests"
run "$ROOT_DIR/scripts/release-provenance.sh" sign --package "$PACKAGE_DIR" --key "$RELEASE_SIGNING_KEY"

log "creating deterministic compressed installer archive"
run "$ROOT_DIR/scripts/release-provenance.sh" archive --package "$PACKAGE_DIR" --output "$ARCHIVE" --epoch "$SOURCE_DATE_EPOCH"
(cd "$RELEASE_DIR" && sha256sum "$(basename "$ARCHIVE")" >"$(basename "$ARCHIVE").sha256")
openssl pkeyutl -sign -inkey "$RELEASE_SIGNING_KEY" -rawin -in "$ARCHIVE.sha256" -out "$ARCHIVE.sha256.sig"

log "release package ready: $ARCHIVE"
