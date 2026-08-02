#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out="${1:-$root/release}"
arch="${LYFLOW_TARGET_ARCH:?LYFLOW_TARGET_ARCH must be amd64 or arm64}"
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported target architecture: $arch" >&2; exit 1 ;;
esac

bundle="$out/lyflow-server-${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/ly-flow-platform/images" "$out"

images=(
  "ly-flow/vendor/postgres:16-alpine-${arch}"
  "ly-flow/vendor/redis:7-alpine-${arch}"
  "ly-flow/vendor/clickhouse:24.8-alpine-${arch}"
  "ly-flow/server:release-${arch}"
  "ly-flow/security-engine:release-${arch}"
  "ly-flow/frontend:release-${arch}"
  "ly-flow/local-mirror:release-${arch}"
  "ly-flow/suricata-profile:release-${arch}"
)
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || { echo "missing local image: $image" >&2; exit 1; }
  actual=$(docker image inspect --format '{{.Architecture}}' "$image")
  [ "$actual" = "$arch" ] || { echo "$image has architecture $actual, expected $arch" >&2; exit 1; }
done

cp docker-compose.yml scripts/init-db.sql "$tmp/ly-flow-platform/"
cp -a rules "$tmp/ly-flow-platform/rules"
if [ -d .sisyphus ]; then
  cp -a .sisyphus "$tmp/ly-flow-platform/.sisyphus"
  # Runtime selections belong to the host and must not leak from the build machine.
  rm -f "$tmp/ly-flow-platform/.sisyphus/runtime/mirror-capture-config.json"
fi
mkdir -p "$tmp/ly-flow-platform/server/sql" "$tmp/ly-flow-platform/scripts"
cp server/sql/asset_tables.sql "$tmp/ly-flow-platform/server/sql/"
cp scripts/install-docker-bundle.sh "$tmp/ly-flow-platform/scripts/"
chmod +x "$tmp/ly-flow-platform/scripts/install-docker-bundle.sh"
printf '%s\n' "$arch" > "$tmp/ly-flow-platform/images/architecture"
printf '%s\n' "${images[@]}" > "$tmp/ly-flow-platform/images/image-pins.txt"
docker save "${images[@]}" | gzip -n -6 > "$tmp/ly-flow-platform/images/lyflow-images.tar.gz"

cat > "$tmp/ly-flow-platform/README.md" <<EOF
# 流影 LyFlow 服务端安装包（${arch}）

在已安装 Docker Engine 与 Compose Plugin 的同架构 Linux 服务器上，以 root 执行：

    bash scripts/install-docker-bundle.sh

安装器会校验主机架构、导入镜像、生成本机 .env 并启动正式 Compose 栈。
安装完成后访问 https://<服务器IP>/，首次登录账号为 admin，密码为 password，系统强制改密。
EOF

tar -C "$tmp" -czf "$bundle" ly-flow-platform
echo "$bundle"
