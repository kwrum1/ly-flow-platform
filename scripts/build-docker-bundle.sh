#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out="${1:-$root/release}"
tag="${GITHUB_SHA:-local}"
arch="${LYFLOW_TARGET_ARCH:?LYFLOW_TARGET_ARCH must be amd64 or arm64}"
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported target architecture: $arch" >&2; exit 1 ;;
esac

bundle="$out/lyflow-docker-bundle-${tag}-${arch}.tar.gz"
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
fi
mkdir -p "$tmp/ly-flow-platform/server/sql" "$tmp/ly-flow-platform/scripts"
cp server/sql/asset_tables.sql "$tmp/ly-flow-platform/server/sql/"
cp scripts/install-docker-bundle.sh "$tmp/ly-flow-platform/scripts/"
chmod +x "$tmp/ly-flow-platform/scripts/install-docker-bundle.sh"
printf '%s\n' "$arch" > "$tmp/ly-flow-platform/images/architecture"
printf '%s\n' "${images[@]}" > "$tmp/ly-flow-platform/images/image-pins.txt"
docker save "${images[@]}" | gzip -n -6 > "$tmp/ly-flow-platform/images/lyflow-images.tar.gz"

cat > "$tmp/ly-flow-platform/README.md" <<EOF
# LyFlow Docker deployment bundle (${arch})

Run as root:

    bash scripts/install-docker-bundle.sh

The installer verifies the host architecture, imports the bundled images,
creates a local .env, and starts the production compose stack.
EOF

tar -C "$tmp" -czf "$bundle" ly-flow-platform
sha256sum "$bundle" > "$bundle.sha256"
echo "$bundle"
