#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out="${1:-$root/release}"
tag="${GITHUB_SHA:-local}"
bundle="$out/lyflow-docker-bundle-${tag}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/ly-flow-platform/images" "$out"
images=(
  postgres:16-alpine
  redis:7-alpine
  clickhouse/clickhouse-server:24.8-alpine
  ly-flow/server:bugfix-20260801-v3
  ly-flow/security-engine:release-138986fe8514d6eb0eb4a7ea037bf7f8dd9a7644-amd64
  ly-flow/frontend:bugfix-20260801
  ly-flow/local-mirror:signed4
  ly-flow/suricata-profile:release-rc-652a7b620dfd-todo5-20260730T071221Z-amd64
)
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || { echo "missing local image: $image" >&2; exit 1; }
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
printf '%s
' "${images[@]}" > "$tmp/ly-flow-platform/images/image-pins.txt"
docker save "${images[@]}" | gzip -n -9 > "$tmp/ly-flow-platform/images/lyflow-images.tar.gz"
cat > "$tmp/ly-flow-platform/README.md" <<'EOF'
# LyFlow Docker deployment bundle

Run as root:
  bash scripts/install-docker-bundle.sh

The installer imports the bundled images, creates a local .env, and starts the
production compose stack. Set LOCAL_MIRROR_INTERFACE before running when the
mirror port is different from the management interface.
EOF
tar -C "$tmp" -czf "$bundle" ly-flow-platform
sha256sum "$bundle" > "$bundle.sha256"
echo "$bundle"
