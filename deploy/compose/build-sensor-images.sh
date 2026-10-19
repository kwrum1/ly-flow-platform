#!/usr/bin/env bash
# Build the host sensor images from LyFlow build artifacts.
# Server/frontend/security-engine images are produced by the existing LyFlow
# image pipeline; this script covers the capture-plane additions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ART="${LYFLOW_ARTIFACTS:-/opt/lyflow/artifacts}"
CONTEXT="$ROOT/deploy/build-context"

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
for file in \
  "$ART/lyprobe/lyprobe" \
  "$ART/lyprobe/liblyprobe-1.0.0.so" \
  "$ART/lyprobe/plugins/servicePlugin.so" \
  "$ART/capturedoctor/lyflow-capturedoctor" \
  "$ART/rulecompiler/lyflow-rulecompiler"; do
  [ -f "$file" ] || { echo "missing build artifact: $file" >&2; exit 1; }
done

rm -rf "$CONTEXT"
mkdir -p "$CONTEXT"
cp "$ART/lyprobe/lyprobe" "$CONTEXT/lyprobe"
cp "$ART/lyprobe/liblyprobe-1.0.0.so" "$CONTEXT/liblyprobe-1.0.0.so"
cp "$ART/lyprobe/plugins/servicePlugin.so" "$CONTEXT/servicePlugin.so"
cp "$ART/capturedoctor/lyflow-capturedoctor" "$CONTEXT/lyflow-capturedoctor"
cp "$ART/rulecompiler/lyflow-rulecompiler" "$CONTEXT/lyflow-rulecompiler"

docker build --network host -f "$ROOT/deploy/docker/lyprobe.Dockerfile" \
  -t "${LYPROBE_IMAGE:-ly-flow/lyprobe:latest}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/capturedoctor.Dockerfile" \
  -t "${LYFLOW_CAPTUREDOCTOR_IMAGE:-ly-flow/capturedoctor:latest}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/rulecompiler.Dockerfile" \
  -t "${LYFLOW_RULECOMPILER_IMAGE:-ly-flow/rulecompiler:latest}" "$ROOT"

if [ "${LYFLOW_BUILD_SURICATA:-0}" = "1" ]; then
  docker build --network host -f "$ROOT/deploy/docker/suricata.Dockerfile" \
    -t "${LY_SURICATA_IMAGE:-ly-flow/suricata:latest}" "$ROOT"
fi

echo "sensor images:"
docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | \
  grep -E 'ly-flow/(lyprobe|capturedoctor|rulecompiler|suricata):' || true
