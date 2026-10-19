#!/usr/bin/env bash
# Build upstream ly_probe in an Ubuntu 24.04 container and publish a runnable
# sensor bundle (binary + liblyprobe) to the artifacts directory.
#
# This intentionally does not install build dependencies on the host and does
# not touch the LyFlow source tree. It is safe to run on a shared build host:
# the container is CPU/IO-throttled and removed afterwards.
set -euo pipefail

IMAGE="${LYPROBE_BUILD_IMAGE:-ubuntu:24.04}"
GIT_URL="${LYPROBE_GIT_URL:-https://github.com/Abyssal-Fish-Technology/ly_probe.git}"
GIT_REF="${LYPROBE_GIT_REF:-}"
OUT="${LYPROBE_OUTPUT_DIR:-/opt/lyflow/artifacts/lyprobe}"
WORK="${LYPROBE_WORKDIR:-/opt/lyflow/build/lyprobe-build}"
JOBS="${LYPROBE_JOBS:-2}"
CPUS="${LYPROBE_CPUS:-1.5}"
MEMORY="${LYPROBE_MEMORY:-2g}"
KEEP_SOURCE="${LYPROBE_KEEP_SOURCE:-0}"

command -v docker >/dev/null 2>&1 || {
  echo "lyprobe-build: docker is required" >&2
  exit 1
}

rm -rf "$WORK"
mkdir -p "$WORK/src" "$OUT"
rm -f "$OUT/lyprobe" "$OUT/liblyprobe-1.0.0.so" "$OUT/SHA256SUMS" "$OUT/BUILD-INFO" "$OUT/lyprobe-help.txt"
trap 'if [ "$KEEP_SOURCE" != "1" ]; then rm -rf "$WORK"; fi' EXIT

echo "lyprobe-build: cloning $GIT_URL"
if [ -n "$GIT_REF" ]; then
  git clone --depth 1 --branch "$GIT_REF" "$GIT_URL" "$WORK/src"
else
  git clone --depth 1 "$GIT_URL" "$WORK/src"
fi
REVISION=$(git -C "$WORK/src" rev-parse HEAD)

cat >"$WORK/build.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential autoconf automake libtool libtool-bin \
  pkg-config libpcap-dev patchelf >/dev/null
cd /src
if [ ! -x ./configure ]; then
  bash ./autogen.sh
fi
# Upstream predates modern autotools and has no config.h.in rule that
# autoheader can regenerate cleanly. Keep generated files fresh so make does
# not rerun autoheader mid-build.
touch aclocal.m4 configure config.h.in Makefile.in Makefile 2>/dev/null || true
# Build only the sensor. plugins/ has macOS-only link flags (-bundle,
# -flat_namespace) and is not needed for the base capture path.
make -j"${BUILD_JOBS:-2}" -o config.h.in -o Makefile.in -o aclocal.m4 \
  -o configure -o Makefile lyprobe
BIN=.libs/lyprobe
LIB=.libs/liblyprobe-1.0.0.so
if [ ! -x "$BIN" ] || [ ! -f "$LIB" ]; then
  echo "lyprobe-build: missing build artifacts" >&2
  exit 1
fi
install -m 0755 "$BIN" /out/lyprobe
install -m 0644 "$LIB" /out/liblyprobe-1.0.0.so
patchelf --set-rpath '$ORIGIN' /out/lyprobe
LD_LIBRARY_PATH=/out ldd /out/lyprobe | grep -q liblyprobe
LD_LIBRARY_PATH=/out /out/lyprobe -h >/out/lyprobe-help.txt 2>&1 || true
INNER

echo "lyprobe-build: building in $IMAGE (cpus=$CPUS jobs=$JOBS)"
docker run --rm --network host --cpus="$CPUS" --memory="$MEMORY" \
  --cpu-shares=128 --blkio-weight=100 -e BUILD_JOBS="$JOBS" \
  -v "$WORK/src:/src" -v "$OUT:/out" -v "$WORK/build.sh:/tmp/build.sh:ro" \
  "$IMAGE" bash /tmp/build.sh

cd "$OUT"
sha256sum lyprobe liblyprobe-1.0.0.so >SHA256SUMS
{
  echo "name=ly_probe"
  echo "source=$GIT_URL"
  echo "revision=$REVISION"
  echo "image=$IMAGE"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "jobs=$JOBS"
  echo "cpus=$CPUS"
} >BUILD-INFO
ls -lh lyprobe liblyprobe-1.0.0.so SHA256SUMS BUILD-INFO lyprobe-help.txt
echo "lyprobe-build: published $OUT"
