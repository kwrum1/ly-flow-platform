#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
helper="$root/scripts/qa/prepare-rasp-conformance-images.sh"
dockerfile="$root/scripts/qa/rasp-conformance-images/cpython3.11-ubuntu22.04.Dockerfile"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

require_pattern() {
  local mode=$1 pattern=$2 file=$3
  if ! grep "$mode" -q -- "$pattern" "$file"; then
    printf 'missing expected pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

if grep -Fq 'make -j"$(nproc)"' "$dockerfile"; then
  printf 'unbounded nproc build parallelism remains in %s\n' "$dockerfile" >&2
  exit 1
fi
require_pattern -F 'ARG BUILD_JOBS=2' "$dockerfile"
require_pattern -F 'make -j"$BUILD_JOBS"' "$dockerfile"
require_pattern -F 'RASP_BUILD_JOBS' "$helper"
require_pattern -F 'BUILD_JOBS' "$helper"

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail

state=${FAKE_DOCKER_STATE:?}
log=${FAKE_DOCKER_LOG:?}
printf '%q ' "$@" >>"$log"
printf '\n' >>"$log"

if [[ ${1:-} == image && ${2:-} == inspect ]]; then
  image=${3:?}
  if [[ $image == *@sha256:* ]]; then
    exit 0
  fi
  if ! grep -Fqx "tag:$image" "$state" 2>/dev/null; then
    exit 1
  fi
  if [[ ${4:-} == --format ]]; then
    if [[ ${5:-} == '{{.Id}}' ]]; then
      printf '%s\n' 'sha256:2222222222222222222222222222222222222222222222222222222222222222'
    else
      case $image in
        *cpython3.10*) printf '%s\n' 'lyflow/rasp-conformance@sha256:1111111111111111111111111111111111111111111111111111111111111111' ;;
        *cpython3.11*) printf '%s\n' '<no value>' ;;
        *cpython3.12*) printf '%s\n' 'lyflow/rasp-conformance@sha256:3333333333333333333333333333333333333333333333333333333333333333' ;;
        *) printf '%s\n' 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
      esac
    fi
  fi
  exit 0
fi

if [[ ${1:-} == buildx && ${2:-} == build ]]; then
  tag=
  previous=
  for argument in "$@"; do
    if [[ $previous == -t ]]; then
      tag=$argument
    fi
    previous=$argument
  done
  [[ -n $tag ]] || { printf 'fake Docker build omitted -t\n' >&2; exit 1; }
  printf 'tag:%s\n' "$tag" >>"$state"
  exit 0
fi

printf 'unexpected fake Docker command: %s\n' "$*" >&2
exit 1
FAKE_DOCKER
chmod +x "$tmp/bin/docker"

export PATH="$tmp/bin:$PATH"
export FAKE_DOCKER_STATE="$tmp/state"
export FAKE_DOCKER_LOG="$tmp/docker.log"
: >"$FAKE_DOCKER_STATE"
: >"$FAKE_DOCKER_LOG"

if bash "$helper" >"$tmp/refs" 2>"$tmp/log"; then
  :
else
  printf 'RASP image preparation failed unexpectedly\n' >&2
  cat "$tmp/log" >&2
  exit 1
fi

expected="$tmp/expected"
cat >"$expected" <<'EOF'
lyflow/rasp-conformance@sha256:1111111111111111111111111111111111111111111111111111111111111111
lyflow/rasp-conformance@sha256:2222222222222222222222222222222222222222222222222222222222222222
lyflow/rasp-conformance@sha256:3333333333333333333333333333333333333333333333333333333333333333
EOF

if ! cmp -s "$expected" "$tmp/refs"; then
  printf 'unexpected ordered immutable refs\n' >&2
  diff -u "$expected" "$tmp/refs" >&2 || true
  exit 1
fi
[[ $(wc -l <"$tmp/refs") -eq 3 ]]
[[ $(grep -c '^buildx build ' "$FAKE_DOCKER_LOG") -eq 3 ]]
grep -Fq -- '--platform linux/amd64 --load --pull=false --no-cache --provenance=false' "$FAKE_DOCKER_LOG"
[[ $(grep -c -- '--build-arg BUILD_JOBS=2' "$FAKE_DOCKER_LOG") -eq 3 ]]
for dockerfile in cpython3.10-ubuntu22.04.Dockerfile cpython3.11-ubuntu22.04.Dockerfile cpython3.12-ubuntu24.04.Dockerfile; do
  grep -Fq -- "$dockerfile" "$FAKE_DOCKER_LOG"
done

bash "$helper" >"$tmp/refs-second" 2>"$tmp/log-second"
[[ $(grep -c '^buildx build ' "$FAKE_DOCKER_LOG") -eq 3 ]]

: >"$FAKE_DOCKER_LOG"
: >"$FAKE_DOCKER_STATE"
RASP_BUILD_JOBS=1 bash "$helper" >"$tmp/refs-one" 2>"$tmp/log-one"
[[ $(grep -c '^buildx build ' "$FAKE_DOCKER_LOG") -eq 3 ]]
[[ $(grep -c -- '--build-arg BUILD_JOBS=1' "$FAKE_DOCKER_LOG") -eq 3 ]]

for invalid_jobs in 0 5 nope; do
  : >"$FAKE_DOCKER_LOG"
  : >"$FAKE_DOCKER_STATE"
  if RASP_BUILD_JOBS=$invalid_jobs bash "$helper" >"$tmp/refs-invalid-$invalid_jobs" 2>"$tmp/log-invalid-$invalid_jobs"; then
    printf 'invalid RASP_BUILD_JOBS=%s unexpectedly passed\n' "$invalid_jobs" >&2
    exit 1
  fi
  [[ ! -s "$FAKE_DOCKER_LOG" ]]
done

printf 'RASP conformance image preparation self-test passed\n'
