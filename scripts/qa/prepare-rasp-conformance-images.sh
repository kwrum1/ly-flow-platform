#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
repository=lyflow/rasp-conformance
BUILD_JOBS=

log() { printf '[rasp-images] %s\n' "$*" >&2; }

validate_build_jobs() {
  BUILD_JOBS=${RASP_BUILD_JOBS:-2}
  [[ $BUILD_JOBS =~ ^[1-4]$ ]] || {
    printf '[rasp-images] ERROR: RASP_BUILD_JOBS must be an integer from 1 to 4: %s\n' "$BUILD_JOBS" >&2
    return 1
  }
}

image_digest_ref() {
  local tag=$1 digest image_id
  digest=$(docker image inspect "$tag" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)
  if [[ -z $digest || $digest == '<no value>' ]]; then
    image_id=$(docker image inspect "$tag" --format '{{.Id}}')
    [[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || {
      printf '[rasp-images] ERROR: image ID is not a sha256 digest for %s: %s\n' "$tag" "$image_id" >&2
      return 1
    }
    digest="$repository@$image_id"
  fi
  [[ $digest =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
    printf '[rasp-images] ERROR: Docker returned a non-immutable reference for %s: %s\n' "$tag" "$digest" >&2
    return 1
  }
  printf '%s\n' "$digest"
}

prepare_image() {
  local tag=$1 dockerfile digest
  dockerfile=$2
  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    log "building $tag from $(basename "$dockerfile")"
    docker buildx build \
      --platform linux/amd64 \
      --load \
      --pull=false \
      --no-cache \
      --provenance=false \
      --build-arg "BUILD_JOBS=$BUILD_JOBS" \
      -f "$dockerfile" \
      -t "$tag" \
      "$root" >&2
  else
    log "using existing local tag $tag"
  fi

  digest=$(image_digest_ref "$tag")
  docker image inspect "$digest" >/dev/null 2>&1 || {
    printf '[rasp-images] ERROR: emitted reference is not locally inspectable: %s\n' "$digest" >&2
    return 1
  }
  printf '%s\n' "$digest"
}

validate_build_jobs

prepare_image \
  "$repository:cpython3.10-ubuntu22.04" \
  "$root/scripts/qa/rasp-conformance-images/cpython3.10-ubuntu22.04.Dockerfile"
prepare_image \
  "$repository:cpython3.11-ubuntu22.04" \
  "$root/scripts/qa/rasp-conformance-images/cpython3.11-ubuntu22.04.Dockerfile"
prepare_image \
  "$repository:cpython3.12-ubuntu24.04" \
  "$root/scripts/qa/rasp-conformance-images/cpython3.12-ubuntu24.04.Dockerfile"
