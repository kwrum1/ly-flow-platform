#!/usr/bin/env bash
# Try Docker Hub mirrors in order. Use for images that the local daemon cannot
# pull directly. The release path should still use a verified offline bundle.
set -euo pipefail

image="${1:?usage: pull-image.sh <namespace/image:tag>}"
mirrors=(
  "${DOCKER_MIRROR:-}"
  "${ALIYUN_MIRROR:-}"
  "docker.1ms.run"
  "docker.m.daocloud.io"
  "docker.1panel.live"
  "docker.xuanyuan.me"
  "docker.1panel.top"
  "dockerpull.org"
  "registry.dockermirror.com"
)
for mirror in "${mirrors[@]}"; do
  [ -n "$mirror" ] || continue
  candidate="${mirror%/}/${image}"
  echo "trying $candidate"
  if timeout "${DOCKER_PULL_TIMEOUT:-300}" docker pull "$candidate"; then
    echo "pulled $candidate"
    exit 0
  fi
done
echo "all mirrors failed for $image; provide an offline image tar or ALIYUN_MIRROR" >&2
exit 1
