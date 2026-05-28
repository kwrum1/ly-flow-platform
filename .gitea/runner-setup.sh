#!/usr/bin/env bash
set -euo pipefail

GITEA_URL="${GITEA_URL:-http://127.0.0.1:10000}"
REPO="${REPO:-ly-flow-platform/ly-flow-platform}"
RUNNER_DIR="${RUNNER_DIR:-/opt/gitea-runner}"
RUNNER_NAME="${RUNNER_NAME:-docker-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-docker}"
ACT_RUNNER_VERSION="${ACT_RUNNER_VERSION:-v0.2.5}"
ACT_RUNNER_ARCH="${ACT_RUNNER_ARCH:-amd64}"

if [[ -z "${GITEA_TOKEN:-}" ]]; then
  printf 'Error: GITEA_TOKEN is required. Export the existing Gitea token before running this script.\n' >&2
  exit 1
fi

printf '=== Gitea Actions Runner Setup ===\n'
printf 'URL: %s\n' "$GITEA_URL"
printf 'Repo: %s\n' "$REPO"
printf 'Runner: %s\n' "$RUNNER_NAME"
printf 'Labels: %s\n' "$RUNNER_LABELS"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

printf 'Downloading act_runner...\n'
ACT_RUNNER_URL="https://gitea.com/gitea/act_runner/releases/download/${ACT_RUNNER_VERSION}/act_runner-linux-${ACT_RUNNER_ARCH}"
if command -v wget >/dev/null 2>&1; then
  wget -O act_runner "$ACT_RUNNER_URL"
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL -o act_runner "$ACT_RUNNER_URL"
else
  printf 'Error: wget or curl required\n' >&2
  exit 1
fi

chmod +x act_runner

printf 'Getting registration token...\n'
response=$(curl -fsS \
  -H "Authorization: token ${GITEA_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "{\"name\":\"${RUNNER_NAME}\",\"labels\":[\"${RUNNER_LABELS}\"]}" \
  "${GITEA_URL}/api/v1/repos/${REPO}/actions/runners/registration-tokens")

token_value=$(printf '%s' "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [[ -z "$token_value" ]]; then
  printf 'Error: could not get registration token.\n' >&2
  exit 1
fi

printf 'Registering runner...\n'
./act_runner register \
  --instance "$GITEA_URL" \
  --repo "$REPO" \
  --token "$token_value" \
  --runner-name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS" \
  --no-interactive

printf '=== Setup Complete ===\n'
printf 'Run the following to start the runner:\n'
printf '  cd %s && ./act_runner daemon\n' "$RUNNER_DIR"
