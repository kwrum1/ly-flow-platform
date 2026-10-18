#!/usr/bin/env bash
# Fail if tracked files contain known credentials or private keys.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# Build the password prefix dynamically so this script does not match itself.
PASSWORD_PREFIX="Iam""yours"
PATTERN="(${PASSWORD_PREFIX}\.\.123|BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) PRIVATE KEY)"

if git grep -nI -E "$PATTERN" -- . \
  ':!docs/dev/DEVELOPMENT_GUIDE.md' \
  ':!docs/dev/ENVIRONMENT.md' \
  ':!scripts/dev/check-secrets.sh' \
  ':!rules/yara/**' >/tmp/lyflow-secret-matches.txt 2>/dev/null; then
  echo "ERROR: tracked secret-like content found:" >&2
  cat /tmp/lyflow-secret-matches.txt >&2
  exit 1
fi

if git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vE '\.example$' >/tmp/lyflow-env-files.txt; then
  echo "ERROR: tracked .env file(s) must not be committed:" >&2
  cat /tmp/lyflow-env-files.txt >&2
  exit 1
fi

echo "ok: no tracked credentials/private keys"
