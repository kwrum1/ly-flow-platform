#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool="$root/scripts/release-provenance.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

package="$tmp/package"
mkdir -p "$package/images" "$package/rules" "$package/scripts"
printf 'fixture payload\n' >"$package/payload.txt"
printf 'fixture rules\n' >"$package/rules/active.json"
cp "$root/scripts/install-offline.sh" "$package/scripts/install-offline.sh"

openssl genpkey -algorithm ED25519 -out "$tmp/release-signer.key" >/dev/null 2>&1
openssl pkey -in "$tmp/release-signer.key" -pubout -out "$tmp/release-root.pem" >/dev/null 2>&1

bash "$tool" sign --package "$package" --key "$tmp/release-signer.key"
bash "$tool" verify --package "$package" --root "$tmp/release-root.pem"

bash "$tool" archive --package "$package" --output "$tmp/one.tar.gz" --epoch 0
bash "$tool" archive --package "$package" --output "$tmp/two.tar.gz" --epoch 0
cmp "$tmp/one.tar.gz" "$tmp/two.tar.gz"

cat >"$tmp/valid-exceptions.json" <<'EOF'
{
  "schema_version": 1,
  "generated_at": "2026-07-14T00:00:00Z",
  "exceptions": [{
    "id": "CVE-2099-0001",
    "component": "fixture@1.0.0",
    "severity": "high",
    "owner": "security-owner",
    "reachability": "Not reachable from the packaged runtime entrypoint; fixture evidence QA-22.",
    "compensating_control": "The affected optional parser is excluded from the release payload.",
    "expires_at": "2026-08-13T00:00:00Z",
    "scanner": {"name": "fixture-scanner", "version": "1.0.0", "database_version": "fixture-db-1"}
  }]
}
EOF
bash "$tool" validate-exceptions --file "$tmp/valid-exceptions.json"
jq '.exceptions[0].owner = ""' "$tmp/valid-exceptions.json" >"$tmp/invalid-exceptions.json"
if bash "$tool" validate-exceptions --file "$tmp/invalid-exceptions.json" >/dev/null 2>&1; then
  printf 'exception without owner was accepted\n' >&2
  exit 1
fi
jq '.exceptions[0].expires_at = "2026-08-14T00:00:00Z"' "$tmp/valid-exceptions.json" >"$tmp/expired-exceptions.json"
if bash "$tool" validate-exceptions --file "$tmp/expired-exceptions.json" >/dev/null 2>&1; then
  printf 'exception exceeding 30 days was accepted\n' >&2
  exit 1
fi

cat >"$tmp/compose.yml" <<'EOF'
services:
  app:
    image: ly-flow/server:latest
EOF
printf 'ly-flow/server:latest\tly-flow/server@sha256:%064d\n' 1 >"$tmp/pins.tsv"
bash "$tool" pin-compose --input "$tmp/compose.yml" --output "$tmp/compose.pinned.yml" --pins "$tmp/pins.tsv"
grep -Fq 'ly-flow/server@sha256:' "$tmp/compose.pinned.yml"
if grep -Fq ':latest' "$tmp/compose.pinned.yml"; then
  printf 'mutable latest survived Compose staging\n' >&2
  exit 1
fi

printf X >>"$package/payload.txt"
if bash "$tool" verify --package "$package" --root "$tmp/release-root.pem" >/dev/null 2>&1; then
  printf 'one-byte mutation was accepted\n' >&2
  exit 1
fi

marker="$tmp/side-effect"
set +e
bash -c '
  set -euo pipefail
  source "$1"
  install_release_root() { TRUST_ROOT=$4; }
  require_root() { :; }
  install_docker() { printf install >"$5"; }
  ensure_docker_running() { printf docker >"$5"; }
  copy_payload() { printf extract >"$5"; }
  write_env() { printf env >"$5"; }
  load_images() { printf images >"$5"; }
  start_stack() { printf start >"$5"; }
  SCRIPT_DIR=$2/scripts
  PACKAGE_ROOT=$2
  IMAGE_ARCHIVE=$2/images/lyflow-images.tar.gz
  main --trust-root "$4"
' _ "$package/scripts/install-offline.sh" "$package" unused "$tmp/release-root.pem" "$marker" >/dev/null 2>&1
status=$?
set -e
if [[ $status -eq 0 || -e "$marker" ]]; then
  printf 'mutated installer reached an extraction/start side effect\n' >&2
  exit 1
fi

printf 'release provenance harness self-test passed\n'
