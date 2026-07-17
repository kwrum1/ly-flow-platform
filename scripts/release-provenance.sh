#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '[release-provenance] ERROR: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "required file missing: $1"
}

require_dir() {
  [[ -d "$1" ]] || fail "required directory missing: $1"
}

manifest_files() {
  local root=$1 manifest=$2
  (
    cd "$root"
    while IFS= read -r -d '' path; do
      sha256sum "${path#./}"
    done < <(find . -type f ! -name "$manifest" ! -name "$manifest.sig" -print0 | sort -z)
  )
}

validate_manifest_paths() {
  local root=$1 manifest=$2
  local digest path
  while read -r digest path; do
    path=${path#\*}
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid digest in $manifest"
    [[ -n "$path" && "$path" != /* && "$path" != ../* && "$path" != */../* ]] || fail "unsafe path in $manifest"
    [[ -f "$root/$path" && ! -L "$root/$path" ]] || fail "manifest target is not a regular file: $path"
  done <"$root/$manifest"
}

sign_manifest() {
  local root=$1 manifest=$2 key=$3
  manifest_files "$root" "$manifest" >"$root/$manifest"
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$root/$manifest" -out "$root/$manifest.sig"
}

sign_artifact() {
  local artifact=$1 output=$2 key=$3
  require_file "$artifact"
  require_file "$key"
  command -v openssl >/dev/null 2>&1 || fail 'openssl is required'
  openssl pkey -in "$key" -text -noout 2>/dev/null | grep -Fq 'ED25519' || fail 'artifact signing key must be Ed25519'
  local name digest work public_der fingerprint payload signature
  name=$(basename "$artifact")
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || fail 'artifact basename contains unsupported characters'
  digest=$(sha256sum "$artifact")
  digest=${digest%% *}
  work=$(mktemp -d)
  openssl pkey -in "$key" -pubout -outform DER -out "$work/public.der"
  public_der=$(wc -c <"$work/public.der")
  [[ $public_der -eq 44 ]] || { rm -rf "$work"; fail 'unexpected Ed25519 public key encoding'; }
  fingerprint=$(tail -c 32 "$work/public.der" | sha256sum)
  fingerprint=${fingerprint%% *}
  payload=$(jq -cn --arg artifact "$name" --arg digest "$digest" --arg fingerprint "$fingerprint" \
    '{schema_version:"lyflow.signed_digest.v1",artifact:$artifact,digest:$digest,signer_fingerprint:$fingerprint}')
  printf '%s' "$payload" >"$work/payload.json"
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$work/payload.json" -out "$work/signature.bin"
  signature=$(od -An -vtx1 "$work/signature.bin" | tr -d ' \n')
  mkdir -p "$(dirname "$output")"
  printf '{"payload":%s,"signature":"%s"}\n' "$payload" "$signature" >"$output"
  chmod 0644 "$output"
  rm -rf "$work"
}

verify_manifest() {
  local root=$1 manifest=$2 public_root=$3
  require_file "$root/$manifest"
  require_file "$root/$manifest.sig"
  validate_manifest_paths "$root" "$manifest"
  openssl pkeyutl -verify -pubin -inkey "$public_root" -rawin -in "$root/$manifest" -sigfile "$root/$manifest.sig" >/dev/null 2>&1 || fail "signature rejected: $manifest"
  (cd "$root" && sha256sum --check --strict "$manifest" >/dev/null) || fail "checksum rejected: $manifest"
}

sign_package() {
  local package=$1 key=$2
  require_dir "$package"
  require_dir "$package/rules"
  require_file "$key"
  command -v openssl >/dev/null 2>&1 || fail 'openssl is required'
  openssl pkey -in "$key" -text -noout 2>/dev/null | grep -Fq 'ED25519' || fail 'release signing key must be Ed25519'
  if find "$package" -type l -print -quit | grep -q .; then
    fail 'release packages may not contain symbolic links'
  fi
  sign_manifest "$package/rules" rules-manifest.sha256 "$key"
  sign_manifest "$package" release-manifest.sha256 "$key"
}

verify_package() {
  local package=$1 public_root=$2
  require_dir "$package"
  require_file "$public_root"
  command -v openssl >/dev/null 2>&1 || fail 'openssl is required'
  verify_manifest "$package" release-manifest.sha256 "$public_root"
  verify_manifest "$package/rules" rules-manifest.sha256 "$public_root"
}

archive_package() {
  local package=$1 output=$2 epoch=$3
  require_dir "$package"
  [[ "$epoch" =~ ^[0-9]+$ ]] || fail 'archive epoch must be an unsigned integer'
  local parent name
  parent=$(cd "$package/.." && pwd)
  name=$(basename "$package")
  TZ=UTC tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime \
    --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -C "$parent" -cf - "$name" | gzip -n -9 >"$output"
}

validate_exceptions() {
  local file=$1
  require_file "$file"
  jq -e '
    . as $document |
    ($document.generated_at | fromdateiso8601) as $generated |
    $document.schema_version == 1 and
    ($document.generated_at | type == "string") and
    ($document.exceptions | type == "array") and
    all($document.exceptions[];
      . as $exception |
      ($exception.expires_at | fromdateiso8601) as $expiry |
      ($exception.id | type == "string" and length > 0) and
      ($exception.component | type == "string" and length > 0) and
      ($exception.severity == "high" or $exception.severity == "critical") and
      ($exception.owner | type == "string" and length > 0) and
      ($exception.reachability | type == "string" and length > 0) and
      ($exception.compensating_control | type == "string" and length > 0) and
      ($expiry > $generated and $expiry <= ($generated + 2592000)) and
      ($exception.scanner.name | type == "string" and length > 0) and
      ($exception.scanner.version | type == "string" and length > 0) and
      ($exception.scanner.database_version | type == "string" and length > 0)
    )
  ' "$file" >/dev/null || fail "invalid vulnerability exception policy: $file"
}

pin_compose() {
  local input=$1 output=$2 pins=$3
  require_file "$input"
  require_file "$pins"
  cp "$input" "$output"
  local old new
  while IFS=$'\t' read -r old new; do
    [[ -n "$old" && -n "$new" ]] || continue
    grep -Fq "$old" "$output" || fail "compose reference not found: $old"
    sed -i "s|$old|$new|g" "$output"
  done <"$pins"
  if grep -Eq '(^|[[:space:]])image:[[:space:]]+[^#[:space:]]*:latest([^-[:alnum:]_.]|$)' "$output"; then
    fail 'staged Compose file still contains a mutable latest image'
  fi
}

usage() {
  printf '%s\n' \
    'usage: release-provenance.sh sign --package DIR --key KEY' \
    '       release-provenance.sh sign-artifact --artifact FILE --output JSON --key KEY' \
    '       release-provenance.sh verify --package DIR --root PEM' \
    '       release-provenance.sh archive --package DIR --output FILE --epoch UNIX_SECONDS' \
    '       release-provenance.sh validate-exceptions --file JSON' \
    '       release-provenance.sh pin-compose --input YAML --output YAML --pins TSV' >&2
  exit 2
}

option() {
  local wanted=$1
  shift
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "$wanted" && $# -gt 1 ]]; then
      printf '%s\n' "$2"
      return
    fi
    shift
  done
  fail "missing option: $wanted"
}

main() {
  [[ $# -gt 0 ]] || usage
  local command=$1
  shift
  case "$command" in
    sign) sign_package "$(option --package "$@")" "$(option --key "$@")" ;;
    sign-artifact) sign_artifact "$(option --artifact "$@")" "$(option --output "$@")" "$(option --key "$@")" ;;
    verify) verify_package "$(option --package "$@")" "$(option --root "$@")" ;;
    archive) archive_package "$(option --package "$@")" "$(option --output "$@")" "$(option --epoch "$@")" ;;
    validate-exceptions) validate_exceptions "$(option --file "$@")" ;;
    pin-compose) pin_compose "$(option --input "$@")" "$(option --output "$@")" "$(option --pins "$@")" ;;
    *) usage ;;
  esac
}

main "$@"
