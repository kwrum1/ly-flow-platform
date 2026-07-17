#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock="$root/third_party/security-engines/suricata-profile.lock.json"
evidence="$root/third_party/security-engines/suricata-evidence/7.0.11"
source_repo="$root/third_party/security-engines/suricata"
archive="$evidence/suricata-7.0.11.tar.gz"
signature="$archive.sig"
tag_key="$evidence/tag-signer-1DBF03667457EB6AED9E0DF9C1F495E3926856B4.asc"
archive_key="$evidence/archive-signer-B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A.asc"
index_manifest="$evidence/image-index.json"
platform_manifest="$evidence/image-linux-amd64-manifest.json"

for path in "$lock" "$archive" "$signature" "$tag_key" "$archive_key" "$index_manifest" "$platform_manifest"; do
	[[ -f "$path" ]] || { printf 'missing retained Suricata provenance asset: %s\n' "$path" >&2; exit 1; }
done
for command in docker git gpg grep jq sha256sum; do
	command -v "$command" >/dev/null 2>&1 || { printf 'required local command unavailable: %s\n' "$command" >&2; exit 2; }
done

check_sha() {
	local path=$1
	local expected=$2
	local actual
	actual=$(sha256sum "$path" | cut -d' ' -f1)
	[[ "$actual" == "$expected" ]] || { printf 'digest mismatch for %s\n' "$path" >&2; exit 1; }
}

check_sha "$archive" "$(jq -r '.source_archive_sha256' "$lock")"
check_sha "$signature" "$(jq -r '.source_archive_signature_sha256' "$lock")"
check_sha "$tag_key" "$(jq -r '.source_tag_signer_key_sha256' "$lock")"
check_sha "$archive_key" "$(jq -r '.source_archive_signer_key_sha256' "$lock")"
check_sha "$index_manifest" "$(jq -r '.image_digest' "$lock" | cut -d: -f2)"
check_sha "$platform_manifest" "$(jq -r '.image_platform_digest' "$lock" | cut -d: -f2)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
chmod 700 "$tmp"
gpg --batch --homedir "$tmp" --show-keys --with-colons "$tag_key" >"$tmp/tag-key.txt"
grep -Fqx 'fpr:::::::::1DBF03667457EB6AED9E0DF9C1F495E3926856B4:' "$tmp/tag-key.txt"
gpg --batch --homedir "$tmp" --show-keys --with-colons "$archive_key" >"$tmp/archive-key.txt"
grep -Fqx 'fpr:::::::::B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A:' "$tmp/archive-key.txt"
gpg --batch --homedir "$tmp" --import "$tag_key" "$archive_key" >"$tmp/import.log" 2>&1
gpg --batch --homedir "$tmp" --status-fd=1 --verify "$signature" "$archive" >"$tmp/archive-verify.log" 2>&1
grep -Fq '[GNUPG:] VALIDSIG B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A ' "$tmp/archive-verify.log"
(
	cd "$source_repo"
	GNUPGHOME="$tmp" git tag -v suricata-7.0.11
) >"$tmp/tag-verify.log" 2>&1
grep -Fq 'using RSA key 1DBF03667457EB6AED9E0DF9C1F495E3926856B4' "$tmp/tag-verify.log"
[[ $(git -C "$source_repo" rev-parse refs/tags/suricata-7.0.11) == "$(jq -r '.source_tag_object' "$lock")" ]]
[[ $(git -C "$source_repo" rev-parse 'suricata-7.0.11^{}') == "$(jq -r '.source_release_commit' "$lock")" ]]
[[ $(git -C "$source_repo" rev-parse HEAD) == "$(jq -r '.vendored_source_commit' "$lock")" ]]

jq -e --arg digest "$(jq -r '.image_platform_digest' "$lock")" '
	any(.manifests[]; .digest == $digest and .platform.os == "linux" and .platform.architecture == "amd64")
' "$index_manifest" >/dev/null
jq -e '.schemaVersion == 2 and .mediaType == "application/vnd.docker.distribution.manifest.v2+json"' "$platform_manifest" >/dev/null
docker image inspect "$(jq -r '.image' "$lock")" >"$tmp/local-image.json"
jq -e --arg digest "$(jq -r '.image_digest' "$lock")" '
	.[0].Architecture == "amd64" and .[0].Os == "linux" and any(.[0].RepoDigests[]; endswith($digest))
' "$tmp/local-image.json" >/dev/null

printf 'SURICATA_PROVENANCE_CHECK=PASS tag_fingerprint=%s archive_fingerprint=%s image_digest=%s platform_digest=%s\n' \
	"$(jq -r '.source_tag_signer_fingerprint' "$lock")" \
	"$(jq -r '.source_archive_signer_fingerprint' "$lock")" \
	"$(jq -r '.image_digest' "$lock")" \
	"$(jq -r '.image_platform_digest' "$lock")"
