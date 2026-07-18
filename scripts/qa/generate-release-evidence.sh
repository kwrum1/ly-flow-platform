#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output=''

fail() {
  printf '[release-evidence] ERROR: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "required file missing: $1"
}

require_dir() {
  [[ -d "$1" ]] || fail "required directory missing: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=${2:-}; shift 2 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$output" ]] || fail '--output is required'
tools=${TODO22_TOOL_DIR:?TODO22_TOOL_DIR is required}
go_db=${TODO22_GO_VULN_DB:?TODO22_GO_VULN_DB is required}
go_reports=${TODO22_GO_REPORT_DIR:?TODO22_GO_REPORT_DIR is required}
npm_report=${TODO22_NPM_AUDIT_JSON:?TODO22_NPM_AUDIT_JSON is required}
python_report=${TODO22_PYTHON_OSV_JSON:?TODO22_PYTHON_OSV_JSON is required}
osv_db=${TODO22_OSV_DB:?TODO22_OSV_DB is required}
trivy_cache=${TODO22_TRIVY_CACHE:?TODO22_TRIVY_CACHE is required}
grype_cache=${TODO22_GRYPE_CACHE:?TODO22_GRYPE_CACHE is required}
grype_status=${TODO22_GRYPE_DB_STATUS:?TODO22_GRYPE_DB_STATUS is required}
java_report=${TODO22_JAVA_REPORT:?TODO22_JAVA_REPORT is required}
java_db=${TODO22_JAVA_DB:?TODO22_JAVA_DB is required}
image_refs=${TODO22_IMAGE_REFS:?TODO22_IMAGE_REFS is required}

for tool in syft trivy grype govulncheck osv-scanner; do
  [[ -x "$tools/$tool" ]] || fail "pinned scanner missing: $tools/$tool"
done
require_dir "$go_db"
require_dir "$go_reports"
require_file "$npm_report"
require_file "$python_report"
require_file "$osv_db"
require_dir "$trivy_cache/db"
require_dir "$grype_cache"
require_file "$grype_status"
require_file "$java_report"
require_file "$java_db"
require_file "$root/scripts/qa/vulnerability-exceptions.json"

"$root/scripts/release-provenance.sh" validate-exceptions --file "$root/scripts/qa/vulnerability-exceptions.json"
"$tools/syft" version | grep -Fq 'Version:       1.46.0' || fail 'unexpected Syft version'
"$tools/trivy" --version | grep -Fq 'Version: 0.72.0' || fail 'unexpected Trivy version'
"$tools/grype" version | grep -Fq 'Version:             0.115.0' || fail 'unexpected Grype version'
"$tools/osv-scanner" --version | grep -Fq 'osv-scanner version: 2.4.0' || fail 'unexpected OSV-Scanner version'
"$tools/govulncheck" -version -db "file://$go_db" | grep -Fq 'Scanner: govulncheck@v1.1.4' || fail 'unexpected govulncheck version'

rm -rf "$output"
mkdir -p "$output/sbom/images" "$output/scanners/images" "$output/provenance"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
generated_at=$(date -u -d "@${SOURCE_DATE_EPOCH:-0}" +%Y-%m-%dT%H:%M:%SZ)

cp "$npm_report" "$output/scanners/npm-audit.json"
cp "$python_report" "$output/scanners/python-osv.json"
cp "$java_report" "$output/scanners/java-dependency-check.json"
cp "$grype_status" "$output/scanners/grype-db-status.json"
jq -e '(.metadata.vulnerabilities.high // -1) == 0 and (.metadata.vulnerabilities.critical // -1) == 0' "$npm_report" >/dev/null \
  || fail 'npm audit reported high or critical production vulnerabilities'
jq -e '[.. | objects | .max_severity? // empty | tonumber? // empty | select(. >= 7)] | length == 0' "$python_report" >/dev/null \
  || fail 'OSV reported high or critical Python vulnerabilities'
jq -e '[.dependencies[]? | .vulnerabilities[]? | (.cvssv4.score // .cvssv3.baseScore // .cvssv2.score // 0) | select(. >= 7)] | length == 0' "$java_report" >/dev/null \
  || fail 'Dependency-Check reported high or critical Java vulnerabilities'

for module in agent dpi-engine pkg security-engine server; do
  report="$go_reports/$module-final.json"
  require_file "$report"
  jq -s -e '[.[] | .finding? | select(.trace != null and (.trace | length) > 1)] | length == 0' "$report" >/dev/null \
    || fail "govulncheck reported reachable vulnerabilities in $module"
  cp "$report" "$output/scanners/go-$module.json"
done

"$tools/syft" scan "dir:$root" \
  --exclude './.git/**' --exclude './.omo/**' --exclude './release/**' \
  --exclude './frontend/node_modules/**' --exclude './third_party/**' \
  -o "cyclonedx-json=$tmp/source.cdx.json" -o "spdx-json=$tmp/source.spdx.json" >/dev/null
jq -S --arg generated "$generated_at" '
  del(.serialNumber) |
  .metadata.timestamp = $generated |
  .metadata.component["bom-ref"] = "lyflow-source" |
  .components = ((.components // []) | sort_by(.type, .group, .name, .version, .["bom-ref"]))
' "$tmp/source.cdx.json" >"$output/sbom/source.cdx.json"
source_digest=$(sha256sum "$output/sbom/source.cdx.json")
source_digest=${source_digest%% *}
jq -S --arg generated "$generated_at" --arg namespace "https://lyflow.local/spdx/source/$source_digest" '
  .creationInfo.created = $generated |
  .documentNamespace = $namespace |
  .packages = ((.packages // []) | sort_by(.SPDXID)) |
  .files = ((.files // []) | sort_by(.SPDXID)) |
  .relationships = ((.relationships // []) | sort_by(.spdxElementId, .relationshipType, .relatedSpdxElement))
' "$tmp/source.spdx.json" >"$output/sbom/source.spdx.json"

IFS=',' read -r -a images <<<"$image_refs"
[[ ${#images[@]} -gt 0 ]] || fail 'no release images supplied'
: >"$output/provenance/image-pins.txt"
image_index=0
for image in "${images[@]}"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || fail "mutable release image: $image"
  docker image inspect "$image" >/dev/null 2>&1 || fail "release image is not local: $image"
  image_index=$((image_index + 1))
  printf -v prefix 'image-%02d' "$image_index"
  printf '%s\n' "$image" >>"$output/provenance/image-pins.txt"

  "$tools/trivy" image --cache-dir "$trivy_cache" --offline-scan --skip-db-update --skip-java-db-update --scanners vuln --pkg-types os \
    --format json --output "$output/scanners/images/$prefix-trivy.json" "$image"

  GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false GRYPE_DB_CACHE_DIR="$grype_cache" \
    "$tools/grype" "$image" -o json --file "$output/scanners/images/$prefix-grype.json" >/dev/null

  "$tools/syft" scan "$image" -o "cyclonedx-json=$tmp/$prefix.cdx.json" -o "spdx-json=$tmp/$prefix.spdx.json" >/dev/null
  jq -S --arg generated "$generated_at" '
    del(.serialNumber) |
    .metadata.timestamp = $generated |
    .components = ((.components // []) | sort_by(.type, .group, .name, .version, .["bom-ref"]))
  ' "$tmp/$prefix.cdx.json" >"$output/sbom/images/$prefix.cdx.json"
  digest=${image##*@sha256:}
  jq -S --arg generated "$generated_at" --arg namespace "https://lyflow.local/spdx/image/$digest" '
    .creationInfo.created = $generated |
    .documentNamespace = $namespace |
    .packages = ((.packages // []) | sort_by(.SPDXID)) |
    .files = ((.files // []) | sort_by(.SPDXID)) |
    .relationships = ((.relationships // []) | sort_by(.spdxElementId, .relationshipType, .relatedSpdxElement))
  ' "$tmp/$prefix.spdx.json" >"$output/sbom/images/$prefix.spdx.json"
done

npm_db=$(sha256sum "$npm_report"); npm_db=${npm_db%% *}
go_db_version=$(jq -r '.modified' "$go_db/index/db.json")
go_db_digest=$(sha256sum "$go_db/SHA256SUMS"); go_db_digest=${go_db_digest%% *}
osv_db_digest=$(sha256sum "$osv_db"); osv_db_digest=${osv_db_digest%% *}
trivy_db_digest=$(sha256sum "$trivy_cache/db/trivy.db"); trivy_db_digest=${trivy_db_digest%% *}
grype_db_digest=$(sha256sum "$grype_cache/6/vulnerability.db"); grype_db_digest=${grype_db_digest%% *}
java_db_digest=$(sha256sum "$java_db"); java_db_digest=${java_db_digest%% *}

jq -n -S \
  --arg generated_at "$generated_at" \
  --arg npm_db "response-sha256:$npm_db" \
  --arg go_db "$go_db_version/$go_db_digest" \
  --arg osv_db "sha256:$osv_db_digest" \
  --arg trivy_db "$(jq -r '.UpdatedAt' "$trivy_cache/db/metadata.json")/sha256:$trivy_db_digest" \
  --arg grype_db "$(jq -r '.schemaVersion + "/" + .built' "$grype_status")/sha256:$grype_db_digest" \
  --arg java_db "$(jq -r '.scanInfo.dataSource[] | select(.name == "NVD Cache Last Modified") | .timestamp' "$java_report")/sha256:$java_db_digest" \
  --argjson image_count "$image_index" \
  '{schema_version:2, generated_at:$generated_at, policy:"pinned offline evidence recorded", image_count:$image_count,
    scanners:[
      {ecosystem:"npm",status:"PASS",tool_version:"npm 10.9.7",database_version:$npm_db},
      {ecosystem:"go",status:"PASS",tool_version:"govulncheck v1.1.4 / Go 1.26.5",database_version:$go_db},
      {ecosystem:"python",status:"PASS",tool_version:"OSV-Scanner 2.4.0",database_version:$osv_db},
      {ecosystem:"container-trivy",status:"RECORDED",tool_version:"Trivy 0.72.0",database_version:$trivy_db},
      {ecosystem:"container-grype",status:"RECORDED",tool_version:"Grype 0.115.0",database_version:$grype_db},
      {ecosystem:"java",status:"PASS",tool_version:"Dependency-Check 12.2.2",database_version:$java_db}
    ]}' >"$output/scanner-summary.json"

(
  cd "$output"
  find . -type f ! -name artifact-digests.sha256 -print0 | sort -z | xargs -0 sha256sum
) >"$output/artifact-digests.sha256"
printf 'release evidence passed\n'
