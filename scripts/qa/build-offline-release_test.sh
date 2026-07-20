#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
release="$root/scripts/build-offline-release.sh"

[[ -f "$release" ]] || { printf 'offline release builder is missing\n' >&2; exit 1; }
bash -n "$release"

for variable in RASP_PYTHON_310_IMAGE RASP_PYTHON_311_IMAGE RASP_PYTHON_312_IMAGE; do
  grep -Fq ": \"\${$variable:?" "$release" || {
    printf 'missing required RASP input validation: %s\n' "$variable" >&2
    exit 1
  }
done

grep -Fq 'sha256:[0-9a-f]{64}' "$release" || {
  printf 'missing immutable digest syntax validation\n' >&2
  exit 1
}
for variable in RASP_PYTHON_310_IMAGE RASP_PYTHON_311_IMAGE RASP_PYTHON_312_IMAGE; do
  grep -Fq "validate_immutable_image_ref $variable \"\$$variable\"" "$release" || {
    printf 'RASP input does not use immutable digest validation: %s\n' "$variable" >&2
    exit 1
  }
done

static_build_line=$(grep -nF 'building static Go binaries' "$release" | cut -d: -f1)
rasp_validation_line=$(grep -nF 'validate_immutable_image_ref' "$release" | head -n1 | cut -d: -f1)
rasp_inspect_line=$(grep -nF 'ensure_image "$RASP_PYTHON_310_IMAGE"' "$release" | head -n1 | cut -d: -f1)
[[ -n $static_build_line && -n $rasp_validation_line && -n $rasp_inspect_line ]]
(( rasp_validation_line < static_build_line ))
(( rasp_inspect_line < static_build_line ))

grep -Fq 'RASP_PYTHON_310_IMAGE="$RASP_PYTHON_310_IMAGE"' "$release"
grep -Fq 'RASP_PYTHON_311_IMAGE="$RASP_PYTHON_311_IMAGE"' "$release"
grep -Fq 'RASP_PYTHON_312_IMAGE="$RASP_PYTHON_312_IMAGE"' "$release"
! grep -Fq 'RASP_PYTHON_310_IMAGE:-' "$release"
! grep -Fq 'RASP_PYTHON_311_IMAGE:-' "$release"
! grep -Fq 'RASP_PYTHON_312_IMAGE:-' "$release"

images_assignment=$(grep -F 'IMAGES=(' "$release")
docker_save=$(grep -F 'docker save ' "$release")
pins=$(sed -n '/cat >"$PACKAGE_DIR\/image-pins.tsv"/,/^EOF$/p' "$release")
if printf '%s\n%s\n%s\n' "$images_assignment" "$docker_save" "$pins" | grep -Eq 'RASP_PYTHON_(310|311|312)_IMAGE'; then
  printf 'RASP images leaked into release package image inputs\n' >&2
  exit 1
fi

grep -Fq 'find "$PACKAGE_DIR/rules/security-engine/lifecycle" -type d -exec chmod 0755 {} +' "$release" || {
  printf 'packaged lifecycle directories are not normalized to 0755\n' >&2
  exit 1
}
grep -Fq 'mkdir -p "$PACKAGE_DIR/rules/security-engine/lifecycle"' "$release" || {
  printf 'packaged lifecycle directory is not created for clean checkouts\n' >&2
  exit 1
}
grep -Fq 'rm -rf "$PACKAGE_DIR/rules/security-engine/lifecycle"' "$release" || {
  printf 'build-host lifecycle state is not excluded from the package\n' >&2
  exit 1
}
grep -Fq 'rm -f "$PACKAGE_DIR/rules/security-engine/.lifecycle.bootstrap.lock"' "$release" || {
  printf 'bootstrap lock is not excluded from the package\n' >&2
  exit 1
}
grep -Fq 'find "$PACKAGE_DIR/rules/security-engine/lifecycle" -type f -exec chmod 0644 {} +' "$release" || {
  printf 'packaged lifecycle files are not normalized to 0644\n' >&2
  exit 1
}
grep -Fq -- '--generate-admin-password' "$release" || {
  printf 'packaged README omits required generated admin password choice\n' >&2
  exit 1
}
grep -Fq '`initial-admin-credentials`' "$release" || {
  printf 'packaged README omits generated credential location\n' >&2
  exit 1
}
if grep -Fq 'admin / password' "$release"; then
  printf 'packaged README advertises a fixed admin password\n' >&2
  exit 1
fi

printf 'offline release RASP contract self-test passed\n'
