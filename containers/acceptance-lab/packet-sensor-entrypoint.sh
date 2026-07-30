#!/bin/sh
set -eu

fail() {
  printf 'acceptance packet sensor failed: %s\n' "$*" >&2
  exit 1
}

for name in LAB_ROLE ENROLLMENT_TOKEN_ENV AGENT_ENROLL_TOKEN AGENT_IDENTITY_CONFIG SPOOL_DIR ENGINE_OUTPUT_DIR CAPTURE_INTERFACE; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || fail "$name must be set"
done

case "$AGENT_ENROLL_TOKEN" in
  *[!A-Za-z0-9._~-]*) fail 'enrollment token has invalid characters' ;;
esac
[ "${#AGENT_ENROLL_TOKEN}" -ge 16 ] || fail 'enrollment token is too short'
[ "$CAPTURE_INTERFACE" = eth0 ] || fail 'capture interface must be eth0'

[ "${LAB_VALIDATE_ONLY:-0}" = 1 ] && exit 0

identity_dir=${AGENT_IDENTITY_CONFIG%/*}
mkdir -p "$identity_dir" "$SPOOL_DIR" "$ENGINE_OUTPUT_DIR"

if [ -s "$AGENT_IDENTITY_CONFIG" ]; then
  grep -Fq 'role: packet-sensor' "$AGENT_IDENTITY_CONFIG" || fail 'stale identity volume belongs to another role'
else
  umask 077
  {
    printf 'schema_version: lyflow.acceptance.identity.v1\n'
    printf 'agent_id: %s\n' "$HOSTNAME"
    printf 'hostname: %s\n' "$HOSTNAME"
    printf 'role: packet-sensor\n'
    printf 'enrollment_token_env: %s\n' "$ENROLLMENT_TOKEN_ENV"
    printf 'capture_interface: %s\n' "$CAPTURE_INTERFACE"
  } >"$AGENT_IDENTITY_CONFIG"
fi

exec suricata \
  -c /etc/suricata/lyflow-acceptance.yaml \
  -i "$CAPTURE_INTERFACE" \
  -l "$ENGINE_OUTPUT_DIR"
