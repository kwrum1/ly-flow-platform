#!/bin/sh
set -eu

fail() {
  printf 'acceptance role agent failed: %s\n' "$*" >&2
  exit 1
}

for name in LAB_ROLE ENROLLMENT_TOKEN_ENV AGENT_ENROLL_TOKEN AGENT_IDENTITY_CONFIG SPOOL_DIR ENGINE_OUTPUT_DIR WORKLOAD_PORT; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || fail "$name must be set"
done

case "$AGENT_ENROLL_TOKEN" in
  *[!A-Za-z0-9._~-]*) fail 'enrollment token has invalid characters' ;;
esac
[ "${#AGENT_ENROLL_TOKEN}" -ge 16 ] || fail 'enrollment token is too short'

[ "${LAB_VALIDATE_ONLY:-0}" = 1 ] && exit 0

identity_dir=${AGENT_IDENTITY_CONFIG%/*}
mkdir -p "$identity_dir" "$SPOOL_DIR" "$ENGINE_OUTPUT_DIR"

if [ -s "$AGENT_IDENTITY_CONFIG" ]; then
  grep -Fq "role: $LAB_ROLE" "$AGENT_IDENTITY_CONFIG" || fail 'stale identity volume belongs to another role'
else
  umask 077
  {
    printf 'schema_version: lyflow.acceptance.identity.v1\n'
    printf 'agent_id: %s\n' "$HOSTNAME"
    printf 'hostname: %s\n' "$HOSTNAME"
    printf 'role: %s\n' "$LAB_ROLE"
    printf 'enrollment_token_env: %s\n' "$ENROLLMENT_TOKEN_ENV"
  } >"$AGENT_IDENTITY_CONFIG"
fi

printf '{"status":"healthy","role":"%s"}\n' "$LAB_ROLE" >"$ENGINE_OUTPUT_DIR/health"
cp /opt/lyflow-acceptance/workload-response.sh "$ENGINE_OUTPUT_DIR/workload-response"
chmod 0700 "$ENGINE_OUTPUT_DIR/workload-response"

heartbeat() {
  while :; do
    printf '{"observed_at":"%s","role":"%s","hostname":"%s","event":"heartbeat"}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LAB_ROLE" "$HOSTNAME" >>"$ENGINE_OUTPUT_DIR/telemetry.jsonl"
    sleep 2
  done
}

heartbeat &
exec nc -lk -p "$WORKLOAD_PORT" -e "$ENGINE_OUTPUT_DIR/workload-response"
