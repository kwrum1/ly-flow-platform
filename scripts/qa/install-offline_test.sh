#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
installer="$root/scripts/install-offline.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
  printf 'install-offline test failed: %s\n' "$*" >&2
  exit 1
}

assert_secret() {
  local env_file=$1 key=$2 value
  value=$(sed -n "s/^${key}=//p" "$env_file")
  [[ ${#value} -ge 24 ]] || fail "$key was not generated"
  case "$value" in
    password|lyflow_secret_password|lyflow_clickhouse_password|change_this_in_production) fail "$key uses a fixed default" ;;
  esac
}

assert_env_value() {
  local env_file=$1 key=$2 expected=$3 actual
  actual=$(sed -n "s/^${key}=//p" "$env_file")
  [[ "$actual" == "$expected" ]] || fail "$key expected $expected, got ${actual:-<missing>}"
}

test_generated_environment() (
  export LYFLOW_INSTALL_DIR="$tmp/generated"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  GENERATE_ADMIN_PASSWORD=1
  mkdir -p "$INSTALL_DIR"
  write_env
  [[ $(stat -c '%a' "$INSTALL_DIR/.env") == 600 ]] || fail '.env permissions are not 0600'
  for key in POSTGRES_PASSWORD CLICKHOUSE_PASSWORD JWT_SECRET DEFAULT_ADMIN_PASSWORD REDIS_ACL_PASSWORD SECURITY_ENGINE_CONTROL_TOKEN; do
    assert_secret "$INSTALL_DIR/.env" "$key"
  done
  grep -q '^REDIS_ACL_USERNAME=lyflow$' "$INSTALL_DIR/.env" || fail 'Redis ACL username missing'
  grep -q '^LYFLOW_RESET_ADMIN_PASSWORD=false$' "$INSTALL_DIR/.env" || fail 'admin password reset must be disabled after bootstrap'
  assert_env_value "$INSTALL_DIR/.env" POSTGRES_BIND_PORT 5432
  assert_env_value "$INSTALL_DIR/.env" REDIS_BIND_PORT 6379
  assert_env_value "$INSTALL_DIR/.env" CLICKHOUSE_HTTP_BIND_PORT 8123
  assert_env_value "$INSTALL_DIR/.env" CLICKHOUSE_NATIVE_BIND_PORT 9000
  assert_env_value "$INSTALL_DIR/.env" SERVER_BIND_PORT 8080
  assert_env_value "$INSTALL_DIR/.env" HTTPS_BIND_PORT 443
  assert_env_value "$INSTALL_DIR/.env" AGENT_CENTER_BIND_PORT 8081
  [[ -s "$INSTALL_DIR/initial-admin-credentials" ]] || fail 'initial admin credential file missing'
  [[ $(stat -c '%a' "$INSTALL_DIR/initial-admin-credentials") == 600 ]] || fail 'admin credential permissions are not 0600'
)

test_custom_bind_ports_are_persisted() (
  export LYFLOW_INSTALL_DIR="$tmp/custom-bind-ports"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  export POSTGRES_BIND_PORT=15432 REDIS_BIND_PORT=16379
  export CLICKHOUSE_HTTP_BIND_PORT=18123 CLICKHOUSE_NATIVE_BIND_PORT=19000
  export SERVER_BIND_PORT=18080 HTTPS_BIND_PORT=18443 AGENT_CENTER_BIND_PORT=18081
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  write_env
  assert_env_value "$INSTALL_DIR/.env" POSTGRES_BIND_PORT 15432
  assert_env_value "$INSTALL_DIR/.env" REDIS_BIND_PORT 16379
  assert_env_value "$INSTALL_DIR/.env" CLICKHOUSE_HTTP_BIND_PORT 18123
  assert_env_value "$INSTALL_DIR/.env" CLICKHOUSE_NATIVE_BIND_PORT 19000
  assert_env_value "$INSTALL_DIR/.env" SERVER_BIND_PORT 18080
  assert_env_value "$INSTALL_DIR/.env" HTTPS_BIND_PORT 18443
  assert_env_value "$INSTALL_DIR/.env" AGENT_CENTER_BIND_PORT 18081
)

test_admin_setup_is_deliberate() (
  export LYFLOW_INSTALL_DIR="$tmp/admin-choice"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  if parse_args --trust-root "$tmp/root.pem" 2>"$tmp/admin-error"; then
    fail 'installer accepted an implicit admin credential choice'
  fi
  grep -q -- '--generate-admin-password' "$tmp/admin-error" || fail 'admin setup diagnostic is missing'
  parse_args --trust-root "$tmp/root.pem" --generate-admin-password
  (( GENERATE_ADMIN_PASSWORD == 1 )) || fail 'explicit generated admin password choice was ignored'
)

test_upgrade_preserves_environment() (
  export LYFLOW_INSTALL_DIR="$tmp/upgrade"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  printf 'JWT_SECRET=existing-secret\n' >"$INSTALL_DIR/.env"
  write_env
  [[ $(cat "$INSTALL_DIR/.env") == 'JWT_SECRET=existing-secret' ]] || fail 'upgrade replaced existing .env'
)

test_offline_docker_preflight() (
  export LYFLOW_INSTALL_DIR="$tmp/docker-preflight"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  command() {
    if [[ $1 == -v && $2 == docker ]]; then
      return 1
    fi
    builtin command "$@"
  }
  if require_docker 2>"$tmp/docker-error"; then
    fail 'missing Docker was accepted'
  fi
  grep -q 'docker' "$tmp/docker-error" || fail 'missing Docker diagnostic is absent'
  ! declare -F install_docker >/dev/null || fail 'installer still contains an online Docker installation path'
)

test_package_file_preflight() (
  export LYFLOW_INSTALL_DIR="$tmp/package-preflight"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  PACKAGE_ROOT="$tmp/package"
  IMAGE_ARCHIVE="$PACKAGE_ROOT/images/lyflow-images.tar.gz"
  mkdir -p "$PACKAGE_ROOT/images" "$PACKAGE_ROOT/rules"
  : >"$PACKAGE_ROOT/ARCH"
  : >"$PACKAGE_ROOT/docker-compose.yml"
  : >"$PACKAGE_ROOT/release-manifest.sha256"
  : >"$PACKAGE_ROOT/release-manifest.sha256.sig"
  : >"$PACKAGE_ROOT/rules/rules-manifest.sha256"
  : >"$PACKAGE_ROOT/rules/rules-manifest.sha256.sig"
  if check_package_files 2>"$tmp/package-error"; then
    fail 'empty image archive was accepted'
  fi
  grep -q 'lyflow-images.tar.gz' "$tmp/package-error" || fail 'invalid image archive diagnostic is absent'
)

test_architecture_preflight() (
  export LYFLOW_INSTALL_DIR="$tmp/preflight-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  printf 'arm64\n' >"$tmp/ARCH"
  PACKAGE_ROOT=$tmp
  LYFLOW_HOST_ARCH=amd64
  if check_architecture 2>"$tmp/arch-error"; then
    fail 'architecture mismatch was accepted'
  fi
  grep -q 'architecture' "$tmp/arch-error" || fail 'architecture mismatch lacks diagnostic'
)

test_port_preflight() (
  export LYFLOW_INSTALL_DIR="$tmp/port-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  LYFLOW_LISTENING_PORTS='443 8081'
  if check_ports 2>"$tmp/port-error"; then
    fail 'occupied ports were accepted'
  fi
  grep -q '443' "$tmp/port-error" || fail 'occupied port diagnostic missing'
)

test_default_public_ports_characterization() (
  export LYFLOW_INSTALL_DIR="$tmp/default-port-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  local port
  for port in 443 8081; do
    LYFLOW_LISTENING_PORTS=$port
    if check_ports 2>"$tmp/default-port-$port-error"; then
      fail "default public port $port was accepted"
    fi
    grep -q "$port" "$tmp/default-port-$port-error" || fail "default public port $port diagnostic missing"
  done
)

test_all_configured_ports_are_preflighted() (
  export LYFLOW_INSTALL_DIR="$tmp/all-port-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  local name port
  while read -r name port; do
    POSTGRES_BIND_PORT=15432
    REDIS_BIND_PORT=16379
    CLICKHOUSE_HTTP_BIND_PORT=18123
    CLICKHOUSE_NATIVE_BIND_PORT=19000
    SERVER_BIND_PORT=18080
    HTTPS_BIND_PORT=18443
    AGENT_CENTER_BIND_PORT=18081
    printf -v "$name" '%s' "$port"
    LYFLOW_LISTENING_PORTS=$port
    if check_ports 2>"$tmp/configured-$name-error"; then
      fail "occupied configured port $name=$port was accepted"
    fi
    grep -q "$port" "$tmp/configured-$name-error" || fail "configured port $name diagnostic missing"
  done <<'EOF'
POSTGRES_BIND_PORT 15432
REDIS_BIND_PORT 16379
CLICKHOUSE_HTTP_BIND_PORT 18123
CLICKHOUSE_NATIVE_BIND_PORT 19000
SERVER_BIND_PORT 18080
HTTPS_BIND_PORT 18443
AGENT_CENTER_BIND_PORT 18081
EOF
)

test_invalid_bind_ports_are_rejected() (
  export LYFLOW_INSTALL_DIR="$tmp/invalid-port-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  local invalid
  for invalid in '' abc 0 65536; do
    POSTGRES_BIND_PORT=$invalid
    LYFLOW_LISTENING_PORTS=''
    if check_ports 2>"$tmp/invalid-port-${invalid:-empty}-error"; then
      fail "invalid bind port '${invalid:-empty}' was accepted"
    fi
    grep -qi 'port' "$tmp/invalid-port-${invalid:-empty}-error" || fail "invalid bind port '${invalid:-empty}' diagnostic missing"
  done
)

test_duplicate_bind_ports_are_rejected() (
  export LYFLOW_INSTALL_DIR="$tmp/duplicate-port-install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  POSTGRES_BIND_PORT=15432
  REDIS_BIND_PORT=15432
  LYFLOW_LISTENING_PORTS=''
  if check_ports 2>"$tmp/duplicate-port-error"; then
    fail 'duplicate bind ports were accepted'
  fi
  grep -qi 'duplicate\|same port' "$tmp/duplicate-port-error" || fail 'duplicate bind port diagnostic missing'
)

test_bounded_health_diagnostics() (
  export LYFLOW_INSTALL_DIR="$tmp/health"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  HEALTH_TIMEOUT_SECONDS=1
  HEALTH_INTERVAL_SECONDS=0
  health_probe() { return 1; }
  compose() {
    printf 'compose %s\n' "$*" >>"$tmp/diagnostics"
    return 0
  }
  if wait_for_health 2>"$tmp/health-error"; then
    fail 'health timeout was accepted'
  fi
  grep -q 'health' "$tmp/health-error" || fail 'health timeout lacks diagnostic'
  grep -q 'compose ps' "$tmp/diagnostics" || fail 'compose status diagnostic missing'
  grep -q 'compose logs' "$tmp/diagnostics" || fail 'compose logs diagnostic missing'
)

test_failed_upgrade_rolls_back() (
  export LYFLOW_INSTALL_DIR="$tmp/rollback/install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  printf 'old payload\n' >"$INSTALL_DIR/version"
  prepare_install
  printf 'new payload\n' >"$INSTALL_DIR/version"
  STACK_STARTED=1
  compose() { return 0; }
  rollback_install
  [[ $(cat "$INSTALL_DIR/version") == 'old payload' ]] || fail 'failed upgrade did not restore previous payload'
  [[ ! -e ${BACKUP_DIR:-/nonexistent} ]] || fail 'rollback backup was not cleaned'
)

test_stopped_upgrade_restarts_before_backup() (
  export LYFLOW_INSTALL_DIR="$tmp/early-rollback/install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  : >"$INSTALL_DIR/docker-compose.yml"
  UPGRADE=1
  compose_at() { printf '%s\n' "$*" >>"$tmp/early-compose"; }
  stop_existing_stack
  rollback_install
  grep -q 'up -d' "$tmp/early-compose" || fail 'stopped previous stack was not restarted after early failure'
)

test_signal_traps_force_rollback_status() {
  grep -Fq "trap 'exit 130' INT" "$installer" || fail 'SIGINT does not force a rollback exit status'
  grep -Fq "trap 'exit 143' TERM" "$installer" || fail 'SIGTERM does not force a rollback exit status'
}

test_signed_manifest_rejects_symlinks() {
  grep -Fq '[[ ! -L "$manifest" && ! -L "$signature" ]]' "$installer" || fail 'manifest or signature symlink rejection is missing'
  grep -Fq -- '-L "$root/$path" || ! -f "$root/$path"' "$installer" || fail 'manifest target symlink rejection is missing'
}

test_partial_down_failure_restarts_previous() (
  export LYFLOW_INSTALL_DIR="$tmp/partial-down/install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  : >"$INSTALL_DIR/docker-compose.yml"
  UPGRADE=1
  compose_at() {
    printf '%s\n' "$*" >>"$tmp/partial-down-compose"
    [[ $* != *' down --remove-orphans' ]]
  }
  if (trap 'on_exit $?' EXIT; stop_existing_stack); then
    fail 'partial previous-stack shutdown was accepted'
  fi
  grep -q 'down --remove-orphans' "$tmp/partial-down-compose" || fail 'partial down was not exercised'
  grep -q 'up -d' "$tmp/partial-down-compose" || fail 'previous stack was not restarted after partial down'
)

test_partial_candidate_up_cleans_and_restores() (
  export LYFLOW_INSTALL_DIR="$tmp/partial-up/install"
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  mkdir -p "$INSTALL_DIR"
  : >"$INSTALL_DIR/docker-compose.yml"
  printf 'old payload\n' >"$INSTALL_DIR/version"
  prepare_install
  : >"$INSTALL_DIR/docker-compose.yml"
  printf 'new payload\n' >"$INSTALL_DIR/version"
  PREVIOUS_STACK_STOPPED=1
  compose() {
    printf 'candidate %s\n' "$*" >>"$tmp/partial-up-compose"
    [[ $* != 'up -d' ]]
  }
  compose_at() {
    printf 'previous %s\n' "$*" >>"$tmp/partial-up-compose"
  }
  if (trap 'on_exit $?' EXIT; start_stack); then
    fail 'partial candidate startup was accepted'
  fi
  grep -q 'candidate down --remove-orphans' "$tmp/partial-up-compose" || fail 'partial candidate containers were not cleaned'
  grep -q 'previous .* up -d' "$tmp/partial-up-compose" || fail 'previous stack was not restarted after candidate failure'
  [[ $(cat "$INSTALL_DIR/version") == 'old payload' ]] || fail 'previous payload was not restored after candidate failure'
)

test_install_target_boundary_precedes_preflight_verification_and_docker() (
  export LYFLOW_TRUST_DIR="$tmp/trust"
  source "$installer"
  local case_root="$tmp/install-target-boundary"
  local call_ledger="$case_root/calls"
  local error_file="$case_root/error"
  local expected_error status before after failures=0
  mkdir -p "$case_root"

  record_call() { printf '%s\n' "$1" >>"$call_ledger"; }
  parse_args() { :; }
  require_root() { :; }
  on_exit() { :; }
  run_preflight() { record_call run_preflight; }
  validate_release_root() { record_call validate_release_root; }
  verify_signed_manifest() { record_call verify_signed_manifest; }
  verify_release_bundle() { record_call verify_release_bundle; }
  ensure_docker_running() { record_call ensure_docker_running; }
  stop_existing_stack() { record_call stop_existing_stack; }
  prepare_install() { record_call prepare_install; }
  copy_payload() { record_call copy_payload; }
  write_env() { record_call write_env; }
  load_images() { record_call load_images; }
  start_stack() { record_call start_stack; }
  persist_release_root() { record_call persist_release_root; }
  commit_install() { record_call commit_install; }

  target_snapshot() {
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      -C "$(dirname "$1")" -cf - "$(basename "$1")" | sha256sum
  }

  assert_fresh_target_rejected() (
    local label=$1 target=$2
    export LYFLOW_INSTALL_DIR=$target
    INSTALL_DIR=$target
    : >"$call_ledger"
    : >"$error_file"
    before=$(target_snapshot "$target")

    if (main) 2>"$error_file"; then
      status=0
    else
      status=$?
    fi

    [[ ! -s "$call_ledger" ]] || fail "$label target reached sentinel: $(paste -sd, "$call_ledger")"
    (( status != 0 )) || fail "$label target was accepted"
    expected_error="[lyflow-install] ERROR: fresh install target must be absent or an empty ordinary directory: $target"
    [[ $(<"$error_file") == "$expected_error" ]] || fail "$label target did not emit the exact fresh-install diagnostic"
    after=$(target_snapshot "$target")
    [[ "$after" == "$before" ]] || fail "$label target bytes changed"
    ! compgen -G "${target}.backup.*" >/dev/null || fail "$label target created a backup"
  )

  # Given an absent target, when the current boundary seam runs, then it remains a fresh install.
  INSTALL_DIR="$case_root/absent"
  UPGRADE=0
  detect_installation
  (( UPGRADE == 0 )) || fail 'absent target was not admitted as a fresh install'

  # Given an empty ordinary directory, when the current boundary seam runs, then it remains a fresh install.
  INSTALL_DIR="$case_root/empty"
  mkdir "$INSTALL_DIR"
  UPGRADE=0
  detect_installation
  (( UPGRADE == 0 )) || fail 'empty ordinary directory was not admitted as a fresh install'

  # Given invalid fresh targets, when main runs, then rejection precedes every recorded downstream path.
  mkdir "$case_root/symlink-referent"
  ln -s "$case_root/symlink-referent" "$case_root/symlink"
  printf 'regular-file-bytes\n' >"$case_root/non-directory"
  mkdir "$case_root/marker-only"
  : >"$case_root/marker-only/marker"
  mkdir "$case_root/hidden-entry"
  printf 'hidden-entry-bytes\n' >"$case_root/hidden-entry/.hidden"
  mkdir -p "$case_root/nested-nonempty/child"
  printf 'nested-entry-bytes\n' >"$case_root/nested-nonempty/child/payload"

  assert_fresh_target_rejected symlink "$case_root/symlink" || failures=1
  assert_fresh_target_rejected non-directory "$case_root/non-directory" || failures=1
  assert_fresh_target_rejected marker-only "$case_root/marker-only" || failures=1
  assert_fresh_target_rejected hidden-entry "$case_root/hidden-entry" || failures=1
  assert_fresh_target_rejected nested-nonempty "$case_root/nested-nonempty" || failures=1
  (( failures == 0 )) || fail 'one or more invalid fresh-install targets crossed the admission boundary'
)

if (( $# > 0 )); then
  [[ $# == 1 && $1 == test_install_target_boundary_precedes_preflight_verification_and_docker ]] || fail 'unknown focused test'
  "$1"
  printf 'install-offline inert tests passed\n'
  exit 0
fi

test_generated_environment
test_custom_bind_ports_are_persisted
test_admin_setup_is_deliberate
test_upgrade_preserves_environment
test_offline_docker_preflight
test_package_file_preflight
test_architecture_preflight
test_port_preflight
test_default_public_ports_characterization
test_all_configured_ports_are_preflighted
test_invalid_bind_ports_are_rejected
test_duplicate_bind_ports_are_rejected
test_bounded_health_diagnostics
test_failed_upgrade_rolls_back
test_stopped_upgrade_restarts_before_backup
test_signal_traps_force_rollback_status
test_signed_manifest_rejects_symlinks
test_partial_down_failure_restarts_previous
test_partial_candidate_up_cleans_and_restores
test_install_target_boundary_precedes_preflight_verification_and_docker

printf 'install-offline inert tests passed\n'
