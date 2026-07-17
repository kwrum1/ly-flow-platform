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
  [[ -s "$INSTALL_DIR/initial-admin-credentials" ]] || fail 'initial admin credential file missing'
  [[ $(stat -c '%a' "$INSTALL_DIR/initial-admin-credentials") == 600 ]] || fail 'admin credential permissions are not 0600'
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

test_generated_environment
test_admin_setup_is_deliberate
test_upgrade_preserves_environment
test_offline_docker_preflight
test_package_file_preflight
test_architecture_preflight
test_port_preflight
test_bounded_health_diagnostics
test_failed_upgrade_rolls_back
test_stopped_upgrade_restarts_before_backup
test_signal_traps_force_rollback_status
test_partial_down_failure_restarts_previous
test_partial_candidate_up_cleans_and_restores

printf 'install-offline inert tests passed\n'
