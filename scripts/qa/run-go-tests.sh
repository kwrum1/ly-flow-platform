#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s <category>\n' "$0" >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
category=$1
manifest="$root/scripts/qa/expected-tests.txt"
events=$(mktemp)
server_modfile=""
cleanup() {
	rm -f "$events"
	if [[ -n $server_modfile ]]; then
		rm -f "$server_modfile" "${server_modfile%.mod}.sum"
	fi
}
trap cleanup EXIT INT TERM
root_packages=()
server_packages=()
agent_packages=()
security_engine_packages=()
dpi_engine_packages=()
clickhouse_packages=()

case "$category" in
  auth)
    server_packages=(./modules/auth ./cmd)
    agent_packages=()
    ;;
  agent-identity)
    server_packages=(./agentidentity ./agentcenter ./cmd)
    agent_packages=(./cmd)
    ;;
  trust-audit)
    server_packages=(./trustroot ./controlaudit ./security ./unified ./cmd)
    agent_packages=()
    ;;
	 ingestion-auth)
		server_packages=(./ingestionauth ./api/websocket ./agentcenter ./cmd)
		agent_packages=(./cmd)
		;;
  event-migration)
		root_packages=(./contracts ./eventinventory)
    server_packages=(./cmd)
    ;;
	clickhouse-migration)
		clickhouse_packages=(./analytics ./cmd)
		;;
	xdr-migration)
		server_packages=(./cmd)
		;;
	xdr-features)
		server_packages=(./xdr/features ./cmd)
		;;
	incident-lifecycle)
		server_packages=(./incidentlifecycle ./cmd)
		;;
	advisory-response)
		server_packages=(./advisoryresponse ./guardmode ./cmd)
		;;
  suricata-profile)
    agent_packages=(./cmd)
    ;;
	capture-quality)
		agent_packages=(./cmd)
		;;
	rasp-policy)
		server_packages=(./agentpolicy ./trustroot ./modules/rasp ./cmd)
		agent_packages=(./cmd)
		security_engine_packages=(./config ./engine)
		;;
	rasp-bridge)
		agent_packages=(./cmd)
		;;
	rule-lifecycle)
		server_packages=(./rulelifecycle ./controlaudit ./trustroot ./cmd)
		security_engine_packages=(./config ./engine ./cmd)
		server_modfile=$(mktemp --tmpdir="$root/server" --suffix=.mod .qa-rule-lifecycle.XXXXXX)
		cp "$root/server/go.mod" "$server_modfile"
		cp "$root/server/go.sum" "${server_modfile%.mod}.sum"
		;;
	transport-reliability)
		root_packages=(./contracts ./transportreliability)
		server_packages=(./materialization ./models ./ops ./cmd ./consumer ./xdr)
		agent_packages=(./cmd)
		security_engine_packages=(./engine)
		dpi_engine_packages=(./core/output ./core/redis ./core/engine)
		clickhouse_packages=(./analytics)
		;;
	runtime-health)
		agent_packages=(./cmd)
		security_engine_packages=(./config ./engine ./cmd)
		;;
  *)
    printf 'unknown Go test category: %s\n' "$category" >&2
    exit 2
    ;;
esac

(
	if [[ ${#root_packages[@]} -gt 0 ]]; then
		cd "$root/pkg"
		if [[ $category == transport-reliability ]]; then
			"$root/scripts/qa/with-disposable-redis.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "${root_packages[@]}"
		else
			GOWORK=off go test -json -race -shuffle=on -count=1 "${root_packages[@]}"
		fi
	fi
	if [[ ${#server_packages[@]} -gt 0 ]]; then
		cd "$root/server"
		if [[ $category == rule-lifecycle ]]; then
			"$root/scripts/qa/with-disposable-event-stores.sh" env GOWORK=off GOPROXY=off go test -mod=mod -modfile="$server_modfile" -json -race -shuffle=on -count=1 "${server_packages[@]}"
		elif [[ $category == rasp-policy ]]; then
			for package in "${server_packages[@]}"; do
				if [[ $package == ./agentpolicy || $package == ./cmd ]]; then
					"$root/scripts/qa/with-disposable-event-stores.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
				else
					GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
				fi
			done
		elif [[ $category == xdr-migration || $category == xdr-features || $category == incident-lifecycle || $category == advisory-response ]]; then
			for package in "${server_packages[@]}"; do
				"$root/scripts/qa/with-disposable-redis.sh" "$root/scripts/qa/with-disposable-event-stores.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
			done
		elif [[ $category == event-migration || $category == transport-reliability ]]; then
			for package in "${server_packages[@]}"; do
				"$root/scripts/qa/with-disposable-redis.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
			done
		else
			GOWORK=off go test -json -race -shuffle=on -count=1 "${server_packages[@]}"
		fi
	fi
	if [[ ${#agent_packages[@]} -gt 0 ]]; then
		cd "$root/agent"
		if [[ $category == transport-reliability ]]; then
			"$root/scripts/qa/with-disposable-redis.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "${agent_packages[@]}"
		else
			GOWORK=off go test -json -race -shuffle=on -count=1 "${agent_packages[@]}"
		fi
	fi
	if [[ ${#security_engine_packages[@]} -gt 0 ]]; then
		cd "$root/security-engine"
		"$root/scripts/qa/with-disposable-redis.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "${security_engine_packages[@]}"
	fi
	if [[ ${#dpi_engine_packages[@]} -gt 0 ]]; then
		cd "$root/dpi-engine"
		for package in "${dpi_engine_packages[@]}"; do
			"$root/scripts/qa/with-disposable-redis.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
		done
	fi
	if [[ ${#clickhouse_packages[@]} -gt 0 ]]; then
		cd "$root/server"
		if [[ $category == clickhouse-migration ]]; then
			for package in "${clickhouse_packages[@]}"; do
				"$root/scripts/qa/with-disposable-event-stores.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "$package"
			done
		else
			"$root/scripts/qa/with-disposable-clickhouse.sh" env GOWORK=off go test -json -race -shuffle=on -count=1 "${clickhouse_packages[@]}"
		fi
	fi
) | tee "$events"

"$root/scripts/qa/verify-go-test-json.sh" "$category" "$manifest" "$events"
printf 'verified expected passing test events for category: %s\n' "$category"
