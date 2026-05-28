#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/ly-agent}"
BIN_DIR="${BIN_DIR:-$INSTALL_DIR/bin}"
CONFIG_DIR="${CONFIG_DIR:-$INSTALL_DIR/etc}"
LOG_DIR="${LOG_DIR:-/var/log/ly-agent}"
DATA_DIR="${DATA_DIR:-$INSTALL_DIR/data}"
RASP_DIR="${RASP_DIR:-$INSTALL_DIR/rasp}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/ly-agent.service}"
SERVICE_USER="${SERVICE_USER:-root}"
SERVICE_GROUP="${SERVICE_GROUP:-root}"
BINARY_SOURCE="${BINARY_SOURCE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ly-agent}"
API_SERVER="${API_SERVER:-http://127.0.0.1:8080}"
REDIS_SERVER="${REDIS_SERVER:-127.0.0.1:6379}"
AGENT_ID="${AGENT_ID:-}"
AGENT_KEY="${AGENT_KEY:-}"
TRAFFIC_INTERFACE="${TRAFFIC_INTERFACE:-auto}"
CAPTURE_ENGINE="${CAPTURE_ENGINE:-auto}"
BPF_FILTER="${BPF_FILTER:-tcp or udp}"
PROMISCUOUS="${PROMISCUOUS:-true}"
DRY_RUN=0
START_SERVICE=0

usage() {
  cat <<'EOF'
Usage: install.sh [--dry-run] [--start]

Environment overrides:
  BINARY_SOURCE=/path/to/ly-agent
  INSTALL_DIR=/opt/ly-agent
  API_SERVER=http://127.0.0.1:8080
  REDIS_SERVER=127.0.0.1:6379
  AGENT_ID=existing-id
  AGENT_KEY=existing-key
  TRAFFIC_INTERFACE=auto
  CAPTURE_ENGINE=auto
  BPF_FILTER="tcp or udp"
  PROMISCUOUS=true
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --start) START_SERVICE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

run() {
  printf '+ %s\n' "$*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

write_file() {
  local path="$1"
  local mode="$2"
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  printf '+ install -m %s %s\n' "$mode" "$path"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    sed "s/^/  | /" "$tmp"
  fi
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if [[ -e "$path" ]]; then
      run cp -a "$path" "$path.bak.$(date +%Y%m%d%H%M%S)"
    fi
    install -m "$mode" "$tmp" "$path"
  fi
  rm -f "$tmp"
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "$BINARY_SOURCE" ]]; then
  echo "agent binary not found or not executable: $BINARY_SOURCE" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; systemd host install is unsupported" >&2
  exit 1
fi

run mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$INSTALL_DIR/logs" "$DATA_DIR/sessions" "$DATA_DIR/packets" "$DATA_DIR/cache" "$RASP_DIR/java" "$RASP_DIR/python" "$RASP_DIR/ebpf" "$RASP_DIR/rules" "$LOG_DIR"
run install -m 0755 "$BINARY_SOURCE" "$BIN_DIR/ly-agent"
run chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" "$LOG_DIR"

write_file "$CONFIG_DIR/agent.yaml" 0640 <<EOF
server:
  api: "$API_SERVER"
  redis: "$REDIS_SERVER"

agent:
  id: "$AGENT_ID"
  key: "$AGENT_KEY"
  heartbeat_interval: 30
  log_level: info
  log_file: $INSTALL_DIR/logs/agent.log

traffic:
  enabled: true
  interface: "$TRAFFIC_INTERFACE"
  capture_engine: "$CAPTURE_ENGINE"
  bpf_filter: "$BPF_FILTER"
  promiscuous: $PROMISCUOUS
  streams:
    raw: "flows:raw"
    semantic: "flows:semantic"

session:
  enabled: true
  mode: behavior_aggregate
  stream: "sessions:semantic"
  local_path: $DATA_DIR/sessions
  retain_days: 7

packet:
  retain_enabled: true
  sample_mode: suspicious
  local_path: $DATA_DIR/packets
  max_file_mb: 128
  retain_days: 3

asset:
  enabled: true
  interval: 60
  collect:
    interfaces: true
    performance: true
    processes: true

runtime:
  enabled: true
  mode: monitor
  backend: auto
  centos7_fallback: auditd
  stream: "alerts:runtime"

rasp:
  enabled: true
  mode: monitor
  auto_inject: true
  language_fallback: true
  stream: "alerts:rasp"

logging:
  level: "info"
  output: "$INSTALL_DIR/logs/agent.log"
EOF

write_file "$SYSTEMD_UNIT" 0644 <<EOF
[Unit]
Description=LyFlow Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=$BIN_DIR/ly-agent --config $CONFIG_DIR/agent.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576
WorkingDirectory=$INSTALL_DIR
StandardOutput=journal
StandardError=journal
Environment=CONFIG_FILE=$CONFIG_DIR/agent.yaml

[Install]
WantedBy=multi-user.target
EOF

run systemctl daemon-reload
run systemctl enable ly-agent.service

if [[ "$START_SERVICE" -eq 1 ]]; then
  run systemctl restart ly-agent.service
fi

echo "ly-agent install complete"
echo "Binary: $BIN_DIR/ly-agent"
echo "Config: $CONFIG_DIR/agent.yaml"
echo "Service: $SYSTEMD_UNIT"
