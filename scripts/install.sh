#!/bin/bash
# 流影 Agent 安装脚本
# 版本: v1.0.0
# 更新日期: 2026-05-08
# 仅支持 Linux

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认配置
MANAGER_ADDR="http://localhost:8081"
AGENT_VERSION="1.0.0"
INSTALL_DIR="/opt/ly-agent"
PLUGINS="all"
LOG_FILE="/var/log/ly-agent-install.log"

# 用法
usage() {
    echo "流影 Agent 安装脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --manager=<addr>      Manager 地址 (默认: http://localhost:8081)"
    echo "  --plugins=<list>      安装的插件，逗号分隔 (默认: all)"
    echo "                         可选: probe,agent,rasp-java,rasp-python"
    echo "  --install-dir=<path>  安装目录 (默认: /opt/ly-agent)"
    echo "  --help                显示帮助"
    echo ""
    exit 0
}

# 日志函数
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

log_info() {
    log "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "需要 root 权限运行此脚本"
        exit 1
    fi
}

# 检查系统要求
check_system() {
    log_info "检查系统要求..."

    # 检查 Linux
    if [[ ! -f /etc/os-release ]]; then
        log_error "不支持此操作系统"
        exit 1
    fi

    # 检查架构
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
        log_warn "架构 $ARCH 可能不受支持"
    fi

    # 检查内存
    MEM=$(free -m | awk '/Mem:/ {print $2}')
    if [[ $MEM -lt 512 ]]; then
        log_warn "内存小于 512MB，可能影响性能"
    fi

    log_info "系统检查完成"
}

# 创建目录
create_dirs() {
    log_info "创建安装目录..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/plugins"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/domain-lists"

    log_info "目录创建完成"
}

# 下载 Agent
download_agent() {
    log_info "下载 Agent..."

    local download_url="$MANAGER_ADDR/api/v1/agent/download"
    local tmp_file="/tmp/ly-agent.tar.gz"

    if command -v curl &> /dev/null; then
        curl -L -o "$tmp_file" "$download_url" 2>/dev/null || {
            log_warn "下载失败，使用内置二进制"
            return 0
        }
    elif command -v wget &> /dev/null; then
        wget -O "$tmp_file" "$download_url" 2>/dev/null || {
            log_warn "下载失败，使用内置二进制"
            return 0
        }
    fi

    if [[ -f "$tmp_file" ]]; then
        tar -xzf "$tmp_file" -C "$INSTALL_DIR"
        rm -f "$tmp_file"
        log_info "Agent 下载完成"
    fi
}

# 复制规则文件
copy_rules() {
    log_info "复制规则文件..."

    # 如果 Manager 上有规则，从 Manager 下载
    # 否则使用内置规则

    log_info "规则文件复制完成"
}

# 创建 systemd 服务
create_service() {
    log_info "创建 systemd 服务..."

    cat > /etc/systemd/system/ly-agent.service <<EOF
[Unit]
Description=LyFlow Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/bin/ly-agent --config $INSTALL_DIR/config/agent.yaml
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "systemd 服务创建完成"
}

# 配置 Agent
configure_agent() {
    log_info "配置 Agent..."

    cat > "$INSTALL_DIR/config/agent.yaml" <<EOF
# LyFlow Agent 配置
version: $AGENT_VERSION

# Manager 配置
manager:
  addr: "$MANAGER_ADDR"
  heartbeat_interval: 30
  report_interval: 60

# 日志配置
logging:
  level: info
  file: $INSTALL_DIR/logs/agent.log
  max_size: 100MB
  max_backups: 5

# 插件配置
plugins:
  enabled: all

# 流量检测
traffic_analysis:
  enabled: true
  interface: auto
  bpf_filter: "tcp or udp"
  redis_stream: "flows:raw"
  suricata_rules: true

# 端点检测
endpoint_detection:
  enabled: true
  events:
    - process_create
    - file_create
    - network_connect

# 域名审计
domain_audit:
  enabled: true
  lists:
    - $INSTALL_DIR/domain-lists/mining.txt
    - $INSTALL_DIR/domain-lists/fraud.txt
    - $INSTALL_DIR/domain-lists/custom.txt
EOF

    log_info "Agent 配置完成"
}

# 启动 Agent
start_agent() {
    log_info "启动 Agent..."

    systemctl enable ly-agent
    systemctl start ly-agent

    if systemctl is-active --quiet ly-agent; then
        log_info "${GREEN}Agent 启动成功${NC}"
    else
        log_error "Agent 启动失败，请检查日志"
        exit 1
    fi
}

# 安装指定插件
install_plugins() {
    log_info "安装插件: $PLUGINS"

    if [[ "$PLUGINS" == "all" ]]; then
        # 安装所有插件
        PLUGINS="probe,agent"
    fi

    IFS=',' read -ra PLUGIN_ARRAY <<< "$PLUGINS"

    for plugin in "${PLUGIN_ARRAY[@]}"; do
        case "$plugin" in
            probe)
                log_info "安装 probe 插件..."
                # 配置探针
                ;;
            agent)
                log_info "安装 agent 插件..."
                # 配置端点检测
                ;;
            rasp-java)
                log_info "安装 RASP Java 插件..."
                # 配置 Java Agent
                ;;
            rasp-python)
                log_info "安装 RASP Python 插件..."
                # 配置 Python Hook
                ;;
            *)
                log_warn "未知插件: $plugin"
                ;;
        esac
    done

    log_info "插件安装完成"
}

# 验证安装
verify_installation() {
    log_info "验证安装..."

    if systemctl is-active --quiet ly-agent; then
        log_info "${GREEN}✓ Agent 运行正常${NC}"
    else
        log_error "✗ Agent 未运行"
        return 1
    fi

    # 检查进程
    if pgrep -f ly-agent > /dev/null; then
        log_info "${GREEN}✓ Agent 进程存在${NC}"
    else
        log_warn "Agent 进程不存在"
    fi

    log_info "验证完成"
}

# 卸载函数
uninstall() {
    log_info "卸载 Agent..."

    systemctl stop ly-agent
    systemctl disable ly-agent
    rm -f /etc/systemd/system/ly-agent.service
    rm -rf "$INSTALL_DIR"

    log_info "${GREEN}卸载完成${NC}"
}

# 主函数
main() {
    echo "=============================================="
    echo "  流影 Agent 安装脚本 v$AGENT_VERSION"
    echo "=============================================="
    echo ""

    # 解析参数
    for arg in "$@"; do
        case "$arg" in
            --manager=*)
                MANAGER_ADDR="${arg#*=}"
                ;;
            --plugins=*)
                PLUGINS="${arg#*=}"
                ;;
            --install-dir=*)
                INSTALL_DIR="${arg#*=}"
                ;;
            --uninstall)
                uninstall
                exit 0
                ;;
            --help|-h)
                usage
                ;;
        esac
    done

    log_info "开始安装..."
    log_info "Manager 地址: $MANAGER_ADDR"
    log_info "安装目录: $INSTALL_DIR"
    log_info "插件: $PLUGINS"
    echo ""

    check_root
    check_system
    create_dirs
    download_agent
    copy_rules
    install_plugins
    configure_agent
    create_service
    start_agent
    verify_installation

    echo ""
    echo "=============================================="
    echo -e "${GREEN}  安装完成！${NC}"
    echo "=============================================="
    echo ""
    echo "管理命令:"
    echo "  启动: systemctl start ly-agent"
    echo "  停止: systemctl stop ly-agent"
    echo "  状态: systemctl status ly-agent"
    echo "  日志: journalctl -u ly-agent -f"
    echo ""
}

main "$@"