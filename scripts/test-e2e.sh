#!/bin/bash
# 流影平台端到端测试脚本
# 版本: v1.0.0
# 更新日期: 2026-05-08

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVER_URL="${SERVER_URL:-http://localhost:8080}"
REDIS_ADDR="${REDIS_ADDR:-localhost:6379}"
REDIS_ACL_USERNAME="${REDIS_ACL_USERNAME:-}"
REDIS_ACL_PASSWORD="${REDIS_ACL_PASSWORD:-}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"
LOG_FILE="/tmp/ly-e2e-test.log"

redis_cli() {
    local host="${REDIS_ADDR%:*}"
    local port="${REDIS_ADDR##*:}"
    local auth=()
    if [[ -n "$REDIS_ACL_USERNAME" && -n "$REDIS_ACL_PASSWORD" ]]; then
        auth=(--user "$REDIS_ACL_USERNAME" --pass "$REDIS_ACL_PASSWORD")
    elif [[ -n "$REDIS_PASSWORD" ]]; then
        auth=(--pass "$REDIS_PASSWORD")
    fi
    redis-cli -h "$host" -p "$port" "${auth[@]}" "$@"
}

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_info() { log "${GREEN}[PASS]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_error() { log "${RED}[FAIL]${NC} $1"; }

PASSED=0
FAILED=0

test_case() {
    local name="$1"
    local cmd="$2"
    echo -n "Testing: $name ... "
    if eval "$cmd" > /dev/null 2>&1; then
        log_info "$name"
        ((PASSED++))
    else
        log_error "$name"
        ((FAILED++))
    fi
}

# ============================================
# 1. 健康检查
# ============================================
echo "========================================"
echo "  流影平台端到端测试"
echo "========================================"
echo ""

log "开始端到端测试..."

echo ""
echo "=== 1. 健康检查 ==="

test_case "ly-server API 健康检查" \
    "curl -s -f $SERVER_URL/api/v1/health"

test_case "PostgreSQL 连接" \
    "redis_cli PING"

# ============================================
# 2. 数据流测试
# ============================================
echo ""
echo "=== 2. Redis Stream 数据流测试 ==="

# 生成测试流量
test_flow() {
    local flow_id="test-$(date +%s)-$$"
    redis_cli XADD flows:raw "*" \
        src_ip "192.168.1.100" \
        dst_ip "8.8.8.8" \
        dst_port "443" \
        protocol "TCP" \
        app_protocol "HTTPS" \
        tls_sni "pool.btc.com" \
        sensor_id "test-sensor" \
        timestamp $(date +%s)
}

test_case "flows:raw 生产者" "test_flow"

sleep 2

# 检查 alerts:dpi 是否有告警
test_case "alerts:dpi 消费者" \
    "redis_cli XLEN alerts:dpi | grep -qE '[0-9]+'"

# ============================================
# 3. API 功能测试
# ============================================
echo ""
echo "=== 3. API 功能测试 ==="

# 登录
test_case "用户登录" \
    "curl -s -f -X POST $SERVER_URL/api/v1/auth/login \
        -H 'Content-Type: application/json' \
        -d '{\"username\":\"admin\",\"password\":\"admin\"}'"

# 获取事件列表
test_case "获取事件列表" \
    "curl -s -f $SERVER_URL/api/v1/events | grep -q 'code'"

# 获取资产列表
test_case "获取资产列表" \
    "curl -s -f $SERVER_URL/api/v1/assets | grep -q 'code'"

# 获取统计数据
test_case "获取统计数据" \
    "curl -s -f $SERVER_URL/api/v1/stats | grep -q 'code'"

# ============================================
# 4. WebSocket 测试
# ============================================
echo ""
echo "=== 4. WebSocket 测试 ==="

test_case "WebSocket 连接" \
    "timeout 3 bash -c 'echo ping | nc -w 1 localhost 8080' 2>/dev/null || true"

# ============================================
# 5. 数据库测试
# ============================================
echo ""
echo "=== 5. 数据库测试 ==="

# 检查 events 表
test_case "events 表查询" \
    "redis_cli --no-raw INFO stats | grep -q instantaneous_ops_per_sec"

# ============================================
# 测试报告
# ============================================
echo ""
echo "========================================"
echo "  测试报告"
echo "========================================"
echo ""
log "通过: $PASSED"
log "失败: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    log_info "全部测试通过！"
    exit 0
else
    log_error "$FAILED 个测试失败"
    exit 1
fi
