#!/bin/bash
# 流影平台性能压测脚本
# 版本: v1.0.0
# 更新日期: 2026-05-08

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

REDIS_ADDR="${REDIS_ADDR:-localhost:6379}"
DURATION="${DURATION:-60}"
RATE="${RATE:-1000}"  # 每秒消息数

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_info() { log "${GREEN}[INFO]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }

echo "========================================"
echo "  流影平台性能压测"
echo "========================================"
echo ""
log "配置:"
log "  Redis: $REDIS_ADDR"
log "  持续时间: ${DURATION}秒"
log "  发送速率: ${RATE}条/秒"
log "  预计总消息: $((DURATION * RATE))条"
echo ""

# 清理旧数据
log_info "清理 Redis Stream..."
redis-cli DEL flows:raw alerts:dpi > /dev/null 2>&1 || true

# 生成测试流量
generate_flows() {
    local count=$1
    local start_time=$(date +%s)

    for i in $(seq 1 $count); do
        local flow_id="perf-test-${start_time}-${i}"
        local domains=("pool.btc.com" "ethermine.org" "legit-site.com" "cdn.jsdelivr.net")
        local domain=${domains[$((RANDOM % ${#domains[@]}))]}

        redis-cli XADD flows:raw "*" \
            src_ip "192.168.$((RANDOM % 256)).$((RANDOM % 256))" \
            dst_ip "$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))" \
            dst_port "$((RANDOM % 2 == 0 ? 443 : 80))" \
            protocol "TCP" \
            app_protocol "HTTPS" \
            tls_sni "$domain" \
            sensor_id "perf-test-sensor" \
            timestamp $(date +%s) \
            bytes_in $((RANDOM % 10000)) \
            bytes_out $((RANDOM % 10000)) > /dev/null 2>&1 || true

        # 限速
        if [ $((i % RATE)) -eq 0 ]; then
            sleep 1
        fi
    done
}

# 监控 Redis Stream 长度
monitor_streams() {
    echo ""
    log_info "开始监控 Redis Stream..."
    echo ""

    local start_time=$(date +%s)
    local initial_flows=$(redis-cli XLEN flows:raw 2>/dev/null || echo 0)
    local initial_alerts=$(redis-cli XLEN alerts:dpi 2>/dev/null || echo 0)

    for i in $(seq 1 $DURATION); do
        local elapsed=$(($(date +%s) - start_time))
        local flows=$(redis-cli XLEN flows:raw 2>/dev/null || echo 0)
        local alerts=$(redis-cli XLEN alerts:dpi 2>/dev/null || echo 0)

        printf "\r[%3ds] flows:raw=%-8s | alerts:dpi=%-8s | rate=%s/s   " \
            "$elapsed" "$flows" "$alerts" "$RATE"

        sleep 1
    done
    echo ""
}

# 统计分析
show_stats() {
    echo ""
    log_info "压测结果统计"
    echo ""

    local flows_count=$(redis-cli XLEN flows:raw 2>/dev/null || echo 0)
    local alerts_count=$(redis-cli XLEN alerts:dpi 2>/dev/null || echo 0)

    log "flows:raw 总数: $flows_count"
    log "alerts:dpi 总数: $alerts_count"

    if [ "$flows_count" -gt 0 ]; then
        local detection_rate=$(awk "BEGIN {printf \"%.2f\", ($alerts_count/$flows_count)*100}")
        log "检测率: ${detection_rate}%"
    fi

    # Redis 内存使用
    echo ""
    log_info "Redis 内存状态:"
    redis-cli INFO memory | grep -E "used_memory_human|maxmemory_human" || true

    # 延迟统计
    echo ""
    log_info "Redis 延迟:"
    redis-cli --latency-history 2>/dev/null | tail -5 || true
}

# 清理函数
cleanup() {
    log_info "清理测试数据..."
    redis-cli XTRIM flows:raw MAXLEN 100 > /dev/null 2>&1 || true
}

# 主流程
main() {
    log_info "开始压测..."

    # 启动后台流量生成
    generate_flows $((DURATION * RATE)) &
    local pid=$!

    # 监控
    monitor_streams

    # 等待生成完成
    wait $pid 2>/dev/null || true

    # 等待 DPI 处理
    sleep 5

    # 统计结果
    show_stats

    # 清理
    cleanup

    echo ""
    log_info "压测完成"
}

trap cleanup EXIT
main
