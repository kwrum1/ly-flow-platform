#!/bin/bash
# 流影规则订阅更新脚本
# 版本: 1.0.0
# 更新时间: 2026-05-09

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="${SCRIPT_DIR}/../rules"
BACKUP_DIR="${RULES_DIR}/backup"
LOG_FILE="${SCRIPT_DIR}/../logs/rules-update.log"
CONFIG_FILE="${SCRIPT_DIR}/../config/subscription.yaml"

mkdir -p "$RULES_DIR/et-open"
mkdir -p "$RULES_DIR/pt-attack"
mkdir -p "$RULES_DIR/combined"
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "========== 开始规则更新 =========="

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "*.rules" 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 0 ]; then
    log "备份现有规则..."
    cp "$RULES_DIR"/*.rules "$BACKUP_DIR/" 2>/dev/null || true
fi

ET_OPEN_URL="https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
log "下载 ET Open 规则..."
if curl -sfL "$ET_OPEN_URL" -o /tmp/et-open.tar.gz; then
    tar -xzf /tmp/et-open.tar.gz -C "$RULES_DIR/et-open" 2>/dev/null || true
    rm -f /tmp/et-open.tar.gz
    ET_COUNT=$(find "$RULES_DIR/et-open" -name "*.rules" 2>/dev/null | wc -l)
    log "ET Open 规则下载完成: $ET_COUNT 个规则文件"
else
    log "ET Open 规则下载失败"
fi

PT_ATTACK_URL="https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz"
log "下载 PT AttackDetection 规则..."
if curl -sfL "$PT_ATTACK_URL" -o /tmp/pt-attack.tar.gz; then
    tar -xzf /tmp/pt-attack.tar.gz -C "$RULES_DIR/pt-attack" 2>/dev/null || true
    rm -f /tmp/pt-attack.tar.gz
    PT_COUNT=$(find "$RULES_DIR/pt-attack" -name "*.rules" 2>/dev/null | wc -l)
    log "PT AttackDetection 规则下载完成: $PT_COUNT 个规则文件"
else
    log "PT AttackDetection 规则下载失败（可能网络问题）"
fi

CUSTOM_COUNT=$(find "$RULES_DIR/ly-custom" -name "*.rules" 2>/dev/null | wc -l)
log "自定义规则文件: $CUSTOM_COUNT 个"

TOTAL_RULES=0
for rules_file in "$RULES_DIR"/*.rules "$RULES_DIR"/**/*.rules; do
    if [ -f "$rules_file" ]; then
        RULE_COUNT=$(grep -c "^alert " "$rules_file" 2>/dev/null || echo 0)
        TOTAL_RULES=$((TOTAL_RULES + RULE_COUNT))
    fi
done
log "规则总数: $TOTAL_RULES"

cat > "$RULES_DIR/combined/active.rules" << 'HEADER'
# 流影活跃规则集
# 生成时间: TIMESTAMP_PLACEHOLDER
# 请勿手动编辑此文件
HEADER

sed -i "s/TIMESTAMP_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/" "$RULES_DIR/combined/active.rules"

for enabled in $(grep -r "enabled: true" "$CONFIG_FILE" 2>/dev/null | cut -d: -f1); do
    category=$(basename "$enabled" .enabled)
    if [ -f "$RULES_DIR/et-open/emerging-$category.rules" ]; then
        cat "$RULES_DIR/et-open/emerging-$category.rules" >> "$RULES_DIR/combined/active.rules"
        ENABLED_COUNT=$(grep -c "^alert " "$RULES_DIR/et-open/emerging-$category.rules" 2>/dev/null || echo 0)
        log "启用规则 $category: $ENABLED_COUNT 条"
    fi
done

for custom in "$RULES_DIR/ly-custom"/*.rules; do
    if [ -f "$custom" ]; then
        custom_name=$(basename "$custom")
        cat "$custom" >> "$RULES_DIR/combined/active.rules"
        CUSTOM_ENABLED=$(grep -c "^alert " "$custom" 2>/dev/null || echo 0)
        log "启用自定义规则 $custom_name: $CUSTOM_ENABLED 条"
    fi
done

ACTIVE_COUNT=$(grep -c "^alert " "$RULES_DIR/combined/active.rules" 2>/dev/null || echo 0)
log "已启用活跃规则总数: $ACTIVE_COUNT 条"

echo ""
log "========== 规则更新完成 =========="
log "活跃规则文件: $RULES_DIR/combined/active.rules"
log "下次更新时间: 明天凌晨3点"

echo "UPDATE_SUCCESS"
exit 0
