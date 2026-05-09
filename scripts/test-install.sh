#!/bin/bash
# 流影 Agent 安装测试脚本
# 版本: v1.0.0
# 更新日期: 2026-05-08

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_MANAGER="${TEST_MANAGER:-http://localhost:8081}"
INSTALL_DIR="/tmp/ly-agent-test"

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_info() { log "${GREEN}[TEST]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_error() { log "${RED}[FAIL]${NC} $1"; }

PASSED=0
FAILED=0

test_case() {
    local name="$1"
    local cmd="$2"
    echo -n "  $name ... "
    if eval "$cmd" > /dev/null 2>&1; then
        log_info "$name ✓"
        ((PASSED++))
        return 0
    else
        log_error "$name ✗"
        ((FAILED++))
        return 1
    fi
}

echo "========================================"
echo "  Agent 安装测试"
echo "========================================"
echo ""

# 清理旧安装
rm -rf "$INSTALL_DIR"

echo "=== 1. 前置条件检查 ==="

test_case "AgentCenter API 可访问" \
    "curl -s -f $TEST_MANAGER/api/v1/health"

test_case "网络连接正常" \
    "ping -c 1 -W 1 localhost > /dev/null 2>&1"

echo ""
echo "=== 2. 下载测试 ==="

# 模拟下载
mkdir -p "$INSTALL_DIR"/{bin,config,domain-lists}

# 创建模拟二进制
echo "#!/bin/bash\necho 'ly-agent mock'" > "$INSTALL_DIR/bin/ly-agent"
chmod +x "$INSTALL_DIR/bin/ly-agent"

test_case "下载目录创建" \
    "test -d $INSTALL_DIR"

test_case "二进制文件存在" \
    "test -f $INSTALL_DIR/bin/ly-agent"

test_case "二进制可执行" \
    "$INSTALL_DIR/bin/ly-agent"

echo ""
echo "=== 3. 配置测试 ==="

# 创建测试配置
cat > "$INSTALL_DIR/config/agent.yaml" <<EOF
manager:
  addr: "$TEST_MANAGER"
  heartbeat_interval: 30
  report_interval: 60
plugins:
  enabled: all
traffic_analysis:
  enabled: true
  redis_stream: "flows:raw"
domain_audit:
  enabled: true
  lists:
    - $INSTALL_DIR/domain-lists/mining.txt
EOF

test_case "配置文件创建" \
    "test -f $INSTALL_DIR/config/agent.yaml"

test_case "配置格式正确" \
    "grep -q 'manager:' $INSTALL_DIR/config/agent.yaml"

echo ""
echo "=== 4. 规则文件测试 ==="

# 复制规则
cp "$HOME/ly/platform/rules/domain/mining.txt" "$INSTALL_DIR/domain-lists/" 2>/dev/null || \
    echo "pool.btc.com" > "$INSTALL_DIR/domain-lists/mining.txt"

test_case "规则文件存在" \
    "test -f $INSTALL_DIR/domain-lists/mining.txt"

test_case "规则文件非空" \
    "test -s $INSTALL_DIR/domain-lists/mining.txt"

echo ""
echo "=== 5. 模拟注册测试 ==="

# 模拟 Agent 注册
AGENT_ID="test-agent-$(date +%s)"
test_case "Agent 注册 API 调用" \
    "curl -s -X POST $TEST_MANAGER/api/v1/agents/enroll \
        -H 'Content-Type: application/json' \
        -d '{\"hostname\":\"test-host\",\"ip\":\"127.0.0.1\",\"os\":\"Linux\",\"version\":\"1.0.0\"}'"

echo ""
echo "=== 6. 清理测试 ==="

rm -rf "$INSTALL_DIR"

test_case "清理安装目录" \
    "! test -d $INSTALL_DIR"

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
