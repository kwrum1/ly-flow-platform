export const backendGapReport = Object.freeze([
  {
    domain: '现场 Agent 认证',
    priority: 'critical',
    finding: '静态 amd64/arm64 Agent 和当前宿主机链路已验收，但尚无独立 CentOS 7、Linux 3.10 与 ARM 实机长期运行证据。',
    requiredForRelease: '完成仅开放 HTTPS 的 72 小时矩阵，覆盖断网补传、升级回滚、auditd fallback、AF_PACKET、YARA 和 RASP。',
    source: 'agent/cmd docs/zh/后续工作计划.md',
  },
  {
    domain: '检测质量基线',
    priority: 'critical',
    finding: '多引擎检测与规则生命周期已打通，但尚未用持续标注样本量化召回率、误报率、重复率与吞吐上限。',
    requiredForRelease: '建立版本化 corpus 和发布准入线，规则更新不达标时自动拒绝或回滚。',
    source: 'security-engine/engine server/cmd docs/zh/后续工作计划.md',
  },
  {
    domain: 'RASP 兼容矩阵',
    priority: 'critical',
    finding: 'Python RASP 检测、事件、策略签名和 protect 模式已验证；真实业务框架兼容与误伤数据仍不足。',
    requiredForRelease: '明确支持语言和框架，在真实应用验证检测点、阻断、超时、降级和回滚；Java 继续保持实验状态。',
    source: 'agent/rasp/python server/cmd docs/zh/后续工作计划.md',
  },
  {
    domain: '安全运营权限',
    priority: 'high',
    finding: 'Incident 生命周期与审计可用，但大部分业务页面仍只允许 admin，分析员工作流尚未完整。',
    requiredForRelease: '补齐 analyst/viewer 页面权限、分派、评论、合并、抑制和 SLA。',
    source: 'frontend/src/router/index.js server/cmd/incident_lifecycle.go',
  },
  {
    domain: '自动响应边界',
    priority: 'high',
    finding: 'XDR 会生成候选处置建议，但当前不执行自动隔离或封禁。',
    requiredForRelease: '如需执行响应，先实现人工审批、目标绑定、幂等、超时、回滚、审计和失联保护。',
    source: 'server/advisoryresponse server/xdr',
  },
])

export function criticalBackendGaps() {
  return backendGapReport.filter((item) => item.priority === 'critical')
}
