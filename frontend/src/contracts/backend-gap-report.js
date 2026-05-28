export const backendGapReport = Object.freeze([
  {
    domain: '攻击链工作台',
    priority: 'critical',
    finding: '事故与时间线当前由 XDR 事件即时派生，缺少独立事故、证据、攻击阶段和处置状态持久化表。',
    requiredBeforeUi: '新增或启用真实事故、攻击时间线、证据链持久化，并保证接口按持久化结果返回。',
    source: 'server/cmd/main.go incidentsHandler timelineHandler deriveIncidents buildTimeline',
  },
  {
    domain: '统一事件',
    priority: 'critical',
    finding: '统一事件主要从 Redis events:xdr、alerts:list 和 Postgres events 聚合，Postgres 回退字段较少，message/rule/evidence 语义不足。',
    requiredBeforeUi: '统一事件需要稳定事件详情、行为上下文、实体、原始引用、证据和中文可读描述字段。',
    source: 'server/cmd/main.go loadXDREvents mapUnifiedEventFromXDR',
  },
  {
    domain: 'RASP 与 Runtime',
    priority: 'critical',
    finding: 'RASP 模块部分 handler 已读取 Redis alerts:rasp 和保护状态，但模块包内仍有内存事件模型；Runtime 独立查询与控制接口不完整。',
    requiredBeforeUi: 'RASP 事件、防护状态、阻断记录、Runtime 行为、日志审计结果必须持久化并提供查询接口。',
    source: 'server/cmd/main.go rasp*Handler server/modules/rasp/handler.go',
  },
  {
    domain: 'Trace 分析',
    priority: 'high',
    finding: 'Trace SQL 表存在，但当前全局 traceHandler 需要确认是否接入真实 DB manager，而不是空 SessionManager。',
    requiredBeforeUi: 'Trace 会话、事件、序列、IOC 和 MITRE 信息必须从持久化表返回。',
    source: 'server/sql/trace_tables.sql server/modules/trace/handler.go server/cmd/main.go trace*Handler',
  },
  {
    domain: '资产与 Agent 管理',
    priority: 'high',
    finding: 'Agent 注册、心跳、列表和详情已有 Postgres 路径，但策略版本、配置确认、漂移、能力状态、任务队列呈现还不足以支撑商业控制面。',
    requiredBeforeUi: '补齐策略状态、能力状态、漂移状态、配置确认、任务下发/结果和性能状态 API。',
    source: 'server/cmd/main.go agent*Handler scripts/init-db.sql agents agent_tasks',
  },
  {
    domain: '检测规则中心',
    priority: 'high',
    finding: '规则列表、分类、统计、更新、测试接口存在，但商业 UI 需要干运行差异、确认激活、版本、来源、命中计数和回滚状态。',
    requiredBeforeUi: '补齐规则同步状态、版本差异、确认激活、命中统计和审计记录。',
    source: 'server/cmd/main.go rules*Handler scripts/init-db.sql rules',
  },
  {
    domain: '流量分析模式',
    priority: 'high',
    finding: '文档要求启停流量分析和切换监听网卡；当前 API 契约中缺少明确的操作与状态接口。',
    requiredBeforeUi: '新增流量分析模式状态、启停、网卡切换、热加载结果和错误原因接口。',
    source: '.sisyphus/plans/lyflow-layered-architecture-development.md Functional QA Decisions',
  },
])

export function criticalBackendGaps() {
  return backendGapReport.filter((item) => item.priority === 'critical')
}
