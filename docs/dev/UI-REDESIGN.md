# LyFlow 态势感知 UI 重设计

> 目标：在不杜撰功能、不伪造数据的前提下，把现有 NDR/XDR 后端能力映射成一套可下钻、
> 可处置、默认浅色的运营控制台。设计基线来自 `DEVELOPMENT_GUIDE.md` 第 6 节
> （ly_vis 风格：顶部一级导航 + 二级页签 + 高信息密度 + 浅色默认），并补充深色可切换。

## 信息架构

| 一级 | 二级页面 | 路由 |
|---|---|---|
| 核心运营 | 运营总览 | `/dashboard` |
| 核心运营 | 攻击链处置 | `/incidents` |
| 核心运营 | 事件中心 | `/events`（`/events/:uid` 直接打开详情） |
| 检测面 | 流量威胁 | `/traffic-threats` |
| 检测面 | XDR 调查 | `/xdr` |
| 检测面 | 运行威胁 | `/runtime` |
| 检测面 | 应用威胁 | `/rasp` |
| 检测面 | 全球态势 | `/situation/global` |
| 资产与处置 | 资产运维 | `/assets` |
| 资产与处置 | 响应处置 | `/response` |
| 资产与处置 | 证据库 | `/evidence` |
| 系统管理 | 规则中心 | `/rules` |
| 系统管理 | 引擎健康 | `/engines` |
| 系统管理 | 控制中心 | `/control-center` |
| 系统管理 | 安装配置 | `/install-config` |
| 系统管理 | 账户管理 | `/users` |

## 真实数据映射

| 页面/组件 | 后端来源 |
|---|---|
| 运营总览 KPI | `/api/v1/stats`、`/api/v1/unified/stats`、`/api/v1/assets/stats` |
| 态势评分/活跃链 | `/api/v1/xdr/posture`、`/api/v1/xdr/chains` |
| 攻击阶段 | `/api/v1/incidents`（Incident attack_chain）与活跃链 |
| 检测趋势 | `/api/v1/unified/events` 最近样本，按时间桶聚合 |
| 告警等级/来源 | `/api/v1/unified/stats` 的 `by_severity` / `by_source` |
| 优先处置 | `/api/v1/incidents` |
| 安全事件流 | `/api/v1/unified/events` |
| 引擎心跳 | `/api/v1/engine-health` |
| 资产与 Agent | `/api/v1/assets`、`/api/v1/assets/stats`、`/api/v1/agents` |
| 事件中心 | `/api/v2/events`、`/api/v2/events/{uid}` |
| 响应处置 | `/api/v1/response/actions`（创建/审批/回滚） |
| 证据库 | `/api/v1/evidence/bundles`、`/api/v1/evidence/artifacts` |
| 流量/运行/应用威胁 | `/api/v1/threats/{category}`、`/api/v1/component-alerts/{category}` |
| 规则中心 | `/api/v1/engine-rules`、`/api/v1/rules/sources`、`/api/v1/rules/stats` |

所有空态都有明确文案；所有危险动作都显示后端返回的真实审批/执行/回滚状态。
页面不会生成测试事件、假攻击线或虚构覆盖率。

## 视觉语言

- 默认浅色：`#eef3f8` 画布、白色数据面板、深海军蓝顶部指挥栏。
- 深色可切换：顶部月亮/太阳按钮，主题写入 `localStorage.lyflow-theme`。
- 统一 token：`frontend/src/assets/styles/command.css`，并兼容旧页面的 `--text-*` /
  `--bg-*` 变量，避免旧页面在浅色模式下仍然发黑。
- 数字使用 tabular numerals；严重度、阶段、引擎状态使用统一 badge。
- 主页面采用 `PageHeader + KPI + 数据面板 + 抽屉` 的结构；详情不离开当前工作流。
- 图表使用 ECharts：态势趋势、告警构成均来自真实 API；空数据时显示空态而不是假曲线。

## 已实现页面

- 运营总览：态势评分环、KPI、ATT&CK 阶段、检测趋势、严重度构成、来源覆盖、
  优先处置、实时事件流、引擎状态。
- 事件中心：统一查询、严重度/来源/阶段筛选、事件详情抽屉、证据与原始载荷。
- 攻击链处置：Incident 列表、阶段时间线、证据展开、响应动作创建/审批/回滚、
  证据包生成。
- 资产运维：资产 KPI、资源表、能力 chips、资产详情抽屉（资源/能力/安全计数）。
- 响应处置：动作历史、筛选、L2/L3 审批、回滚。
- 证据库：bundle 列表/下载、按事件或 Incident 生成、PCAP 对象上传。
- 引擎健康：按已安装实例聚合，可展开未安装实例；运行/离线来自真实心跳。
- 流量/运行/应用威胁：真实来源、严重度、规则、探针、详情抽屉。
- 全局态势：真实 Incident 作为攻击链来源；没有 Geo 数据时显示空态，不伪造地图线。

## 验证

- `npm run typecheck`
- `npm test`（115 tests）
- `npm run build`
- Playwright 17 页生产验收：0 console / page / network / 4xx / 5xx
- 截图证据：`/opt/lyflow/reports/G5/ui-redesign/`
- 深色主题截图：`13-dashboard-dark.png`
