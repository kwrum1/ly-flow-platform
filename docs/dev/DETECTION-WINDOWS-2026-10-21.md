# 态势、事件中心与检测窗口

- 日期：2026-10-21
- 目标：闭环后的告警不继续堆积；态势总览只统计未闭环 Incident；事件中心可检索真实检测日志；检测面默认展示最近 10 分钟并保留至少 30 天历史；默认关闭高误报的 GPL NETBIOS 规则。

## 1. Incident 默认视图

- `攻击链处置` 默认筛选 `未闭环`，服务端 `status=active` 排除 `closed`。
- 已闭环 Incident 不再出现在默认列表、态势总览的处置队列和高危计数中。
- 需要查看历史时可在状态下拉选择“全部状态”或“已关闭”。

## 2. 态势总览数据源

- 处置队列、未闭环 Incident、高危/严重、态势评分均来自 **未闭环 Incident**，不再使用 XDR 全量事件或历史累计告警。
- 检测事件数、趋势、等级、来源来自 **最近 10 分钟** 的持久化检测事件。
- 闭环 Incident 立即移出计数；历史事件仍保留在事件中心，不参与态势评分。
- 页面刷新间隔调整为 60 秒，避免数据频繁跳动。

## 3. 事件中心

- 数据源从空的 ClickHouse Event v2 表切换为持久化的 `threat_events`（检测面告警物化表）。
- 支持流量、运行时、应用防护、日志审计分类检索。
- 默认最近 10 分钟，可切换 1 小时、24 小时、30 天。
- 事件详情直接使用已加载事件，不再依赖空的 v2 详情表。

## 4. 检测面页面

- 流量威胁、运行威胁、应用威胁默认最近 10 分钟。
- 流量/运行时/应用告警优先读取持久化告警；无持久化数据时回退到实时组件告警流。
- Redis 清理覆盖 `component_alerts:v2`、`alerts:runtime`、`alerts:rasp`、`alerts:log_audit`、`telemetry:rasp`，避免流无限增长。
- PostgreSQL 日志保留默认 180 天；ClickHouse v2 事件 TTL 30 天，满足至少 30 天历史。

## 5. 流量规则优化

- `GPL NETBIOS SMB NT Trans NT CREATE oversized Security Descriptor attempt`（`et-open-2103018`）加入默认流量噪声策略，首次安装即不进入检测面、XDR 和事件中心。
- 仍可通过规则中心查看规则；该屏蔽是平台默认噪声策略，不修改 vendored 规则源。
- 新增单元测试覆盖默认关闭和真实 SMB 检测不被误伤。

## 6. 移除 XDR 调查入口

- 顶部检测面导航移除 `XDR 调查`。
- `/xdr` 旧链接重定向到 `/incidents`；`/real-time-posture` 重定向到 `/incidents`。
- 删除未使用的 `AttackWorkbench.vue` 页面。

## 7. 验证

- `server/cmd`、`server/incidentlifecycle` 测试通过（含新增流量噪声测试）。
- 前端 117 项测试、typecheck、build 通过。
- 生产 API：`status=active` 返回 0，`status=closed` 返回 6；事件中心默认 10 分钟有真实事件；30 天查询正常；GPL 规则不再返回。
- Playwright：事件中心有事件并可打开详情；攻击链默认空列表；态势总览显示最近 10 分钟与未闭环 Incident；无 console/page error。
- 生产页面巡检：18 个页面 HTTP 200、0 错误、0 横向溢出；旧路由重定向通过。
