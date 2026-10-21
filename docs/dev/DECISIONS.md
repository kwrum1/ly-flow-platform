# LyFlow 决策记录

> 记录非显而易见的技术/产品选择。小决策按默认规则选择后也记录在这里，避免反复讨论。

## 默认决策规则

1. 成本相同选维护成本低的。
2. 都能实现选成熟度高、许可清晰的。
3. UI 不确定选浅色、信息密度高、不引入新框架。
4. 性能不确定选可观测、可回滚的保守值。
5. 规则不确定选 ET Open / OpenRASP / CRS / Nuclei / CISA KEV 等许可清晰的上游。
6. 部署不确定选 `lean` profile；`full-private` 只在明确需要 Elkeid HUB 时启用。
7. 任何涉及自动阻断的决策，默认人工审批。
8. 任何涉及删除数据/重装的决策，默认先快照 + 人工确认。

## D-001 编译机与测试机硬边界

- 日期：2026-10-19
- 决策：所有编译在 `BUILD_HOST`，所有集成/E2E 在 `TEST_HOST`。
- 原因：环境一致、可复现、避免测试机污染源码。
- 替代方案：本地编译；被否，因为依赖/内核/架构不一致。
- 后果：需要维护私有环境文件和 SSH key。

## D-002 网络探针双引擎

- 日期：2026-10-19
- 决策：`ly_probe` 主抓包/流/L7 指纹，Suricata 作为签名协处理。
- 原因：`ly_probe` 抓包与指纹强，但规则表达力/Web 检测不足；Suricata 规则生态成熟。
- 替代方案：只用 `ly_probe`；被否，Web/Exploit 覆盖不足。
- 后果：需要双引擎规则中心与 capture doctor。

## D-003 默认 lean profile，Elkeid HUB 私有

- 日期：2026-10-19
- 决策：默认 `lean`；Elkeid HUB/Console/HIDS-RASP 规则只进 `private/elkeid/`，不进公开包。
- 原因：成本低、许可合规。
- 替代方案：Elkeid 全套默认；被否，资源占用高且许可限制分发。
- 后果：需要 Agent 门面统一 Wazuh/Elkeid。

## D-004 UI 复刻 ly_vis 排版，浅色默认

- 日期：2026-10-19
- 决策：沿用 `ly_vis` 的顶部导航/页签/信息密度，Vue 3 + ECharts 重做；浅色默认，深色可切换。
- 原因：用户明确喜欢其排版与展示效果，但不需要暗色风格；Vue 复用现有前端栈成本最低。
- 替代方案：直接复用 React 代码；被否，GPL + 重写成本高。
- 后果：需要新 UI shell + ATT&CK 组件。

## D-005 RASP 引擎按运行时分工

- 日期：2026-10-19
- 决策：Java/PHP 用 OpenRASP；Python/Go/Node 用 Elkeid RASP；一个运行时只用一个引擎。
- 原因：OpenRASP 的 Java/PHP 规则最成熟；Elkeid 覆盖其余语言。
- 替代方案：单一引擎覆盖全部；被否，规则或语言覆盖不足。
- 后果：Agent 需要管理多探针，但不能在同一运行时双插桩。

## D-006 RASP 规则不人工运营

- 日期：2026-10-19
- 决策：自动同步 OpenRASP/CRS/Nuclei/CISA KEV；不逐条编写/调优。
- 原因：用户不打算运营规则；开源 RASP 规则生态很薄。
- 替代方案：自建规则团队；被否，成本高。
- 后果：接受上游覆盖边界，产品文档必须写明。

## D-007 查询层迁移 ClickHouse/PostgreSQL

- 日期：2026-10-19
- 决策：不复用 `ly_server` 的 MariaDB 查询层；事件/会话进 ClickHouse，配置/Incident 进 PostgreSQL。
- 原因：查询死机、扩展性差。
- 替代方案：优化 MariaDB；被否，架构方向不对。
- 后果：需要迁移/双写/查询治理。

## D-008 测试 VM 未就绪时的处理

- 日期：2026-10-19
- 决策：`10.1.18.124` 是 ESXi 宿主机；现有 `mydist-lab` 仅 2C/2G，不作为 LyFlow 测试机。先做不依赖测试 VM 的 T0.1–T0.5，同时准备专用测试 VM。
- 后续：已创建并启动专用测试 VM `lyflow-test`（Ubuntu 24.04.5，6C/8G/120G，Docker 29.1.3 + Compose 2.40.3，静态 IP 见私有环境文件）；编译机 root SSH key 已注入。
- 原因：避免在资源不足的 VM 上得出错误结论。
- 替代方案：直接在 `mydist-lab` 上测试；被否，资源不足且用途不符。
- 后果：集成/E2E 任务现在可以在 `lyflow-test` 上执行；ESXi 快照待 API 恢复后补。


## D-009 v2 Ingest 使用 agent credential + ClickHouse 直写

- 日期：2026-10-19
- 决策：`/api/v2/ingest/events` 使用现有 `ingestionauth` 的 agent credential；校验后直接写入 ClickHouse `lyflow_events_v2`。
- 原因：复用现有认证与审计链路；v2 事件是追加写，不需要走 v1 的双写迁移状态机。
- 替代方案：新开独立 token；被否，增加一套认证与轮换成本。
- 后果：Vector/Wazuh/Elkeid 接入时需要配置一个 agent/sensor 身份；后续在部署文档中说明。


## D-010 响应动作扩张并关闭旧响应入口

- 日期：2026-10-19
- 决策：保留 /api/v1/response/actions 作为唯一执行入口；关闭旧 candidate/policy/advisory 路由。新增 block_ip、process_kill、file_delete/file_restore、account_disable/account_enable、isolate_host/host_unisolate、namespace_isolate/namespace_restore。
- 原因：用户明确要求推进响应动作并关闭旧响应；旧 candidate 接口只读，继续保留会造成双入口误解。
- 安全：破坏性动作由 RESPONSE_ENABLE_* 默认关闭；L3 必须不同认证管理员审批；测试使用 TEST-NET 目标。
- 回滚：process_kill 不可逆；其余动作都有对应 rollback。

## D-011 证据对象存储使用 SeaweedFS filer

- 日期：2026-10-19
- 决策：证据字节写入 SeaweedFS filer；bundle/artifact 元数据由 ly-server 本地持久化。默认 filesystem backend，Compose evidence profile 启用了 filer。
- 原因：SeaweedFS Apache-2.0、单节点低成本、HTTP filer 可直接接入，无需引入 S3 SDK。
- 后果：离线发布需要固定 SeaweedFS image digest；对象和元数据要一起备份。

## D-012 关闭 Event v1 外部兼容路径

- 日期：2026-10-19
- 决策：移除 /api/v1/events、/api/v1/security-events、/api/v1/event-migration 外部路由；Dashboard 改用 /api/v1/unified/events，事件页使用 /api/v2/events。
- 原因：用户明确要求关闭无意义兼容路径；Event v2 已是主链。
- 后果：内部迁移代码暂时保留用于已有数据一致性，不再对外暴露。

## D-013 放弃 Windows 端

- 日期：2026-10-19
- 决策：停止构建/下载/安装 Windows Agent，删除 Windows 专用 Agent 文件；仅保留 Linux amd64/arm64。
- 原因：用户明确要求砍掉 Windows 端；当前测试与采集面全部为 Linux。
- 后果：安装页、离线包、服务端下载和文档均不再提供 Windows。
## D-014 删除 legacy DPI Engine
- 日期：2026-10-21
- 决策：删除 dpi-engine/ legacy 模块、legacy compose profile、旧 DPI 规则/编译预览、构建/QA 引用和 UI 中的 DPI Engine 卡片/筛选；新流量告警统一由 lyprobe/统一安全引擎处理。
- 原因：该模块仅用于旧 flows:raw 迁移对账，不属于默认生产栈，且已与 LyFlow DPI/探针职责重叠；用户明确要求从源码和 UI 删除过期设计。
- 兼容：pkg/contracts 保留历史 dpi_engine 事件源枚举与 fixture，避免旧事件读取失败；新事件不再产生 dpi_engine 源。
- 后果：不再构建 ly-flow/dpi-engine 镜像；旧 DPI 规则目录和迁移 profile 不再随仓库发布。
