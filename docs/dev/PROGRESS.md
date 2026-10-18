# LyFlow 开发进度

> 每个 Task 完成后追加一条记录：日期 / Task / 变更 / 测试 / 风险 / 回滚。  
> 更细的任务状态见 `WORKQUEUE.md`。

## 2026-10-19

### T0.0 环境接入与基线（IN_PROGRESS）

- 编译机已通过 SSH 接入，确认：
  - OS：Ubuntu 25.10
  - CPU：40 vCPU
  - 内存：62 GiB
  - 磁盘：`/` 295G，已用 79%，剩余约 62G
  - Docker：29.2.1
  - Go：默认 `1.24.4`；`/opt/go1.26-clean/bin/go` 为 `1.26.0`
  - Node：v22.22.2
  - 仓库：`/root/ly-flow-platform`（原工作区，保留）
  - 新工作区：`/opt/lyflow/src`（worktree，分支 `feat/lyflow-v2`，基线 `f02f000`）
- 测试环境：
  - `10.1.18.124` 是 ESXi 8.0.3 宿主机，不是 Linux 测试 VM。
  - 现有 VM：`mydist-lab`，2 vCPU / 2 GiB，双网卡（VM Network / WAN-lab），guest tools 未运行。
  - 结论：`mydist-lab` 不适合作为 LyFlow 全栈测试机；需要新建/准备专用 Linux 测试 VM（建议 8 vCPU / 16–32 GiB / 200G+）。
- 风险：
  - Go 版本与 `go.work` 要求（1.26.5）不一致，需要 `GOTOOLCHAIN=auto` 或安装 1.26.5。
  - 编译机磁盘剩余 62G，构建大镜像前需清理或扩容。
  - 测试 VM 尚未就绪，M0 的文档/契约任务可继续，集成/E2E 任务需等待。
- 回滚：仅创建目录/worktree，无业务变更。

### T0.1 建立开发规范与进度文件（DONE）

- 新增：
  - `AGENTS.md`
  - `docs/dev/WORKQUEUE.md`
  - `docs/dev/PROGRESS.md`
  - `docs/dev/DECISIONS.md`
  - `docs/dev/ENVIRONMENT.md`
  - `docs/adr/000-template.md`
- 测试：Markdown 链接检查（待补脚本）。
- 风险：无。
- 回滚：删除新增文档即可。

### T0.2 Feature flags 与配置（DONE）

- 新增服务端 `FeatureFlags`：
  - `EVENT_SCHEMA_V2_ENABLED`
  - `QUERY_V2_ENABLED`
  - `CORRELATION_V2_ENABLED`
  - `AGENT_FACADE_ENABLED`
  - `RESPONSE_APPROVAL_ENABLED`
  - 默认全部 `false`；接受 `1/true/yes/on`。
- 新增前端 `frontend/src/config/features.js`：
  - `VITE_UI_SHELL_V2_ENABLED`
  - `VITE_QUERY_V2_ENABLED`
  - `VITE_ATTACK_V2_ENABLED`
  - `VITE_AGENT_FACADE_ENABLED`
  - `VITE_RESPONSE_APPROVAL_ENABLED`
  - 默认全部 `false`。
- 新增 `frontend/.env.example`。
- 测试：
  - `cd server && GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go test ./cmd -run 'TestLoadFeatureFlags' -count=1` → `ok`
  - `cd frontend && npm test -- src/config/features.test.js` → 3 passed
- 风险：
  - 服务端仍强制 `GOTOOLCHAIN=auto` + `GOSUMDB=sum.golang.org` 下载 Go 1.26.5；后续在 CI/脚本中固化。
- 回滚：删除新增文件并回退 `server/cmd/main.go` 的 `Features` 字段。

### T0.3 Event v2 契约（DONE）

- 新增 `pkg/contracts/security_event_v2.go`：
  - `SecurityEventSchemaV2 = "lyflow.security_event.v2"`
  - `AttackStage` 与 `StageForTactic`（ATT&CK v16 战术映射）
  - `EventV2`、`Entities`、`Detection`、`EvidenceRef`、`RawRef`
  - `Validate()`：身份、来源、时间、实体、严重度、置信度、ATT&CK、证据、原始摘要、质量标记、治理
  - `FromCanonicalV1()`：v1 → v2 适配，合成 Asset 实体并从 tactic 推导 stage
- 新增 `pkg/contracts/security_event_v2_test.go`：正常路径 + 缺字段/非法枚举/非法置信度/证据缺哈希/重复质量标记/治理缺失 + v1 适配。
- 测试：`cd pkg && GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go test ./contracts -count=1` → `ok`
- 风险：v2 的存储 schema 尚未落地，T0.4 处理。
- 回滚：删除两个新增文件即可，不影响 v1。

### T0.4 证据模型与存储 schema（DONE）

- ClickHouse 新增：
  - `lyflow_events_v2`：按 `toDate(event_at)` 分区，排序键 `(event_at, source, event_type, asset_id)`，TTL 30 天。
  - `lyflow_events_1m` / `lyflow_events_1h`：SummingMergeTree 聚合视图。
- PostgreSQL 新增：
  - `lyflow_evidence`：evidence_id、event_uid、incident_id、stage、type、ref、sha256、size、ttl、redaction、created_at、expires_at。
  - `lyflow_incident_evidence`：incident_id + evidence_id 多对多，级联删除。
  - `event_uid`、`incident_id` 索引。
- 迁移版本：
  - PostgreSQL 6–9。
  - ClickHouse 4–6。
- 测试：`cd server && GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go test ./analytics -count=1` → `ok`
- 风险：
  - 尚未在真实 ClickHouse/PostgreSQL 上执行迁移（测试 VM 未就绪）；T0.5/后续集成测试补。
  - 迁移是 additive，回滚需手动 `DROP TABLE/INDEX`；生产执行前先备份。
- 回滚：按版本反向 drop 新表/索引，不影响旧表。

### T0.5 CI/测试脚本与许可检查（DONE）

- 新增 `scripts/dev/test-all.sh`：`fast` 模式（pkg + server 纯测试 + 前端 typecheck/test/lint + 策略检查）和 `full` 模式。
- 新增策略脚本：
  - `check-secrets.sh`：拦截已知密码、私钥、未忽略的 `.env`。
  - `check-private.sh`：`private/` 不得入库；默认 compose 不得引用 Elkeid HUB/Console。
  - `check-licenses.sh`：拦截已知 AGPL/SSPL 依赖；有 `go-licenses`/`license-checker` 时跑 SPDX 报告。
- 新增 `.github/workflows/ci.yml`（fast checks）。
- `.gitignore`/`.dockerignore` 增加 `private/` 边界。
- 重新生成 `docs/generated/event-contract-inventory.json`。
- 测试：`bash scripts/dev/test-all.sh fast` → `all fast checks passed`
- 已知：前端 lint 有 1442 个 warning、0 error（历史问题，后续单独清理）。
- Gate G1：`READY_FOR_REVIEW`。
- 回滚：删除脚本/工作流并恢复 `.gitignore`/`.dockerignore`。

### T1.1 Ingest v2（DONE）

- 新增 `server/ingestv2/handler.go`：
  - `POST /api/v2/ingest/events`，agent credential 认证。
  - 批量上限 1000，body 上限 4 MiB。
  - 默认填充 tenant/correlation/asset/ingested_at；payload SHA-256 自动计算。
  - 校验 `contracts.EventV2`，返回 `{code:0,data:{accepted}}`。
- 新增 `server/analytics/clickhouse_v2.go`：`InsertEventsV2` 写入 `lyflow_events_v2`。
- `StorageEventRuntime` 新增 `WriteEventsV2`。
- 路由注册：
  - `route_registry_data.go`：新增 `/api/v2/ingest/events`，agent-credential。
  - `route_registry_methods.go`：POST。
  - `route-api-contract.json`：117 条路由，更新 digest。
- 前端契约测试改为从 `registry.mountedPathCount` 读取，不再硬编码 116。
- 测试：
  - `go test ./ingestv2 ./analytics` → ok
  - `go test ./cmd -run 'TestRouteAPIContract|TestLoadFeatureFlags'` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：尚未在测试 VM 上做真实 HTTP + ClickHouse 集成；T1.2/测试 VM 就绪后补。
- 回滚：移除路由和 handler，保留 v2 表不影响旧链路。

### T1.2 Query v2 + 查询治理（DONE）

- 新增 `server/analytics/query_v2.go`：
  - `QueryEventsV2`：时间范围、source/event_type/severity/stage/asset_id/technique_id 过滤，游标分页，`event_at DESC, event_uid DESC`。
  - `GetEventV2`：单事件详情 + 证据 JSON。
  - 查询治理：默认 24h、最大 30 天、默认 50 条、最大 500 条。
  - ClickHouse 字符串转义 + 时间格式。
- 新增 `server/queryv2/handler.go`：
  - `GET /api/v2/events`
  - `GET /api/v2/events/{id}`
  - 统一错误/成功 envelope，游标编解码。
- 路由注册与契约更新：119 条路由。
- 测试：
  - `go test ./queryv2 ./analytics` → ok
  - `go test ./cmd -run 'TestRouteAPIContract'` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：真实 ClickHouse 集成/分页边界待测试 VM；当前只有单元测试。
- 回滚：移除两条 v2 路由和 query 包，不影响旧 API。

### T1.3 新 UI shell（DONE）

- 新增 `frontend/src/app/shell/AppShellV2.vue`：
  - ly_vis 风格：50px 顶部一级导航 + 45px 二级页签 + 20px 内容区。
  - 浅色默认；品牌、统一搜索、时间、用户、退出。
  - 响应式：窄屏隐藏搜索/时钟，导航可横向滚动。
- 新增 `frontend/src/app/shell/navigation.js`：按角色过滤、当前分组、页签计算。
- `frontend/src/app/AppShell.vue` 通过 `features.uiShellV2` 切换新旧 shell；默认关闭。
- 测试：
  - `npm run typecheck` → ok
  - `npm test -- src/app/shell/navigation.test.js` → 5 passed
  - `npm run build` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：尚未做浏览器截图/可访问性验收；T1.4–T1.6 页面接入时补。
- 回滚：关闭 `VITE_UI_SHELL_V2_ENABLED` 即回到旧 shell。

### 维护：编译机磁盘清理（2026-10-19）

- 清理 `/root/ly-flow-platform` 的旧生成物：`release/`、`images/`、`node_modules/`、`frontend/dist/`、`server/dist/`、旧编译产物、`rules/compiled/live/` 等。
- 删除旧 takeover 备份目录 `ly-flow-takeover-archive-20260730.*`。
- 清理 Docker build cache/悬空镜像。
- 结果：根分区可用空间从约 60G 提升到约 116G（59% used）。
- 未删除：`/root/ly-flow-platform/.git`、当前 worktree `/opt/lyflow/src`、`/opt/lyflow/repo.git`、签名目录、其他项目目录。

### T1.4 总览页（DONE）

- 新增 `frontend/src/api/v2.js`：`/api/v2/events` 列表/详情。
- 新增 `frontend/src/views/situation/OverviewV2.vue`：
  - KPI：24h 新增、高危/严重、在线 Agent、Incident。
  - ATT&CK 阶段分布、数据来源覆盖。
  - 最近事件表格；加载/错误/空态；无数据不伪造。
- `GlobalSituation.vue` 通过 `features.attackV2` 切换到新总览；默认关闭。
- 测试：`npm run typecheck`、`npm run build`、`bash scripts/dev/test-all.sh fast` 均通过。
- 风险：阶段/来源分布基于最近 100 条样本，T2.6 改为服务端聚合。
- 回滚：关闭 `VITE_ATTACK_V2_ENABLED`。

### T1.5 事件中心 + 详情 + 证据面板（DONE）

- 新增 `frontend/src/views/events/EventsV2.vue`：
  - 时间/来源/严重度/阶段筛选。
  - 游标分页 + 加载更多。
  - 事件表格：时间/来源/类型/阶段/严重度/资产/规则/置信度。
  - 详情抽屉：实体字段、证据列表（type/ref/sha256/size）、原始载荷、原始来源。
- 新增 `EventsRoute.vue`：`features.attackV2` 开时用新事件中心，否则保留旧会话查询。
- 导航 `/events` 改为“事件中心”；新增 `frontend/src/domain/attack-labels.js`。
- 测试：`npm run typecheck`、`npm run build`、`bash scripts/dev/test-all.sh fast` 均通过。
- 风险：证据下载/原始 JSON 复制待 T1.6/T2.5 完善；真实数据联调待测试 VM。
- 回滚：关闭 `VITE_ATTACK_V2_ENABLED`。

### T1.6 统一搜索（DONE）

- 后端 `EventV2Query` 增加 `Query` 字段；ClickHouse 对 `src_ip/dst_ip/asset_id/user_id/process_exe/file_hash/rule_id/event_type` 做 `positionCaseInsensitive` 匹配。
- `GET /api/v2/events?q=` 接入关键词。
- 前端事件中心增加关键字输入；顶部全局搜索跳转 `/events?q=...` 后自动带入。
- 测试：
  - `go test ./queryv2 ./analytics` → ok
  - `npm run typecheck` / `npm run build` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：关键词搜索是大小写不敏感子串匹配，未做分词/相关性排序；后续可接 ClickHouse 全文索引。
- 回滚：移除 `q` 参数与输入即可。

### T2.1 ATT&CK 元数据与映射（DONE）

- 新增 `pkg/attack/mapping.go`：
  - ATT&CK v16 战术表 + 常用技术表（含子技术）。
  - 从 Suricata/Wazuh 规则 `metadata`、tags（`attack.technique:`/`attack.tactic:`/`mitre:`）解析。
  - 技术已知时自动推导战术；战术映射到 `contracts.AttackStage`。
  - 支持规则 ID fallback 表；未知时返回 `unknown`，不猜测。
  - 置信度：显式技术 0.8、技术+战术 0.8、仅战术 0.6、fallback 由表定义。
- 新增 `pkg/attack/mapping_test.go`：metadata、tag、tactic-only、fallback、unknown、大小写查找。
- 测试：`cd pkg && go test ./attack -count=1` → ok
- 风险：fallback 表目前为空；后续按规则库逐步补充并评审，避免猜技术 ID。
- 回滚：删除 `pkg/attack` 即可。

### T2.2 阶段状态机（DONE）

- 新增 `server/correlation/stage/state.go`：
  - 阶段顺序：Recon → Initial Access → … → Impact。
  - 初始/推进/同阶段/回退/时间窗/跳阶/低置信度/多源佐证/重复事件处理。
  - 证据列表、来源集合、阶段置信度、整体置信度、快照。
  - 默认：时间窗 24h、最小置信度 0.5、最大跳阶 2；可配置 `RequireCorroboration`。
- 新增 `server/correlation/stage/state_test.go`：推进、回退、同阶段、跳阶、时间窗、低置信度、多源门控、重复/未知、快照隔离。
- 测试：`cd server && go test ./correlation/stage -count=1` → ok
- 风险：状态机目前是内存态，尚未接 ClickHouse/实体图；T2.3/T2.4 接入。
- 回滚：删除 `server/correlation/stage` 即可。

### T2.3 实体图与关联（DONE）

- 新增 `server/correlation/graph/graph.go`：
  - 节点：asset/user/process/file/ip/domain。
  - 边：spawn/write/connect/login/resolve。
  - 事件去重、邻接表、BFS 最短路径、连通分量。
- 新增 `server/correlation/graph/graph_test.go`：实体节点、资产→文件路径、用户→资产登录、断链分量、重复事件去重。
- 测试：`cd server && go test ./correlation/graph -count=1` → ok
- 风险：当前为进程内图，未做持久化/时间滑窗；T2.4/T2.5 接入 Incident 与前端。
- 回滚：删除 `server/correlation/graph` 即可。

### T2.4 Incident API/生命周期（DONE）

- 新增 `server/correlation/incident/builder.go`：
  - 复用 `server/correlation/stage` 与 `server/correlation/graph`，把事件序列转成 `incidentlifecycle.Candidate`。
  - 自动生成 Incident ID、摘要、最高严重度、首末时间、证据列表。
  - 支持从 tactic 推导 stage；无 stage 的事件不生成 Incident。
  - 兼容现有 `incidentlifecycle.NewActiveSnapshot`。
- 生命周期/API 复用现有 `server/incidentlifecycle`（open/triaged/processing/resolved/closed、审计、抑制）。
- 新增 `server/correlation/incident/builder_test.go`：3 段链、空输入、无 stage、tactic 推导。
- 测试：`cd server && go test ./correlation/incident -count=1` → ok
- 风险：builder 尚未挂到实时消费/持久化循环；T2.5 前端先用现有 v1 Incident API。
- 回滚：删除 `server/correlation/incident` 即可。

### T2.5 攻击链/时间线 UI（DONE）

- 新增 `frontend/src/views/incidents/IncidentTimelineV2.vue`：
  - 左侧 Incident 列表，右侧详情。
  - 阶段时间线：按 `stage_groups`（或 `stages`）分组，证据挂在阶段下。
  - 证据矩阵、源/受害 IP、资产、建议、状态流转。
- 新增 `IncidentRoute.vue`：`features.attackV2` 开时用新页面，否则保留旧 `Incidents.vue`。
- 路由 `/incidents` 改为包装器；路由数量不变。
- 补充 `server/ingestv2/handler.go` 的 native fixture 绑定，重新生成 event inventory。
- 测试：
  - `npm run typecheck` / `npm run build` → ok
  - `go test ./contracts ./eventinventory` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：证据下载/原始 JSON 展开待后续；真实数据联调待测试 VM。
- 回滚：关闭 `VITE_ATTACK_V2_ENABLED`。

### T2.6 ATT&CK 覆盖率（DONE）

- 新增 `pkg/attack/coverage.go`：
  - 基于 ATT&CK 表统计已知战术/技术、观测技术数、覆盖率。
  - 战术维度聚合，技术按命中次数排序；未知技术忽略。
- 新增 `frontend/src/domain/attack-matrix.js`：
  - 阶段顺序、阶段/技术聚合、未映射归入 unknown。
- 总览页新增“ATT&CK 覆盖（样本）”矩阵：阶段 × 技术 chip，显示样本命中数。
- 测试：
  - `go test ./attack` → ok
  - `npm test -- src/domain/attack-matrix.test.js` → 3 passed
  - `npm run typecheck` / `npm run build` → ok
  - `bash scripts/dev/test-all.sh fast` → all fast checks passed
- 风险：当前矩阵基于最近 100 条样本，不是全量覆盖率；后续接服务端聚合。
- 回滚：移除矩阵组件/覆盖率包。

### T2.7 关联验证（DONE）

- 新增 `server/correlation/incident/validation_test.go`：
  - Web Exploit → Execution → C2。
  - Credential Access → Discovery → Lateral Movement。
  - WebShell → Persistence → Privilege Escalation。
- 每条链校验：阶段、证据数、技术数、最高严重度。
- 测试：`cd server && go test ./correlation/incident -count=1` → ok
- Gate G3：`READY_FOR_REVIEW`；真实 PCAP/EVTX 回放待测试 VM。
- 回滚：删除验证测试即可。

### T3.1 `ly-agent` supervisor（DONE）

- 新增 `agent/supervisor/supervisor.go`：
  - 组件生命周期（starting/running/restarting/stopped/failed）。
  - 指数退避重启、最大重启次数、上下文取消、状态快照。
- 新增 `agent/supervisor/supervisor_test.go`：正常停止、flaky 重启、永久失败、状态顺序。
- 测试：`cd agent && go test ./supervisor -count=1` → ok
- 风险：尚未接入具体组件（Elkeid/Wazuh/YARA/RASP）；T3.2–T3.5 逐步接入。
- 回滚：删除 `agent/supervisor` 即可。

### T3.2/T3.3 进程组件与 Elkeid/Wazuh Provider（REVIEW）

- 新增 `agent/supervisor/process.go`：
  - 外部长驻进程生命周期、stdout/stderr 行日志、取消、非零退出错误、Probe。
- 新增 `agent/supervisor/providers/elkeid`：
  - 默认 `/opt/elkeid/agent/elkeid-agent`，可配置路径/参数/环境。
- 新增 `agent/supervisor/providers/wazuh`：
  - 默认 `/var/ossec/bin/wazuh-agentd`，可配置。
- 测试：
  - `cd agent && go test ./supervisor/... -count=1` → ok
  - 覆盖：正常退出、非零退出、取消、日志、Probe、默认/显式路径。
- 状态：`REVIEW`。进程监管/Provider 已就绪；**事件规范化、注册/心跳、配置下发仍待接入**，因此不标记 DONE。
- 回滚：删除 provider/process 文件即可。

### 测试 VM 建成（T0.0 DONE）

- 在 ESXi `10.1.18.124` 的 `data` 存储创建 `lyflow-test`：
  - Ubuntu 24.04.5 cloud image（官方 VMDK，120G 虚拟盘）。
  - 6 vCPU / 8 GiB / 根分区约 113G 可用。
  - 静态 IP：见私有环境文件；网关 `10.1.18.1`。
  - Docker 29.1.3 + Compose v2.40.3。
  - 编译机 root SSH key 已注入；root 密码已设置。
- 关键修复：
  - ESXi VMX 使用 `guestOS = "ubuntu-64"`、`firmware = "bios"`、`lsilogic` + PCI bridges。
  - 官方 VMDK 经 `vmkfstools -i` 转 VMFS thin，并扩展/`resize2fs` 到 120G。
  - 通过离线挂载修好 netplan、SSH key、GRUB serial console、host keys。
- 验证：
  - 编译机 `ping 10.1.18.126` → OK
  - `ssh root@10.1.18.126` → OK
  - `docker version` → 29.1.3
  - `docker compose version` → 2.40.3
- 待补：ESXi 快照（API 暂时拒绝连接，稍后补）。

### T3.4/T3.5 RASP 配置助手（REVIEW）

- 新增 `agent/supervisor/rasp/openrasp`：
  - Java `-javaagent` 参数生成（jar/root/config/cloud.enable=false）。
  - PHP `extension`/ini 生成。
  - `Probe` 检查 jar/so 是否存在。
- 新增 `agent/supervisor/rasp/elkeidrasp`：
  - Python `PYTHONPATH`/`LYFLOW_RASP_CONFIG`/`LYFLOW_RASP_ROOT`/monitor 模式环境。
  - `Probe` 检查探针目录。
- 测试：`cd agent && go test ./supervisor/... -count=1` → all ok
- 状态：`REVIEW`。配置生成/探针检查就绪；**真实注入、attach、事件上报仍待测试 VM 联调**。
- 回滚：删除 `agent/supervisor/rasp` 即可。

### T3.6 Agent 统一门面（REVIEW）

- 新增 `server/agentfacade/facade.go`：
  - 统一 `Agent` 模型（ID/名称/平台/版本/状态/Provider/最后心跳/组/能力）。
  - `Provider` 接口 + 多 Provider 合并、部分失败返回、按心跳排序。
  - `Filter`（查询/状态/Provider）、`Page`（offset/limit）。
- 新增 `server/agentfacade/facade_test.go`：合并排序、部分失败、过滤、分页。
- 测试：`cd server && go test ./agentfacade -count=1` → ok
- 状态：`REVIEW`。后端门面就绪；**HTTP API 与 UI 尚未接入**，下一步 T3.6b/T3.7。
- 回滚：删除 `server/agentfacade` 即可。

### T3.7 安装器/自检/回滚（REVIEW）

- 新增 `scripts/agent/preflight.sh`：root/systemd/命令/磁盘/时间同步/SELinux 检查。
- 新增 `scripts/agent/self-test.sh`：二进制、服务 active/enabled/重启次数、数据/日志目录、最近日志。
- 新增 `scripts/agent/install-agent.sh`：备份 → 安装 → daemon-reload → 启动 → 自检；失败自动回滚。
- 新增 `scripts/agent/rollback-agent.sh`：手动恢复备份。
- 在测试 VM `lyflow-test` 实测：
  - `preflight.sh` → exit 0，全部 OK（时钟已同步）。
  - `self-test.sh ssh /usr/sbin/sshd` → exit 0。
- 状态：`REVIEW`。脚本骨架与自检可用；真实 `ly-agent` 包/服务联调待 T3.7b。
- 回滚：删除 `scripts/agent` 即可。

### T3.8 响应审批/时间窗/回滚（REVIEW）

- 新增 `server/response/policy.go`：
  - 动作风险分级 L1/L2/L3。
  - L1 自动；L2 默认审批，指定时间窗内可自动；L3 永远审批。
  - 四眼原则、审批 TTL、时间窗校验。
- 新增 `server/response/policy_test.go`：L1/L2/L3、时间窗、四眼、未知动作。
- 测试：`cd server && go test ./response -count=1` → ok
- 状态：`REVIEW`。策略引擎就绪；**执行器/回滚/审计持久化**尚未接入，T3.8b 处理。
- 回滚：删除 `server/response` 即可。

### T3.9 横向移动检测（REVIEW）

- 新增 `server/correlation/lateral/detector.go`：
  - SMB/RDP/WinRM/SSH 端口识别与目标聚合。
  - 时间窗内多目标横向、凭据失败爆发两类 finding。
  - 置信度、技术 ID、首末时间、证据事件 UID。
- 新增 `server/correlation/lateral/detector_test.go`：SMB 横向、最少目标数、凭据爆发、时间窗。
- 测试：`cd server && go test ./correlation/lateral -count=1` → ok
- 状态：`REVIEW`。检测器就绪；**尚未接入实时消费与 Incident 阶段机**，T3.9b/M4 接入。
- Gate G4：`READY_FOR_REVIEW`。
- 回滚：删除 `server/correlation/lateral` 即可。

### T4.1 内容同步服务（REVIEW）

- 新增 `server/content/registry.go`：
  - 源模型（ID/名称/Kind/URL/License/Cadence/Enabled）。
  - `Due` 按 cadence 计算待同步源。
  - 许可门：拒绝 Elkeid License、proprietary、unknown。
- 新增 `server/content/registry_test.go`：待同步、Elkeid License 拒绝、非法源、许可白名单。
- 测试：`cd server && go test ./content -count=1` → ok
- 状态：`REVIEW`。注册表/许可门就绪；**实际下载/编译/灰度**由 `suricata-update`、`sigma-cli`、`yara` 适配器接入，T4.2 处理。
- 回滚：删除 `server/content` 即可。























