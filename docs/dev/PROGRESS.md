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

### T4.2 Suricata/ET Open 集成（REVIEW）

- 更新 `deploy/suricata/lyflow-suricata-profile.yaml`：补齐 ET Open 需要的 `HTTP_SERVERS` 等变量。
- 新增 `deploy/suricata/lyflow-suricata-test.yaml`：测试 VM 的 `ens160` af-packet profile。
- 新增 `deploy/suricata/README.md`、`rules/suricata/et-open.manifest.json`。
- 新增 `scripts/dev/suricata-e2e.sh`、`scripts/dev/suricata-replay.sh`。
- 测试 VM 实测：
  - Suricata 7.0.3 / suricata-update 1.3.0。
  - `suricata-update` 加载 ET Open：69,107 条，启用 53,151。
  - `suricata -T`：53,162 条规则成功，0 失败。
  - PCAP 回放触发自定义规则 `LYFLOW INERT pinned profile verification`（sid 9000001）。
  - EVE 输出包含 `alert`/`dns`/`flow`。
- 状态：`REVIEW`。规则/引擎集成已验证；容器化与自动灰度待 T4.7。
- 回滚：恢复旧 profile；删除新增测试脚本/manifest 即可。

### T4.3 `ly_probe` 产品化（REVIEW）

- 新增 `agent/supervisor/providers/lyprobe`：
  - 外部进程生命周期交给 supervisor。
  - `CommandArgs` 校验 `-i`/`-n`，支持 `ExtraArgs`。
  - `New` 默认 `/opt/lyflow/bin/lyprobe`，`Probe` 检查可执行文件。
  - 测试：`cd agent && go test ./supervisor/providers/lyprobe -count=1` → ok
- 新增 `scripts/dev/lyprobe-build.sh`：
  - Ubuntu 24.04 容器内构建，不污染编译机宿主依赖。
  - `--network host` 解决容器 DNS；`--cpus=1.5`、`--cpu-shares=128`、`--blkio-weight=100` 降低对共享编译机影响。
  - 只构建 `lyprobe`，跳过带 macOS-only 链接参数的 `plugins/`。
  - `patchelf --set-rpath '$ORIGIN'`，产物含 `lyprobe` + `liblyprobe-1.0.0.so` + `SHA256SUMS` + `BUILD-INFO`。
- 新增 `scripts/agent/lyprobe-preflight.sh`：root、binary、runtime lib、`ldd`、接口状态、GRO/GSO、RX ring、libpcap、PF_RING、CPU、MTU。
- 新增 `scripts/dev/lyprobe-netflow-smoke.sh`：本地 UDP collector + 14 秒抓包 + IPv4 流量，验证 NetFlow v5 导出。
- 新增 `deploy/lyprobe/{lyprobe.service,lyprobe.env.example,README.md}`。
- 测试 VM 实测（`10.1.18.126`，ens160）：
  - 上游 revision `06c097dd5c69e391efd3c8b3776d672e03386e49`，Ubuntu 24.04 容器构建成功。
  - 产物：`lyprobe` 203K，`liblyprobe-1.0.0.so` 542K；SHA256 校验通过。
  - preflight：binary/runtime/ldd/interface/libpcap/CPU/MTU 全部 OK；GRO on、RX ring 1024、PF_RING 未加载为 WARN。
  - NetFlow smoke：单次 23–27 包捕获，0 dropped，collector 收到 2–4 个 NetFlow v5 包。
  - `suricata-replay.sh` 改为纯 Python 生成 PCAP（移除 scapy 依赖），仍触发 sid `9000001`。
- 已知上游问题：
  - `lyprobe -P <dir> -D t` 文本 dump 触发 `*** buffer overflow detected ***`。
  - `-D b` 仅写 IPv4 NetFlow v5；IPv6-only 窗口会得到 0 字节 dump。
  - LyFlow 产品路径使用 NetFlow collector，不在生产启用文本 dump。
- 存储清理：
  - 测试 VM 清除 `python3-scapy`/`matplotlib`/`numpy`、apt cache、临时 dump/core；根分区 `3.2G → 2.5G`，清理后重新跑 preflight/NetFlow/Suricata replay 均通过；证据保存在 `/opt/lyflow/reports/T4.3/`。
  - 编译机删除旧 Ubuntu/VMDK staging 2.3G、临时 `ly_probe` 源码 29M；根分区可用 `93G → 95G`。未执行全局 Docker prune，避免影响其他构建/测试。
- 状态：`REVIEW`。规则转换、采集诊断、打包分别进入 T4.4/T4.5/T4.7。
- 回滚：删除 provider、preflight、unit、构建/冒烟脚本及 `/opt/lyflow/bin/lyprobe`、`liblyprobe-1.0.0.so`；不影响现有 Suricata。

### T4.4 `ly_probe` 规则转换与热加载（REVIEW）

- 新增 `server/rulecompiler`：
  - Suricata 简单规则解析：单个 `content` 或简单 `pcre`。
  - HTTP URI/Header/Body、TLS SNI、精确 DNS 查询名（编码为 DNS label regex）。
  - `nocase`、PCRE `i` 支持；Go/RE2 先行校验。
  - 复杂规则（多 content、flowbits、byte_test、threshold、dataset、复杂 PCRE）记录到 manifest，保留 Suricata。
  - 原子写 `threat.json` + `manifest.json`，失败保留旧规则。
  - `Watcher` 轮询源目录，按 SHA256 去重，变更后编译并可选执行 reload hook。
- 新增 `server/cmd/rulecompiler`：
  - `-once` 单次生成；默认 watch 模式。
  - `-source`、`-output`、`-manifest`、`-interval`、`-reload-command`。
- 新增 `rules/lyprobe/`：
  - `source/lyflow-sample.rules`。
  - 生成的 `threat.json`（6 条）与 `manifest.json`（2 条跳过原因）。
- 新增 `deploy/rulecompiler/{lyflow-rulecompiler.service,rulecompiler.env.example,README.md}`。
- 新增 `patches/lyprobe/0001-hot-reload.patch`：
  - servicePlugin 读入完整新规则集后，在 `pthread_rwlock` 保护下原子交换。
  - 2 秒轮询 inode/size/mtime，原子 rename 触发零停机热加载。
  - 解析失败保留旧规则。
  - 修复上游 sentinel 节点未初始化导致的 reload 非法 free。
- 更新 `scripts/dev/lyprobe-build.sh`：
  - 容器内安装 `libpcre3-dev`，编译 `servicePlugin.so`。
  - 应用 `patches/lyprobe/*.patch`。
  - 支持 `LYPROBE_SOURCE_DIR` 离线构建。
- 更新 `deploy/lyprobe`：
  - 服务插件、`fp-patterns`、`WorkingDirectory=/opt/lyflow`。
  - `-T` 模板包含 `%PROTOCOL` 与 `%THREAT_*`，避免协议过滤被禁用。
- 测试 VM 实测：
  - `go test ./rulecompiler ./cmd/rulecompiler` → ok。
  - 生成：6 条转换、2 条跳过；输出确定性（重复生成 sha256 一致）。
  - 合成 HTTP/DNS PCAP 命中 `9100001` 和 `9100005`。
  - 真实 `ens160` HTTP 请求 + 规则热更新：日志出现 `Hot-reloaded 101 patterns`，随后命中 `9200001`，**lyprobe 进程未重启**。
  - `lyprobe` 初始加载 101 条 fingerprint，reload 后仍为 101。
- 已知限制：
  - 转换是保守子集，不做复杂 PCRE/多 content 语义推断。
  - DNS 只支持精确域名 label 序列，不支持通配/子域泛化。
  - 未打补丁的 ly_probe 可用 `-reload-command 'systemctl restart lyprobe'` 兜底，但有短暂抓包中断。
- 状态：`REVIEW`。规则源 freshness、热转换、零停机 reload 已端到端验证。
- 证据：`/opt/lyflow/reports/T4.4/`（热加载日志、生成规则、二进制校验和）；测试 VM 清理 gdb/临时目录，根分区约 `2.5G/116G`。
- 回滚：停止 `lyflow-rulecompiler`，恢复旧 `threat.json`；ly_probe 可继续运行，仅失去自动规则刷新。

### T4.5 Capture doctor（REVIEW）

- 新增 `agent/capturedoctor`：
  - 接口存在/UP/MTU。
  - `/proc/net/dev` RX 包/丢包/错误，按采样间隔计算 PPS 与 drop%。
  - `/proc/net/softnet_stat` dropped/squeezed。
  - `ethtool -g` RX ring、`-k` GRO/GSO、`-S` RX missed/FIFO/over/no-buffer。
  - PF_RING 可用性。
  - ly_probe 进程/PID/RSS。
  - 状态 `ok/warn/critical`，JSON 原子写入。
- 新增 `agent/cmd/capturedoctor`：
  - `-once` 退出码：0 ok、1 warn、2 critical。
  - watch 模式、JSON 状态文件、状态变化告警命令。
  - `-restart-command` 必须显式配置；连续 critical 达阈值且超过 cooldown 才执行，执行前写日志和 `issues[].code=restart`，不静默重启。
- 新增 `deploy/capturedoctor/{service,env,README}`。
- 新增 `scripts/agent/capturedoctor-smoke.sh`。
- `scripts/dev/test-all.sh fast` 现在纳入 `agent ./...`。
- 测试 VM 实测：
  - `go test ./capturedoctor` 与 `go test ./...`（agent）通过。
  - `ens160`：`exit=1 status=warn`，正确报告 ring 1024、GRO on、PF_RING 未加载。
  - 不存在接口：`exit=2 status=critical`，`interface_missing`。
  - lyprobe 进程检查：`"running": true`，PID/RSS 正常。
  - 告警命令收到 JSON；`-restart-after 1` 仅执行一次并打印 `CRITICAL: executing configured restart`。
- 限制：
  - 队列覆盖采用 softnet/ring/no-buffer，不解析 `tc qdisc` 详细队列。
  - 权限不足由既有 `lyprobe-preflight.sh` 的 root/能力检查负责。
  - 默认不自动重启；只有运维显式配置才启用。
- 证据：`/opt/lyflow/reports/T4.5/`。
- 状态：`REVIEW`。抓包运行时监控、告警和受控重启已端到端验证。
- 回滚：停止 `lyflow-capturedoctor`，删除状态文件；不影响 ly_probe/Suricata。

### T4.6 查询性能与压测（REVIEW）

- 新增 `server/bench`：
  - 确定性 Event v2 生成器，30 天时间分布、可配置 EPS/载荷。
  - 最近秩百分位 p50/p95/p99。
- 新增 `server/cmd/eventbench`：
  - ClickHouse schema 创建/重建、批量写入（支持 parallel writers）。
  - 30 天采样数据 + 20k EPS + 1Gbps 载荷三种模式。
  - 查询工作负载：事件列表、严重度/来源/阶段过滤、30 天关键字、详情、游标翻页、24h count、1m 聚合。
  - 超时 10 分钟；`-optimize`/`-settle-seconds` 控制 merge 稳定。
  - 报告 JSON，p95 阈值 2000ms。
- Schema：
  - `idx_event_uid` bloom_filter，修复详情查询。
  - asset/user/src/dst/process/file/rule 的 ngrambf 跳过索引。
  - 迁移版本 7 增加索引 DDL。
  - `HTTPClickHouse.Exec` 供压测/诊断使用。
- 测试 VM（6 vCPU/8GiB，ClickHouse 26.9.21.9）结果：
  - 30 天 12.96M 事件（5 EPS 采样）：查询 p95 最大 728ms，0 errors。
  - 20k EPS 正常载荷：21,525 EPS。
  - 1Gbps 载荷（5.5KB/事件）：22,114 EPS，约 1.06Gbps，单独写入通过。
  - 30 天索引表 + 1Gbps 同时：18,525 EPS，未稳定达到 20k；查询 p95 492ms。
  - 冷启动单次全流程受 part/merge/内存影响，不能把单次冷态 p95 当作稳态。
- 结论：30 天查询、20k 正常载荷、1Gbps 单独写入分别通过；“30 天 + 20k + 1Gbps + 查询”在 6 vCPU/8GiB 单节点未完全达标。
- 证据：`/opt/lyflow/reports/T4.6/`，详细报告 `docs/dev/T4.6-REPORT.md`。
- 状态：`REVIEW`。容量边界已量化，不作为全量生产容量承诺。
- 回滚：删除 `server/bench`、`server/cmd/eventbench`，移除新增索引/迁移版本 7；旧查询仍可用。

### T4.7 打包与 Compose profiles（REVIEW）

- 新增 `deploy/compose/lean.yml`：
  - core：PostgreSQL、Redis、ClickHouse、ly-server、security-engine、agent-center、ly-vis。
  - capture：lyprobe、Suricata、rulecompiler、capturedoctor。
  - healthcheck、资源限制、host network/capabilities、共享 `runtime/fp-patterns`。
- 新增 `deploy/compose/full-private.yml`：
  - 私有 overlay（Elkeid HUB/Console/AgentCenter/Manager/ServiceDiscovery/MongoDB/Kafka）。
  - 不在 lean 中默认启用；镜像/规则不进入公开产物。
- 新增 `deploy/compose/lyflowctl`：
  - `bootstrap/config/up/down/ps/logs/upgrade/rollback/backup`。
  - 自动生成 `lean.env` 随机密钥、runtime 目录和样例规则。
- 新增 sensor Dockerfile：
  - `lyprobe.Dockerfile`（libpcap/libpcre/PCRE plugin）
  - `capturedoctor.Dockerfile`（ethtool/procps）
  - `rulecompiler.Dockerfile`
- 新增 `build-sensor-images.sh`：从 `/opt/lyflow/artifacts` 构建 sensor 镜像。
- 测试 VM 实测：
  - lean config 629 行 / 11 服务；full-private config 711 行 / 15 服务。
  - sensor 镜像构建成功：lyprobe 127MB、capturedoctor 135MB、rulecompiler 20MB。
  - capture profile 三容器实际启动并 healthy。
  - lyprobe 加载 106 条 pattern，rulecompiler 生成 6 条规则，capturedoctor 看到 lyprobe 进程并输出 `status=warn`。
  - 规则更新触发 lyprobe `Hot-reloaded 106 patterns`。
- 未验证：
  - core 的 ly-server/security-engine/frontend 镜像仍由既有流水线提供，编译机没有本地镜像，未在测试 VM 启动完整 core 栈。
  - suricata 容器镜像依赖上游 `jasonish/suricata`，当前网络无法拉取；宿主态 T4.2 已验证。
  - Vector/SeaweedFS 未加入，等待采集/证据链路验收。
- 证据：`/opt/lyflow/reports/T4.7/`，详细报告 `docs/dev/T4.7-REPORT.md`。
- 状态：`REVIEW`。capture plane 打包和运行已验证；core 全栈启动待镜像流水线。
- 回滚：停止 capture profile，删除 sensor 镜像/`deploy/build-context`；core 用 `lyflowctl rollback` 恢复 env 备份；不自动删除 named volume。

### T4.8 文档/许可/安全审计（REVIEW）

- 文档：
  - README 更新为 v2 core + capture 11 服务拓扑、现代 Linux Agent 边界。
  - ARCHITECTURE 增加 v2 实现状态和旧拓扑差异说明。
  - API 文档增加 Event v2 ingest/query。
  - 新增 `docs/legal/THIRD_PARTY_NOTICES.md`、`docs/legal/GPL-SOURCE-OFFER.md`。
  - 新增 `docs/dev/T4.8-AUDIT.md`。
- 许可：
  - 公开 lean Redis 固定 `7.2-alpine`（BSD-3）；`check-licenses.sh` 增加 Redis 版本回归检查。
  - ly_probe GPL-3.0 独立进程/容器边界、补丁/构建/source offer 记录。
  - full-private 的 MongoDB（SSPL）和 Elkeid 私有组件明确不进入公开产物。
  - 新增 `scripts/dev/generate-sbom.sh`，生成 Go module、前端依赖/许可、镜像和元数据清单。
- 安全：
  - 修复安装脚本 Host 注入：`sanitizeRequestHost`，拒绝 shell 元字符，忽略 `X-Forwarded-Host`，端口白名单。
  - 新增 `SecurityHeaders`（nosniff/frame/referrer/permissions）。
  - 前端高危依赖升级：Vue 3.5.42、axios 1.20.0，postcss/source-map-js/nanoid 传递依赖更新；`npm audit` high=0/critical=0。
- 验证：
  - `check-secrets.sh`、`check-private.sh`、`check-licenses.sh` 通过。
  - `go vet ./...`（pkg/server/agent/security-engine/dpi-engine）通过。
  - 前端 typecheck、31 files/114 tests、lint（0 errors）通过。
  - `scripts/dev/test-all.sh fast` 通过。
  - SBOM 输出 `/opt/lyflow/artifacts/sbom`。
- 残余风险：
  - ingest v2 的 TenantID/AssetID 未绑定认证 principal（多租户前需修）。
  - ECharts 5.6.0 仍有 1 个 moderate XSS advisory；升级 6.1.0 属 breaking，留待单独验证。
  - core 全栈未在测试 VM 启动（缺本地镜像），发布前需补一次完整安全冒烟。
  - Elkeid 私有模块需在私有仓库独立审计。
- 状态：`REVIEW`。公开仓库许可/密钥/私有边界和主要安全修复已完成；G5 全栈验收仍受 core 镜像流水线阻塞。
- 回滚：还原 Host 校验/安全头/前端依赖即回到审计前状态；许可文档和 SBOM 只增不删。

### G5 全栈验收（PASS_WITH_EXCEPTIONS）

- 新增 `deploy/compose/g5-host.yml`（测试专用 host-network 拓扑）和
  `deploy/docker/{server,security-engine,pingora-frontend,suricata,redis}-lean.Dockerfile`。
- 前端改为 **Pingora 0.9**：
  - Rust builder 从 `docker.1ms.run/library/rust:1.85-bookworm` 拉取。
  - 静态文件 + `/api/` `/ws/` 反向代理 + HTTP 80→443 重定向。
  - 注入 `X-Forwarded-Proto: https`，安装脚本生成 HTTPS API 地址。
- 测试机 core + capture 10 个容器全部 healthy：
  - ly-server、agent-center、security-engine、ly-vis(Pingora)、
    postgres、redis、lyprobe、suricata、rulecompiler、capturedoctor。
  - ClickHouse 使用测试机原生 26.9.21.9。
- 端到端：
  - 管理员登录/强制改密。
  - 签发 enrollment token，注册 `g5-agent`。
  - v2 ingest 接收 1 个事件；`/api/v2/events` 查询命中同一 `event_uid`。
  - `/api/v1/agents` 返回 agent。
  - `docker compose restart` 后 11 服务恢复 healthy，事件仍可查询。
- 例外：
  - Docker Hub 镜像站不稳定；Postgres 使用本地 `safeline-postgres:15.18`，
    ClickHouse 使用原生进程，Redis/Pingora/core 镜像本地构建。
  - 真实 Elkeid/Wazuh/OpenRASP Agent 链路、ESXi 快照仍未完成。
- 报告：`docs/dev/G5-REPORT.md`，证据 `/opt/lyflow/reports/G5/`。
- 状态：`PASS_WITH_EXCEPTIONS`，不是无条件可发布。

### G5 功能收口：Event v2 → Incident 与 UI 边界（DONE）

- 修复 v2 事件没有进入 XDR/Incident 的问题：
  - `StorageEventRuntime.WriteEventsV2` 写 ClickHouse 后追加 canonical 投影。
  - 投影保留资产、ATT&CK、网络五元组和治理字段；失败只记录日志。
  - XDR graph 从 canonical 投影生成攻击链，`/api/v1/incidents` 持久化并返回。
  - 实测 2 条同资产 `initial_access` + `execution` v2 事件生成 Incident 和 2 条证据。
- 修复控制台没有按边界显示：
  - `VITE_UI_SHELL_V2_ENABLED` 默认开启，ly_vis 顶部导航/二级页签/20px 内容区生效。
  - `VITE_ATTACK_V2_ENABLED` 默认开启，事件中心和攻击链使用 V2 页面。
  - `/dashboard` 固定使用 `OverviewV2`，全球态势保留在 `/situation/global`。
  - 修复 Event v2 客户端错误请求 `/api/v1/v2/events` 的双前缀问题。
  - 修复总览/事件/Incident 对已解包响应的二次 `unwrap` 导致空数据。
- 路由契约：
  - 补 `/api/v2/events/` 路由策略、方法、测试和契约记录。
  - 路由快照更新为 120 条；`TestRouteAPIContract` 通过。
- 验证：
  - `go test ./cmd -run 'TestCanonicalProjection|TestArchitectureRoute|TestRouteRegistry|TestRouteAPIContract'` → ok。
  - 前端 31 个测试文件 / 115 tests 通过；typecheck 通过。
  - 真实 UI 验收（生产 dist + Vite preview，代理到自签 HTTPS API）：
    Firefox 1440×900 + 390×844，17 页全部 200/304，0 console/page/network
    error、0 4xx/5xx、无水平溢出；截图和 `validation.json` 在
    `/opt/lyflow/reports/G5/ui-production/`。
  - G5 host-network 补 `SECURITY_ENGINE_HEALTH_URL=http://127.0.0.1:8082/health`，
    `/api/v1/engine-runtime/status` 恢复 200，XDR/运行态页面不再出现 503。
- 未完成：真实 Agent/RASP、Vector 告警链、ESXi 快照。
- 自签证书已接受，不再作为 UI 验收阻塞项。
- 残余风险：测试机历史合成 Incident 仍保留；新路径已过滤 `weak_same_ip`，
  不再因同源 IP 交叉提升。

### G5 真实 Agent / 告警 / UI 能力对齐（DONE）

- 真实 Agent：
  - `g5-real-agent` 在测试机注册、心跳 online、资产指标 fresh。
  - 资产页读取真实 CPU/内存/磁盘/网卡/进程；新增能力列。
  - runtime sensor 启用（eBPF fallback）；YARA 4.5.0 + 规则包 active；RASP monitor active。
- 告警链路：
  - Suricata 7.0.11 PCAP 回放 SID `9000001`。
  - Vector 0.49.0 读取 EVE，VRL 映射 ComponentAlert，HTTP POST
    `/api/v1/agent/component-alert`。
  - 服务端接受单对象/数组，写 canonical 并发布 `component_alerts:v2`。
  - UI `/traffic-threats` 从 `/api/v1/component-alerts/traffic` 显示 Vector 告警。
  - Agent Suricata EVE adapter 保留为无 Vector 环境备用路径。
  - 修复 Agent EVE adapter 在 CPU budget 后永久退出的问题。
- RASP / YARA：
  - Python/Java/PHP/Node/dotnet 五种运行时均完成真实 attach 并上报事件；
    `/rasp` 显示 39 组，语言/应用字段可见，heartbeat 已过滤。
  - 修复 Python reporter 注册、Node http 自递归、Java/PHP/Node/.NET 轮换 token 获取。
  - Agent bridge 兼容 legacy probe 并归一化为 RASP 事件。
  - Wazuh manager 4.9.2 本地安装，关闭高开销模块并加 2 GiB swap；
    native alerts 进入 component alert / XDR / Incident。
  - OpenRASP 1.3.7 官方 Java engine 已下载并 attach 初始化；
    Jetty 9.4 真实请求产生 command alarm；`openrasp-alarm-bridge.py`
    systemd 服务把 alarm 送入 component alerts / UI。
  - 响应执行器：block_ip/unblock_ip、process_kill、file_delete/file_restore、
    account_disable/account_enable、isolate_host/host_unisolate、
    namespace_isolate/namespace_restore 均完成审批、执行、回滚；
    破坏性动作由 RESPONSE_ENABLE_* 默认关闭。
  - 证据对象存储：SeaweedFS 3.80 + evidence artifacts/bundles API；
    bundle 可下载并校验 SHA256。
  - 横向移动 detector 接入 WriteEventsV2，派生 `lateral.movement` 事件并
    更新 Incident 阶段。
  - Event v1、旧 response candidate/advisory 入口关闭；Windows Agent 放弃。
  - YARA 规则包合并可编译规则，避免 external-variable 规则污染。
- UI 修复：
  - 总览在线 Agent/资产总数改用 assets stats。
  - 全球态势无地理数据时回退到真实 Incident。
  - 运行威胁改查 `/api/v1/component-alerts/runtime`，显示真实 HIDS/Wazuh 事件。
  - RASP 页接入 `component-alerts/rasp`，并显示 Python RASP 事件。
  - 安装页改为现代 Linux 支持范围。
  - 自签证书生产 dist 验收 17 页，0 console/page/network error、0 4xx/5xx。
- Installer：
  - install.sh/uninstall.sh/download/Python/PHP/Java/Node.js/.NET RASP probe 均公开返回 200。
  - linux/amd64、linux/arm64 两种 Agent 下载均可用；Windows 已砍掉。
  - `scripts/build-agent-binaries.sh` 只构建 Linux 双架构，核心镜像构建脚本
    自动调用。
  - 安装页生成 10 分钟一次性 enrollment token，脚本写入 agent.env 并由
    systemd EnvironmentFile 注入；危险 token 字符会被拒绝。
  - 安装脚本自动下载 RASP policy root 到 /etc/lyflow/trust，供签名策略验证。
  - server image 已包含 Agent 二进制和 probe 资产。
- 验证：
  - `G5_REAL_AGENT_OK`
  - `G5_INCIDENT_OK`
  - `G5_VECTOR_OK`
  - `G5_RASP_OK`
  - `G5_RASP_MULTILANG_OK`
  - `G5_WAZUH_NATIVE_OK`
  - `G5_OPENRASP_ATTACHED`
  - `G5_OPENRASP_ALARM_OK`
  - `G5_RESPONSE_OK`
  - `G5_RESPONSE_EXPANDED_OK`
  - `G5_EVIDENCE_OBJECT_STORE_OK`
  - `G5_LATERAL_REALTIME_OK`
  - `G5_LEGACY_RETIRED`
  - UI validation exit 0
- 仍未完成：clean VM/systemd 安装（ESXi 凭据阻塞）、ESXi 快照、
  Wazuh/OpenRASP/SeaweedFS 离线包固定 digest；Elkeid/Windows 已放弃。

## 2026-10-20 态势感知 UI 重设计

- 新增浅色优先、可切换深色的指挥控制台 shell：顶部一级导航、二级页签、全局搜索、
  平台在线状态、主题切换、响应式布局。
- 重做运营总览：真实态势评分、KPI、ATT&CK 阶段、检测趋势、告警构成、来源覆盖、
  优先 Incident、实时事件流、引擎心跳。
- 重做事件中心、攻击链处置、资产运维；新增响应处置、证据库、引擎健康页面。
- 事件详情支持证据抽屉、原始载荷、来源 Schema；攻击链支持阶段时间线、证据展开、
  真实响应动作创建/审批/回滚、Incident 证据包生成。
- 证据库支持证据包列表/下载、Incident 证据包、PCAP 对象上传到 SeaweedFS。
- 检测面页面统一浅色令牌并接入真实流量/运行/RASP 数据；全球态势在无 Geo 数据时
  显示空态，不生成假攻击线。
- 修复 Incident 同步在主键冲突场景下的重复键错误，XDR 工作台不再因 Incident 大列表
  阻塞；深色主题图表重绘。
- 前端验证：typecheck 通过，115 前端测试通过，生产构建通过；17 页 Playwright
  验收 0 console/page/network/4xx/5xx；截图见
  /opt/lyflow/reports/G5/ui-redesign/。
- 设计说明：docs/dev/UI-REDESIGN.md。

## 2026-10-20 响应与 Incident 功能打磨

- Incident 状态机支持显式重开：已分诊/处理中/已解决/已关闭可回到新发，回到新发时
  清空确认与解决时间，所有变更继续写审计；前端只展示合法状态迁移。
- Incident 列表改为服务端 status/severity 筛选与分页，默认使用 live=0 快速首屏，
  刷新时再触发活动图同步。
- 响应处置表单简化为 Agent + 动作 + 说明；目标仅在封禁/进程/文件/账号/容器动作
  需要时显示，主机隔离和观察直接使用 Agent。
- 新增持久化自动处置策略 API：GET/PUT /api/v1/response/automation；支持启用、
  起止小时、审批 TTL，按 Asia/Shanghai 计算；策略写入 response/policy.json。
- G5 测试机自动处置窗口已开启，实测 L2 block_ip 自动执行，rollback 清空 nft set；
  L3 仍保持人工审批。
- 前端 typecheck、115 测试、生产构建通过；响应页和 Incident 页浏览器功能检查
  无 console/page error。
- 总览各数据块增加独立 ready 状态，XDR 态势/事件/引擎/资产未返回时显示加载态，
  不再把未加载显示为 0 或低风险；趋势和严重度图在对应数据到达后重绘。
- 响应动作历史区分自动策略批准与人工审批；L3 file_delete 实测仍进入 pending_approval，
  由 approver 审批后执行，auto_approved=false。
- 最终 G5 功能校验：总览 9s 内全部数据就绪；响应页表单只剩 Agent/动作/说明；
  Incident 状态 open→triaged→open 无错误；无 console/page error。
- 规则中心「规则源同步」按引擎拆成 5 个模块：流量、运行、文件、应用防护、IP 地理归属；
  桌面宽屏一行展示，窄屏自动换行，RASP 规则数与应用防护路径直接来自真实引擎规则清单。
- 规则源同步接口改为并行容错：引擎健康接口短暂不可用时，仍展示本地规则源、规则数量
  和版本，并给出「引擎健康接口暂不可用」提示，不再整页失败。
- GeoIP 未配置时显示「未配置 / 0 条」，不再伪造 city-db 运行状态。
## 2026-10-20 规则源、账户、事件与引擎稳定性修复

- 规则中心「规则源同步」改为由后端实装引擎驱动：LyFlow DPI、Suricata、Wazuh、YARA、OpenRASP；
  上游来源合并 /rule-platform/sources、/rule-platform/versions 与 /rules/sources，只展示可更新、
  有真实 URL 的来源，内置/受限/不可更新规则不进入同步列表。
- 每个上游展示更新地址、当前版本、最近同步和更新按钮；GeoIP 明确标注为地图基础数据，
  不再作为规则引擎模块或伪造 city-db 状态。
- 响应处置页删除重复的「发起响应动作」表单，只保留定时自动处置策略与真实处置历史；
  动作统一从攻击链 Incident 发起。
- 账户新增不再向 /auth/register 传 role（该接口按安全设计拒绝调用方角色），
  先创建 viewer，再通过管理员用户更新接口设置角色；账户列表增加角色管理。
- 运营总览事件流改用 /api/v2/events，事件链接统一使用 event_uid，修复从总览点事件
  进入详情时 UID 不匹配导致的 event not found。
- security-engine watchdog 在消费/回收批次中刷新，并将 liveness 窗口从约 2 秒放宽到约 11 秒，
  定位并修复引擎频繁因 watchdog stale 重启、导致 /engine-runtime/status 偶发
  127.0.0.1:8082 connection refused 的根因。

## 2026-10-20 lyprobe NetFlow 证据链、eBPF 进程检测与规则可见性

- 新增 `server/cmd/netflow-collector`：NetFlow v9 template/data 解码、原始 UDP 接收（规避 lyprobe 校验和问题）、
  8 worker 并发发布、30s 超时和重试。修复 `0xe169` 等 threat 字段被误判为 IPFIX enterprise 字段导致模板丢失的问题。
- lyprobe 模板加入 `%IN_BYTES %IN_PKTS`；collector 同时写入 `flows:raw` 与 `sessions:semantic`，
  流量归属到被观测主机 `g5-real-agent`，同时保留 `probe_name=lyprobe`、`capture_source=lyprobe`、`engine=lyprobe`。
- 新增独立 `flow-bridge` 消费组：只把 `flows:raw` 桥接到 `flows:semantic`，不再重复写入 `sessions:semantic`，
  避免高频抓包流量把会话消费者积压。
- 规则中心新增 lyprobe 实装引擎：`/api/v1/engine-rules` 返回 6 条真实 `rules/lyprobe/threat.json` 规则，
  `/api/v1/engine-runtime/status` 返回 lyprobe 规则集、来源、NetFlow v9 传输与生成版本；前端显示
  「LyFlow 探针规则」卡片，不伪造可更新 URL。原生规则扫描增加 2 分钟缓存与启动预热，消除规则页首次加载超时。
- Agent 运行时进程采集改为 eBPF 优先：`bpftrace` 监听 `sched_process_exec`；不可用时回退
  `/var/log/audit/audit.log` 的 EXECVE/SYSCALL；最后回退 procfs 快照。事件继续写入 `alerts:runtime`，
  在运行威胁页展示 `runtime.process.exec` 与 `backend=ebpf`。
- 验证：netflow 解码单测通过；`/traffic/flows` 可查到 lyprobe 流（含真实 bytes/packets），
  `/traffic/sessions` 可查到 lyprobe 会话；`/engine-rules?engine=lyprobe` 0.36s 返回 6 条；
  eBPF 事件在 `/component-alerts/runtime` 可见；前端 typecheck 与 115 项测试通过。
- 已知限制：测试机 Docker 守护进程曾因容器重启循环卡住，已重启恢复。会话持久化在消费者追上积压后已验证：
  `traffic_sessions` 中 lyprobe 记录 273 条，最新 observed_at 为 12:26；积压期间 Redis 语义流仍可查询。


## 2026-10-20 二次功能回归与联调修复

- 二次回归覆盖 17 个页面/视口：全部 HTTP 200、横向溢出 0、console/page error 0、异常请求 0。
- 修复规则中心慢源接口阻塞引擎卡、规则总数与清单口径不一致、6 卡布局、探针/运行时来源展示。
- 流量观测新增 lyprobe 探针筛选，支持检索真实 NetFlow 证据；NetFlow 丢弃 unspecified 地址。
- 运行威胁页显示 eBPF/auditd/日志审计来源；lyprobe 引擎状态改为基于最近 5 分钟 flows:raw 心跳。
- 规则源目录增加 30s 进程内缓存；冷请求仍较慢，作为后续性能项。
- 回归报告：`docs/dev/REGRESSION-2026-10-20.md`；证据：`/opt/lyflow/reports/G5/regression-2026-10-20/`。

## 2026-10-20 生产级最终验收

- 生产验收脚本 `frontend/e2e/production-acceptance.js` 通过：19 个页面、6 条 legacy 重定向、重复 UI、Incident、响应、规则、流量、eBPF 全部通过。
- 全量 UI 巡检 17 个页面/视口：全部 200，console/page/network error 0，移动端无横向溢出。
- API 烟测 29 个接口全部 200；lyprobe 流量 158 条、坏地址 0；eBPF process 事件 68 条；规则清单 29,906 条。
- 去重：删除 6 个重复页面并重定向到 `/rasp`、`/runtime`、`/assets`、`/xdr`、`/rules`；控制中心移除重复 Agent 列表，改名平台设置。
- 修复 security-engine CPU budget 重启循环（1000ms），控制健康稳定、restart_count=0。
- 修复 lyprobe 心跳扫描窗口、规则源冷启动缓存和流量会话冷查询预热。
- 报告：`docs/dev/PRODUCTION-ACCEPTANCE-2026-10-20.md`；证据：`/opt/lyflow/reports/G5/production-acceptance-2026-10-20/`。
- 发布级例外：clean VM 安装/回滚、20k EPS 容量复测。

## 2026-10-20 GitHub 主分支与云发布收敛

- 按 D-013 彻底移除 Windows Agent：删除 Windows 专用文件，Release 工作流只构建 Linux AMD64/ARM64；安装页、下载 API 和文档不再提供 Windows/Npcap 入口。
- 云构建改用 `GOPROXY=direct`，不注入 HTTP/HTTPS 代理；移除构建机/测试机 Docker 代理覆盖和 RASP 验收脚本的代理环境。
- GitHub Release run `39448186932` 成功，`latest-server` 已发布 AMD64/ARM64 一键安装包。
- 删除 Windows 抓包文件后重新生成事件清单，保持 Linux-only 路径计数一致。
- 修复 supervisor 在进程退出时提前关闭 stdout/stderr 管道导致的日志丢失竞态，改为行缓冲 writer + `WaitDelay`，100 次重复测试通过。
- 最终代码提交 `659093d` 的 CI run `39450350180` 与 Release run `39450350251` 均成功，`latest-server` 已指向该提交；后续仅追加 docs-only 报告提交（`[skip ci]`）。

## 2026-10-21 ESXi 10.1.18.123 / 10.1.18.198 全新部署

- 在 vCenter `10.1.18.110` 管理的 ESXi `10.1.18.123` 上新建 `lyflow-198`，配置 8 vCPU / 16 GiB / 200 GiB。
- 管理口 `mgmt` 配置 `10.1.18.198/24`，镜像口 `mirror` 无 IP；安装 9 个正式容器并全部 healthy。
- 验证 `https://10.1.18.198/`、`/api/v1/health` 和 `admin` 登录成功。
- 修复 ClickHouse 24.8 的 v2 事件表 TTL：`TTL toDateTime(event_at) + INTERVAL 30 DAY`（`a8106f6`）。
- Suricata 使用 `mirror`；本机镜像采集在 PF_RING 模块缺失时回退 AF_PACKET。
- 详细记录：`docs/dev/ESXI-198-2026-10-21.md`。

## 2026-10-21 真机专家测试与修复

- 在 10.1.18.8 完成真实 Agent 全新安装、心跳、资产和流量上报验证。
- 修复 LyFlow 探针心跳误判：接受 local-mirror-capture / mirror 流量作为探针活跃证据。
- 修复 YARA 显式失败被 capability fallback 覆盖为运行中的问题。
- 规则中心改为「已是最新 / 有新版本 / 未上报」，无更新时不再显示可点击更新按钮；Falco 实测同步 3 条规则成功。
- 重做平台设置布局，三块设置完整展开；生产 19 页面巡检 0 错误，30 个 API 烟测全部 200。
- 详细记录：docs/dev/EXPERT-ACCEPTANCE-2026-10-21.md。

## 2026-10-21 保留问题修复与 legacy DPI 清理

- YARA：Agent 安装器自动安装 YARA CLI 并下载规则包；测试机安装 YARA 4.5.5、规则 6,996,814 字节后，引擎健康显示 `installed=true`、`running=true`。
- Java RASP probe：服务端镜像补齐 `probe/rasp/` 资产，五个 probe 下载接口全部 200。
- Agent 完整性：服务端用平台 policy signer 动态签发 Agent 二进制摘要，安装器下载摘要与 trust root 后启用 binary fail-closed；配置摘要继续关闭。
- legacy DPI：确认 `DPI Engine` 仅用于旧 `flows:raw` 迁移，已删除源码模块、legacy compose、旧规则/编译预览和 UI 卡片/筛选；新的 LyFlow 探针告警统一标记 `lyprobe`，历史 `dpi_engine` 仅保留契约兼容。
- 验证：`pkg`、`server/cmd`、`server/cmd/netflow-collector`、`security-engine` 测试通过；前端 117 项测试、typecheck、build 通过。

## 2026-10-21 Incident 闭环与规则抑制

- Incident 页面新增闭环结论：观察、确认误报、授权/预期操作、确认已处置；关闭必须填写原因，生命周期审计完整保留。
- 支持按规则、来源 IP、资产/受害实体抑制 7/30/90 天；威胁详情页可直接标记单点告警为误报。
- 修复重复闭环幂等键冲突；抑制策略持久化到 `.sisyphus/runtime/xdr-response-policy.json`（.sisyphus 持久化目录）。
- 生产已将 `test8-final3` 的 SSH 授权登录按预期操作关闭，旧 `test8-fresh` 重复链按历史测试数据关闭；`et-open-2103018`（GPL NETBIOS）已抑制 30 天。
- 平台设置卡片改为等高；验证：前端 117 项测试、typecheck、build，`server/cmd` 测试，Playwright 闭环提交全部通过。
- 详细记录：`docs/dev/INCIDENT-CLOSURE-2026-10-21.md`。

## 2026-10-21 检测窗口、态势与事件中心修正

- 攻击链处置默认只显示未闭环 Incident；闭环后立即从默认列表、处置队列和高危计数中移出。
- 态势总览改为最近 10 分钟检测事件 + 未闭环 Incident；移除 XDR 全量统计和 XDR 调查入口，评分与高危只由未闭环 Incident 计算。
- 事件中心从空的 ClickHouse v2 表切换为持久化 threat_events，默认最近 10 分钟，支持 1 小时/24 小时/30 天分类检索。
- 流量/运行/应用威胁默认最近 10 分钟；Redis 清理覆盖组件告警流，PostgreSQL 保留 180 天、ClickHouse v2 保留 30 天。
- `et-open-2103018`（GPL NETBIOS SMB NT Trans NT）加入默认噪声策略，首次安装即不进入检测面、XDR 和事件中心，并补单元测试。
- 生产验证：18 页 HTTP 200/0 错误，事件中心有数据，态势总览闭环为 0，GPL 规则不再返回。详细记录见 `docs/dev/DETECTION-WINDOWS-2026-10-21.md`。

## 2026-10-22 安全运营审计与修复

- 资产详情恢复 Agent 重命名，支持业务名称识别受害服务器。
- 单条内网中/高危流量告警可生成“内网横向可疑流量” Incident，不再等待第二阶段遥测。
- 规则 ID 0 修复为真实 SID；流量详情和白名单使用真实规则标识。
- 规则中心新增告警白名单管理（规则/来源/资产，7/30/90 天，可移除）。
- 引擎运行时接口健康超时改为 degraded 200，避免 503 导致页面数据缺失。
- 修复攻击链默认 active 筛选在前后端重复过滤导致活动 Incident 显示为空的问题。
- 验证：活动 Incident 可见，Agent 重命名成功，白名单增删成功，页面无 API/console 错误。详细记录见 `docs/dev/SECURITY-AUDIT-2026-10-22.md`。

## 2026-10-22 Redis OOM 导致安全引擎/探针异常

- 根因：Redis `flows:semantic` 与 `telemetry:traffic` 未纳入清理，达到 8GB maxmemory 后安全引擎无法创建 consumer group，持续重启；探针因 payload 时间落后被误判。
- 修复：Redis 流保留默认 2 小时（`REDIS_STREAM_RETENTION_HOURS=2`），清理全部实时流；探针活跃判断改用 payload 时间与 Redis message ID 的较新值。
- 生产：Redis 降至约 1GB；安全引擎 healthy/running、degraded=false；LyFlow 探针 running=true。

## 2026-10-24 生产运行优化与误报治理

- Redis 实时流保留默认 2 小时、清理周期 15 分钟，覆盖 flows:semantic/telemetry:traffic 等全部实时流；Redis 从约 5.2GB 降至约 1GB。
- 安全引擎生产 CPU 预算调整为 1000ms，重启计数归零；LyFlow 探针恢复 running。
- 内网横向候选按来源/受害/规则聚合；历史 240 个逐事件重复 Incident 已闭环，当前活动 Incident 13 条。
- GPL POLICY PCAnywhere 默认加入噪声策略；高频 XSS 不再逐事件生成 Incident。
- 总览安全评分与未闭环 Incident 等级使用同一口径；原始事件趋势明确标注不等同 Incident。
- 详细记录：`docs/dev/PRODUCTION-OPTIMIZATION-2026-10-24.md`。

## 2026-10-29 Gate 1–6 收口（XDR + RASP 加固）

- 部署基线：`ly-flow/server:v17` + `ly-flow/frontend:v9`，9/9 容器 healthy，验收 **30/30**（`docs/dev/ACCEPTANCE-V4.md`）。
- Gate 1：T0-02 五元组缺失语义、T0-03 ClickHouse 零值语义、T0-04 投影重试/DLQ、T0-05 幂等键 v2、T0-06 留存审计、T0-07 租户绑定、T0-08 采集计数器合同。
- Gate 2：`capture_health.go` 六态状态机 + 丢包率分母可信性；真实传感器（`0cf8e6df…`，主机网络抓 `lo`）验证 healthy → degraded(41.68% 丢包) → healthy；内核计数停滞时回退用户态收包数，分母不可信不发布比率。
- Gate 3：T1-01 实体索引消 O(n²)（与两两比较等价性测试）、T1-02 证据分级（弱证据只作上下文）、T1-03 Incident 根因聚合、T1-04 评分解释与版本化（`xdr-score.v1.1/v2.1`、components/capped）。
- Gate 4：T4-01 规则正/负/边界样本 CI（44 条规则全覆盖，顺带修出 81001/31101 大小写与 31158 转义 3 个真实缺陷）、T1-05 行为基线 shadow、T4-02 误报反馈限域可过期（rule+tenant+entity，TTL≤30 天，仅影子候选）。
- Gate 5：RASP 五态分离、`rasp-runtime.v1` 调用上下文（不再伪造 python）、阻断 monitor/dry_run/enforce + fail-safe + 紧急开关（A10.3 验收）。
- Gate 6：PG 逻辑恢复（独立容器、5 表行数与样本一致）、ClickHouse 冷备 130 MB 恢复（`traffic_sessions=6306`、迁移账本 1..9）、`v17→v16→v17` 回滚演练；手册见 `docs/dev/BACKUP-RESTORE.md`。
- 已知边界：ClickHouse 冷备需短暂停机（约 20 秒）；备份未异地复制；RASP 生产阻断需签名策略显式开启。

## 2026-10-29 线上缺陷修复（v22 + frontend:v13，验收 30/30）

1. **组件误报未就绪**：`security_engine.alert_bus` / `xdr.evaluator` 在“可读但无数据/无链路”时不再判 degraded，改为 `ok` 且 `details.state=idle`；真实不可读/算法不健康仍报错。
2. **规则源同步 `source_id is required`**：`/api/v1/rule-platform/sync` 无 `source_id` 时启动后台全量同步（20 分钟上限、单源 180 秒、携带操作者身份），`GET` 同一路由返回进度；前端轮询并展示成功/失败/跳过明细。
3. **同步不再静默激活**：外部规则默认只“暂存”（`status=staged`），必须点「应用规则」（compile-preview → rollback）才生效；此前全量同步自动激活 PTsecurity 规则，在回环 TLS 流量上产生上千条误报，已禁用 `…-11003921` 并重建 792 条规则的干净 bundle。
4. **引擎规则全 0**：页面把“规则明细列表”误当“按引擎汇总”。改为读取 `counts` / `count_semantics`；实际 `lyprobe 6、rasp 1340、suricata 764、wazuh 22214、yara 6335`。
5. **引擎全“未运行”**：服务端把“能力已上报但未启用”误标为 installed=true。现输出 `state`（running / adapter_active / installed / disabled / not_installed），零值时间不再渲染 0001/01/01。
6. **能力开关 `field must be traffic or rasp`**：接受 `traffic_sensor/runtime_sensor/rasp_probe_manager` 等别名并映射到 `traffic_enabled/hids_enabled/rasp_enabled`；YARA/日志审计明确返回“可上报但不可远程控制”，前端改为只读徽标；错误提示带后端原因。
7. **空态文案位置**：空态从表格内 `td[colspan]` 移到滚动容器内的 sticky 块，按可视宽度居中（表格横向溢出时不再偏到一侧）；Events/Incidents/Assets/Threats/Rules/Health/Settings 统一。
8. **规则源版本可解释**：`/rule-platform/sources` 关联 `rule_source_versions`，返回 `current_version/display_version/last_sync_at/sync_status`，不再全部显示“未同步/已同步”。

验证：`go test ./server/...` 全绿；部署 `ly-flow/server:v22` + `ly-flow/frontend:v13`；验收 30/30；`/debug/components` 顶层 `status=ok`；能力别名 PUT 200，YARA PUT 422。

遗留（需人工确认后执行，未自动删除）：历史误报事件（规则 `ptresearch-attackdetection-…-11003921`，已禁用）仍在 ClickHouse 中，可按规则 ID 清理。

## 2026-10-29 数据面补齐 + Wazuh 平替（server:v27 / frontend:v16）

### 规则源做加减法
- 分组：规则中心拆成「可更新源」与「本地与自建」，`updatable=false` 与用户自建源不再参与同步。
- 镜像：GitHub 源按顺序尝试 `raw.githubusercontent.com` → `cdn.jsdelivr.net` → `raw.gitmirror.com` → `ghproxy.net` → `gh-proxy.com`，结果记录实际命中的 endpoint。
- 同步语义：同步即「拉取 → 暂存 → 立即应用」，取消独立「应用规则」按钮；失败项逐条显示源名与原因。
- 删除：`ip-geo-attribution`（大屏已下线）、`snort-community`（与 ET Open 重叠）、`ptresearch-attackdetection`（上游 EOF、误报高）、`restricted-commercial`（占位源）。
- 修复：人工禁用规则在重新同步时不再复活；新源首次同步不再被误判为“全部禁用”。

### Agent 侧数据源（10.1.18.8 验证）
- 新增长原生日志采集 `LOG_SOURCES`：`name:path` 列表，nginx access/error 与 auth 日志；access 行做 `+`→空格与 URL 解码后再交给规则。
- `HIDS_ENABLED=true`：进程/文件/认证采集运行，runtime 事件进入 `telemetry:runtime`。
- YARA 引擎：安装 `yara 4.5.5`，把仓库 746 个规则文件合并、去重、剔除 `filename/filepath/extension` 等外部变量与无法编译规则，得到 5284 条可用规则包；自测 marker 命中并生成 artifact 告警。
- nginx 日志检测实测：XSS、SQL 注入、Web 扫描器、SSH root 登录均生成事件；遍历规则仅在日志保留 `../` 时触发（nginx 会先归一化路径）。

### Wazuh 平替与移除
- 调研结论：Wazuh 的日志采集/解码/规则能力已由 `LOG_SOURCES` + nginx/auth 解析 + `default-bundle` 规则覆盖；FIM/SCA/漏洞扫描不在本项目承诺范围。
- 移除：Agent 的 Wazuh supervisor/adapter 与 auth→Wazuh 告警转换；服务端 `wazuh` 引擎状态、desired state、native rules 扫描；`rules/wazuh/**`、`rules/subscriptions/wazuh-auditd`、上游版本映射。
- 保留：`xdr/converter/wazuh.go` 仅作为历史规则导入格式，不参与运行时。

### 验证
- `go test ./server/cmd` 全绿；agent/server 交叉编译通过。
- 规则中心：可更新源与本地源分组显示；同步失败项可见。
- 引擎健康：只剩 `suricata / yara / rasp`，YARA 在 10.1.18.8 上 `running`，`last_event_at` 为真实时间。
- 功能验收：**30/30**；`/debug/components` 顶层 `ok`；XDR 链数由 0 增至 20。

## 2026-10-29 规则追新与防御入口（server:v33 / frontend:v19）

- Sigma 全量接入：`sigma-full` 从 codeload 拉取，tar 内 YAML 多文档解析；只保留 Linux/unix、sshd/auditd/nginx/apache/cron/sudo、webserver，剔除 Windows/macOS/Azure 等无数据源产品，过滤纯数字/短词条件，上限 400 条。实测导入 218 条，active bundle 由 86 增至 286，其中 log_audit 116 条（原 10 条）。
- 清理：删除 DB 中 `snort-community`、`ptresearch-attackdetection` 及其 718 条规则，避免同步把它们拉回并制造误报。
- Bundle 基准改为数据库驱动：同步时以 `detection_rules`（排除当前源）为基集，不再继承旧 active bundle，删除的规则不会复活。
- 同步可观测：进度百分比、当前源、已应用/未变化/失败计数；本地/自建源不再出现在同步结果与计数中。
- 增量：内容摘要与上一版本一致时标记 `unchanged`，只刷新 synced_at，不重建/重新激活 bundle。
- 自动追新：`LYFLOW_RULE_SYNC_INTERVAL_HOURS` 默认 24h；`rule_platform.freshness` 与规则中心显示新鲜度。
- 资产运维新增「防御能力」页：按 Agent 展示 RASP 监控/YARA 扫描状态，可开关监控；阻断按钮明确标注“需签名 canary 策略”，未签名时 fail-safe 放行。
- 已知：ET Open 全量包在当前网络 180s 仍超时；其余源同步正常，失败项会在结果中如实显示。

## 2026-10-29 Incident 闭环与规则治理（server:v36 / frontend:v26）

- Incident 列表 `live=0` → `live=1`：修复“永远没有 Incident”，当前 17 条可见。
- Incident 标题可读化：UUID 实体不再作为标题，改为“资产 · 阶段 · 摘要”（如“目标资产 · 入侵突破阶段 · 2 个检测事件形成 2 阶段攻击链”）。
- Incident 负责人：抽屉新增负责人输入与保存，调用 `PUT /incidents/{id}/assign`，回读验证通过。
- 关闭原因：输入框改为始终可见，修复“点关闭才要求原因但输入框不显示”的死锁。
- 规则治理：规则中心新增「检测规则」面板，按 log_audit/runtime 拉取可治理规则（当前 128 条日志规则），支持逐条启用/停用；停用即重编译并激活 bundle（实测 200）。
- 服务端引擎规则合并所有类别（traffic/log_audit/runtime），不再只列 traffic。
- 剩余 P0：Incident 备注/证据包下载、响应执行闭环（dry-run/审批/回滚）、RASP 阻断签名入口、RBAC/多租户 UI、隔离区处置、通知/Webhook。

## 2026-10-29 处置闭环与备注（server:v37 / frontend:v29）

- Incident 处置动作：抽屉新增「处置动作」，支持封禁源 IP（L2）、隔离主机（L3，需审批）、仅观察（L1）；动作列表显示状态，可按权限批准/回滚。后端复用 `response` ActionManager（创建/自动批准/任务下发/回滚）。
- 回滚按钮按动作类型显示：block_ip、isolate_host、file_delete、account_disable、namespace_isolate 才提供回滚，避免 observe 这类无回滚适配的动作报错。
- Incident 备注：新增 `incident_notes` 表与 `GET/POST /incidents/{id}/notes`；抽屉可记录处置进展、判断依据、交接信息。
- 证据获取：新增「复制证据 JSON」，把 Incident 的证据事件导出到剪贴板（后续可换证据包下载）。
- 规则治理：检测规则面板支持逐条启停；YARA 命中面板显示最近 artifact 事件（规则名/文件/时间）。
- 已知：RASP 阻断仍受签名 canary 策略门禁，没有自动放开；ET Open 在当前网络 300s 仍超时，其他源增量正常。

## 2026-10-29 响应处置、备注与升级/备份（server:v38 / frontend:v30）

- Incident 处置动作：封禁源 IP / 隔离主机 / 仅观察；创建、审批、回滚走 `response.ActionManager`，回滚仅对有适配的动作显示。
- Incident 备注：`incident_notes` 表 + `GET/POST /incidents/{id}/notes`；证据支持复制 JSON。
- 规则治理：检测规则面板支持逐条启停（log_audit/runtime），停用即重编译；YARA 命中面板展示最近 artifact 事件。
- 升级与备份：`/debug/components` 新增 `versions`、`backup`、`ops.backup`；Settings 新增「升级与备份」面板，展示 server/frontend 镜像标签、备份目录文件、可复制的备份与回滚命令。备份目录 `/opt/lyflow-backup` 只读挂载到 `/backup`。
- 备份/回滚执行仍在宿主机（容器内无 pg_dump/clickhouse-client），平台只展示状态与生成命令，避免越权重启容器。
- RASP 阻断：`agentpolicy.Promote` 对 block 模式仍返回 `ErrProductionBlockDisabled`，且 canary ACK 与阻断策略存在设计冲突；没有绕过门禁，需先补 dry-run 模式与 canary 批准流程。

## 2026-10-29 数据清理与卡顿修复（server:v39）

- 根因：Sigma 全量规则产生 24 万条 `threat_events`，事件聚合查询超过 30 秒，UI 卡在“正在读取样本”。
- 处置：
  - 先做 PG 备份 `/opt/lyflow-backup/pre-clear-*.dump`（27 MB）。
  - 停用 `sigma-full` 全部规则并重建 bundle（286 → 86），阻断洪水来源。
  - 清空 `threat_events`、`incidents`、备注/证据/审计、XDR 图与链、投影/隔离表。
  - 清空 ClickHouse `lyflow_security_events`、`lyflow_events_v2`、`lyflow_traffic_sessions`、`lyflow_events_1m/1h`。
  - 清空 Redis `alerts:*`、`telemetry:*`、`flows:*`、`sessions:*`、`component_alerts:*` 等流，重启安全引擎。
- Incident 列表瘦身：列表不再携带 `events/attack_chain/stage_groups`，20 条从 263 KB 降到 17.9 KB。
- 清理后接口：events 0.05s/15.7 KB、incidents 0.12s/17.9 KB、stats 0.01s。
- 说明：17 条 Incident 与 99 条事件是清理后新产生的实时数据；如需完全空白，需暂停采集或再次清库。

## 2026-10-29 RASP 阻断闭环与告警重复计数修复（server:v44）

### 根因
- RASP 探针把自身每 30 秒到本地 bridge 的配置拉取连接当成 `network` 事件上报，形成自激噪声。
- legacy 事件没有稳定 id，bridge 每次用 `time.Now()` 生成新 id；spool 重放一次就变成一条新告警。
- 同一个 RASP 事件同时命中原生 `rasp-sqli-default` 与 OWASP CRS `942120/942140`，安全引擎把所有命中都写成告警。
- 汇总页把每条告警的 `occurrence_count` 相加，重复告警叠加成 1,624 次命中。

### 修复
- 探针只上报敏感文件读、命令执行、SQL、metadata SSRF；不再上报普通 socket 连接和文件写入。
- 探针生成稳定 `event_id`；legacy 事件无 id 时用 payload SHA-256 摘要生成稳定 id。
- 安全引擎对同一个 RASP 事件只保留最高优先级告警（原生 `rasp-*` 优先，其次分数）。
- 服务端把 `blocked` / `would_block` / `policy_version` / `policy_id` 写入事件并用于统计。
- 清理测试 RASP 告警与 `telemetry:rasp` / `alerts:rasp` 流；当前窗口从 1,624 次/27 组降到 144 次/10 组。

### RASP 阻断实测
- 创建签名 block canary（version 2），Agent ACK 后 `mode=block / block_on_hit=false`，只上报 would-block。
- 完成 canary 并提升为 active 后，Agent 下发的 bridge 配置为 `block_on_hit=true`。
- 实测：`os.system("id; rm ...")` 与 `sqlite3.execute("SELECT 1 UNION SELECT 2")` 均抛出 `LyFlow RASP blocked`，事件 `blocked=true`。
- 回滚到 monitor（version 1）后，同样调用恢复执行，`block_on_hit=false`。
- 当前保持 monitor；阻断能力已完整可用，不会默认开启。

## 2026-10-29 总体大改第一批（server:v51 / frontend:v35）

### 告警噪声与证据
- 安全引擎增加 match-all 正则防护与 RASP 心跳跳过；`(?i)`、空分支规则不再产生告警。
- RASP 探针不再上报普通 socket 连接和文件写入；事件带稳定 `event_id`；legacy 事件用 payload 摘要生成稳定 id。
- OWASP CRS 转换改为完整 SecRule 解析，跳过不可转换和匹配空串的规则。
- RASP 心跳误报清除；当前 RASP 事件数为 0，总览从 1,624 次/27 组降到 24 次/2 组。
- Incident 证据保留原始规则名、来源引擎、阶段判定、首次时间；阶段组按真实时间排序，不再把 `component.alert` 当标题。
- YARA/artifact 事件允许落入 `threat_events`，为检测面 YARA tab 提供数据。

### 页面收缩
- 导航隐藏「数据与健康」；系统管理新增「开发者」入口跳转 `/health`。
- 总览：处置态势只保留分诊/处理中/闭环；「热源→目标」改为「情报源→受害 Agent」，Agent 侧只显示可编辑 Agent 名。
- Incident：三态（已分诊/处理中/闭环）、紧凑抽屉、处理人手填、处理意见、开启防护/观察二选一、单保存按钮；闭环后只追加记录。
- 事件：主机运行时/RASP/日志只显示受害 Agent；同源同目的同情报按滚动 1 小时聚合；原始载荷折叠、长 ID 缩写。
- 资产详情：去掉采集能力，显示 CPU/内存/磁盘；列表点名字直接改名；删除仅在离线详情底部；采集能力只允许流量开关。
- 规则中心：隐藏本地与自建；检测规则每页 10 条；YARA 命中移到检测面第四个 tab。
- 详情抽屉统一收窄到 `min(38vw, 520px)`，长 ID 缩写，原始 JSON 折叠。

### 未完成（下一批）
- 资产防御能力：监控/阻断切换、tag 分组自动值守、整体防护会话。
- RASP 请求级：OpenRASP + Coraza sidecar、CRS 虚拟补丁、canary→block。
- 流量引擎：Suricata ET Open 子集、lyprobe + NetFlow collector + Vector、规则归属去重。
- Sigma/Falco 构建期转换器和定时更新调度器。

## 2026-10-29 页面问题修复（server:v52 / frontend:v37）

- 事件/检测面文案改为「受害服务器」，不再把受害对象叫 Agent。
- 运行时事件缺 `agent_id` 时用 `asset_id/hostname` 映射到服务器名，不再显示「未知 Agent」。
- 事件抽屉徽章恢复为紧凑横排，长 ID 缩写，原始载荷折叠。
- 检测面探针列加载 Agent 列表映射服务器名；空态统一为「暂无情报」。
- 资产详情删除按钮只显示「删除」，在线时置灰并给出说明；详情标签改为「服务器名称 / 服务器 ID」。
- 修复流量开关：Agent 配置接口不再用 capability 覆盖数据库 `traffic_enabled`，关闭后配置下发为 false；重新开启需等待下一次配置拉取。
- 规则中心「引擎规则」按四类归并：系统检测引擎、Web 检测防护引擎、流量聚合引擎、病毒扫描引擎。
- YARA/artifact 事件允许写入 `threat_events`，为检测面 YARA tab 提供数据。

## 2026-10-29 UI 修正（frontend:v38）

- 事件详情「技术详情 / 原始载荷」默认展开，不再折叠。
- 检测面详情抽屉收窄到 `min(38vw, 520px)`，与事件详情一致；KV 行、原始载荷更紧凑。
- 总览「情报源 → 受害服务器」修复 `asset_id/payload.agent_id` 映射，不再出现「未知 Agent」；运行时事件来源不是监听 IO，而是运行时进程事件缺 `agent_id`。
- 资产详情删除只保留一个「删除」按钮，在线置灰；去掉额外说明文案。
- 资产运行信息改为 CPU/内存/磁盘进度条 + 负载/运行时长。
- 采集能力矩阵只允许流量开关；切换后立即乐观更新，并提示等待 Agent 拉取；后端数据库开关为唯一权威。
- 防御能力 UI 简化：顶部只保留当前模式、演练命中、已阻断；操作收敛为「开启阻断演练 / 完成演练 / 提升为阻断 / 回滚 / 紧急停止」，高级参数折叠。
- 规则中心「可更新源」按四类引擎归并：系统检测、Web 检测防护、流量聚合、病毒扫描；显示自动更新频率、最近同步、状态和手动更新。

## 2026-10-29 资产/防御/规则源二次修正（server:v53 / frontend:v39 / agent uptime）

- 资产详情恢复「负载 / 运行时长」：Agent 采集 `/proc/uptime`，资产 API 暴露 `load_avg_1/5/15` 与 `uptime_seconds`。
- 删除按钮从详情抽屉移到资产表格「详情」后面；在线置灰，离线可点，详情内不再放删除。
- 运行信息改为 CPU/内存/磁盘进度条。
- 防御能力删除演练类 UI：每个服务器行只保留「切换为阻断 / 切换为监控」；阻断后端自动走签名策略并轮询提升。
- 规则中心规则源按四类引擎归并，显示自动更新频率和手动更新；病毒扫描引擎在无上游时显示 Agent 本地 YARA 规则包。
- 采集能力切换增加乐观更新和「等待 Agent 拉取」提示。

## 2026-10-29 YARA 本地导入（server:v54 / frontend:v41）

- 不接外部 YARA 上游；新增本地导入路径 `/data/yara/imported.yar`。
- 新增 `GET/DELETE /api/v1/rule-platform/yara` 和 `POST /api/v1/rule-platform/yara/import`。
- 导入支持 multipart 文件，校验大小、空内容、`rule`/`{` 结构；原子写入。
- `/api/v1/agent/yara/rules` 合并内置 `*.yar` 与导入文件，Agent 可下载完整规则包。
- Agent 在每次 YARA 扫描周期拉取一次规则包，内容变化时原子替换本地 `rules.yar`。
- 规则中心新增「病毒扫描引擎 · 本地规则导入」面板：显示总规则数、内置、导入、大小、更新时间、导入路径；支持导入/清空。
- 病毒扫描引擎仍不接外部上游，UI 显示「无上游（本地/构建产物）」。

## 2026-10-29 P1/P2/P3 并行交付（server:v55 / frontend:v42）

### P1 整体防护与自动值守
- 新增 `defense_sessions` / `defense_schedules` 表与审计事件。
- 防护会话状态机：`dry_run → active → stopped/expired/failed`；失败回滚 monitor。
- 自动值守：tag 分组、每日时段、优先级、5 分钟 dry-run、窗口结束回监控、单活阻断会话。
- API：`/defense/status`、`/defense/sessions`、`/defense/schedules`、`/defense/audit`。
- 防御页：当前会话倒计时、手动会话、自动值守规则表、启停/删除；两个切换按钮改为会话 API。
- 实测：monitor 会话创建/停止、block 会话 canary 创建/停止、规则创建/删除均 200/201。

### P2 流量引擎规则集
- 新增 `rules/scenarios/server-zone.yaml` 与 `server/cmd/traffic_rule_profile.go`。
- 服务器区过滤：方向、类别、协议、入站端口、预算、signature_hash 去重、双引擎归属。
- 实测仓库语料：输入 169，接受 87，Suricata 78 / lyprobe 9，overlap=0。
- 导出 `/app/rules/compiled/server-zone/suricata.rules`、`lyprobe-source.rules`、manifest。
- API：`/traffic/rule-profile`、`/traffic/rule-profile/export`。
- `rules/scenarios/server-zone.yaml` 已上传至 `.241` 的 `/opt/ly-flow-platform/rules/scenarios/`。

### P3 RASP 请求级
- 新增 24 条 CRS PL1–2 请求侧虚拟补丁规则。
- API：`/rasp/request-rules/status`、`/rasp/request-rules/download`（公开，供探针下载）。
- Python `ly_rasp` 新增请求级中间件、规则加载、请求/Sink 去重；monitor/dry-run/block 三态。
- 已部署 `ly_rasp` 包到 10.1.18.8 `/opt/ly-agent/rasp/python/ly_rasp`，规则包下载到 `/etc/lyflow/rasp/request_rules.json`。
- 实测 block 模式 SQLi 请求抛出 `RASPRequestBlocked`。
- 请求级中间件需应用侧接入 WSGI/ASGI；单文件 `sitecustomize.py` 仍是 Sink 级。

## 2026-10-29 P2/P1/P3 收尾（server:v58 / frontend:v45）

### P2 流量规则集导出过滤
- `server/cmd/traffic_rule_profile.go` 新增 Suricata 不支持关键字过滤：`method`、`icmp.icmp_type`、`ja3_hash`、`ja3_string`、`tcp.options`。
- 新增 `dropped_unsupported` 计数与 `unsupported keyword` skip 原因。
- 实测：输入 169，接受 66（Suricata 57 / lyprobe 9），`dropped_unsupported=31`，`overlap=0`。
- 导出文件直接通过 `suricata -T`：57 rules loaded, 0 failed；已重启 sensor 加载 57 条。

### P1 自动值守与回滚收敛
- 新增 Agent 标签 API：`GET/PUT/POST /api/v1/agent/tags/{agent}`，标签规范化为小写 `[a-z0-9._-]`，最多 16 个。
- Assets 资产详情新增「防御标签」编辑；`.8` 实测写入 `prod, web`，`defense/status` 返回 `tags:[{prod:1},{web:1}]`。
- 修复回滚死循环：
  - 服务端：`/api/v1/agent/config` 收到已被回滚版本的 ACK 时不再 409，记录 `RASP policy ACK superseded` 并返回当前 assignment。
  - Agent：允许回退到当前策略显式指定的 `rollback.target_version`，其他降级仍按 stale 拒绝。
- 真实时间窗实测（tag=prod，21:29–21:49，dry_run=300s）：
  - 21:24:29 窗口前 5 分钟创建 canary，`dry_run`；
  - 21:29:03 自动 promote 为 `active`，服务端 `mode=block`、`enforcing=true`；
  - 21:49 窗口结束自动 expire 并回 monitor（`mode=monitor`、会话 `expired`、`/rasp/policy` active 回到 v1 monitor），Agent 配置拉取无 409。

### P3 请求级验证
- `ly_rasp` WSGI/ASGI 中间件在未显式 `load_config()` 时从环境自动引导配置。
- 新增回归测试 `test_wsgi_middleware_bootstraps_config_from_env`（25 个请求级测试通过）。
- `.8` 实测：
  - monitor：SQLi 命中 1 条，`would_block=false`，放行；
  - block dry-run：`would_block=true`，`blocked=false`，放行；
  - block enforced：抛 `RASPRequestBlocked`，真实 HTTP 请求（systemd 托管的 WSGI 应用）返回 403、`X-Ly-RASP-Blocked` 生效。
  - 修复 WSGI 403 响应携带 hop-by-hop `Connection: close` 导致 wsgiref 报 500 的兼容问题，并加回归断言。

### Suricata 规则挂载持久化
- 主机新增 `/opt/ly-flow-platform/suricata/lyflow-suricata-profile.yaml`，`rule-files` 指向 `server-zone/suricata.rules`。
- `docker-compose.override.yml` 为 `ly-suricata-sensor` 增加只读挂载：
  - profile 文件；
  - `/opt/ly-flow-platform/rules/compiled/server-zone` → `/var/lib/suricata/rules/server-zone`。
- 重新创建 sensor 后仍加载 57 条规则、0 失败；平台再次导出会原子更新同一个目录。

### UI
- Rules 页「流量引擎规则集」移动到「四类引擎规则源」之前，首屏可见。
- `index.html` 增加 build 标记与 no-cache meta；Nginx 对 `/index.html` 返回 `Cache-Control: no-cache, no-store, must-revalidate`，避免旧 index 缓存导致新面板不显示。

## 2026-10-29 借鉴上游 ly_probe，打通服务器区流量探针（server:v58 / frontend:v45）

上游：`https://github.com/Abyssal-Fish-Technology/ly_probe`，固定 revision
`06c097dd5c69e391efd3c8b3776d672e03386e49`。

### 构建与部署
- 从上游源码构建 lyprobe（含 `0001-hot-reload.patch`）：
  - `lyprobe`、`liblyprobe-1.0.0.so`、`plugins/servicePlugin.so`
  - `fp-patterns/` 116 条指纹（44 protocol / 15 device / 16 os / 25 midware / 16 threat）
- 部署到 `.241`：
  - `/opt/ly-flow-platform/lyprobe/`
  - `/opt/lyflow/bin/lyflow-netflow-collector`
  - `/etc/lyflow/netflow.env`（sensor-241 的 agent 凭据，0600）
- 新增 systemd：
  - `lyflow-netflow-collector.service`，UDP/9995
  - `lyflow-lyprobe.service`，`ens192`，`-d 15 -t 60`
- 新增传感器 Agent `sensor-241`（`aa072c61-33ed-48c2-935d-d8442a19b1af`），
  平台流量页显示 `capture_source=lyprobe`。

### 实测
- 已写入 18,000+ 条 lyprobe 会话；平台 `/api/v1/traffic/sessions` 可见。
- 服务识别：
  - `SRV_TYPE=Service`、`SRV_NAME=HTTP`、`SRV_VERS=1.0`
  - TLS 流量识别为 `Service/TLS`
- 威胁识别：
  - 明文 `GET /?x=1 union select 1 HTTP/1.1` 命中 `THREAT_TYPE=SQL`、`THREAT_NAME=CRUD`
  - collector 日志：`threat matched rule=SQL name=CRUD ...`
  - Postgres `traffic_sessions.raw_event->'content'->>'threat_type' = SQL`（双向记录都有）
- 规则热加载：原子替换 threat.json 后日志出现 `Hot-reloaded 116 patterns`。

### collector 修复
- `server/cmd/netflow-collector` 增加威胁方向缓存：正向/反向记录共享同一 flow key，
  匹配方向先写入缓存，另一方向发布时补齐 `threat_type/threat_name`。
- 发布 worker 改为 16、队列 32768；按包级缓存威胁后再发布，兼顾吞吐与方向关联。
- 新增 `threat matched` 日志和 `threat_cache_test.go`。
- component-alert 的 `source_engine` 改为契约允许的 `dpi_engine`（`lyprobe` 不是合法
  source_engine，之前被 400 拒绝）；缓存方向不再重复生成告警。
- 实测一次 SQLi 只生成 1 条 `threat_events`：
  `CRUD 10.1.18.241:18104 -> 10.18.3.67:25931`。

### 已知限制
- `.241` 上 lyprobe 抓 `ens192`，会看到平台自身的管理流量；BPF 过滤在 systemd
  unit 中带空格会漏抓，暂不使用过滤。
- 平台会话落库约滞后 2–3 分钟（Redis -> consumer -> Postgres/ClickHouse）。
- collector 的 component-alert 已落库到 `threat_events`（`source_engine=dpi_engine`），
  同一 flow 只产生一条告警。
- 未启用 Vector；lyprobe 走自有 NetFlow collector，不依赖 Vector。

## 2026-10-30 引擎健康、误报收敛与规则同步（server:v59 / frontend:v46）

### UI
- 按需求移除规则中心「流量引擎规则集」面板；前端 v46。
- 验收 A15.8 改为校验面板已移除。
- `acceptance.py` **38/38**。

### 误报收敛
- 日志审计：移除“成功 root 登录”默认规则，DB 中
  `log-ssh-root-login-default` 置 disabled；重新编译激活 bundle（619→618）。
  实测成功 SSH 登录不再产生新事件。
- Runtime：`processDeltaCollector` 丢弃 `low/new-process`；`authLogCollector`
  不再把成功 root 登录作为 runtime 告警。Agent 已重新构建并部署到 `.8`。
- 保留 `log-ssh-failure-default`，失败/异常登录继续告警。

### YARA
- 原扫描路径只有 `/opt/ly-agent/yara/scan`，只命中自测标记。
- `agent.env` 与代码默认改为：
  `/opt/ly-agent/yara/scan,/tmp,/var/tmp,/dev/shm,/var/www,/usr/local/bin,/root,/home`，
  周期 3600s，超时 300s。
- 实测扫描到 `/tmp`；发现并删除 `/tmp/yara-src` 规则源码自匹配缓存。
- 扫描启动日志会打印生效路径，便于确认配置。

### 规则同步
- 修复 `rule_platform.go` 未把生成的 version 回填到 request 的 bug：
  `rule.source.discover.attempt` 的 resource 为空，导致
  `controlaudit: incomplete audit entry`，所有上游同步失败。
- 实测：
  - ET Open 200 `unchanged`，hash `c6234647...`
  - Falco 200 `unchanged`，hash `30a1a602...`
  - Sigma 200 `unchanged`，hash `8e0302ef...`
- 上游可达、fetch/hash/compare 正常；真实内容变更后的 `activated=true` 待下次验证。

### 引擎健康结论
- RASP：monitor，102 allowed，0 blocked；请求级/in-process 验证通过；业务应用
  事件到 bridge 未完全验证，PHP/Java/Node/.NET 未接真实应用。
- Runtime：464 条/24h 主要是进程噪声，已收敛。
- YARA：17,691 条内置规则，已扩展到真实目录并周期扫描。
- 日志审计：auth/nginx，SSH 成功登录噪声已移除；仍有重复日志事件待去重。
- 已知部署缺口：`.8` 访问不到 `.241:6379`，RASP control health 显示
  `health_store_unavailable`；需要单独解决 Redis 可达性。

新增文档：
- `docs/dev/ENGINE-HEALTH-2026-10-30.md`
- `docs/dev/TRAFFIC-ENGINE-COUPLING.md`

## 2026-10-30 继续收口：RASP 事件链路、Redis 可达性、规则同步（server:v60）

### RASP
- 独立 WSGI 应用只挂 middleware、未调用 `enable()` 时，`_report_match` 现在会懒初始化
  `Reporter`，请求级命中可以上报。
- 真实 SQLi 已验证进入 `telemetry:rasp`：
  `event_type=rasp.sql`、`rule_id=request-sqli-owasp-crs-942270`。
- `/api/v1/rasp/events` 默认过滤 `rasp.protection.heartbeat`，避免心跳把攻击事件挤出第一页；
  需要心跳时加 `include_heartbeat=1`。

### Redis 可达性
- `.241` 新增 `lyflow-redis-proxy.service`：
  `socat TCP-LISTEN:16379,bind=10.1.18.241 -> 127.0.0.1:6379`；
  iptables 仅允许 `10.1.18.8` 访问 16379。
- `.8` agent.env 增加 `REDIS_SERVER=10.1.18.241:16379` 与 `REDIS_PASSWORD`。
- 清理损坏的 `/opt/ly-agent/data/spool/v2`（保留 `v2.corrupt.*` 备份），
  `transport spool corrupt` 错误消失，RASP health store 不再报错。

### 规则同步
- `rule_platform.go` 修复：生成 version 后回填 `req["version"]`，避免
  `rule.source.discover.attempt` 的 resource 为空导致 `incomplete audit entry`。
- 实测 ET Open / Falco / Sigma 均 200 `unchanged`，上游 fetch/hash/compare 正常。

### 其他
- 前端 v46 已移除流量规则面板。
- 验收 38/38。
- 新增 `docs/dev/ENGINE-HEALTH-2026-10-30.md`、`docs/dev/TRAFFIC-ENGINE-COUPLING.md`。

## 2026-10-30 真实防护实装 + 镜像检测实例 10.1.18.125

### 真实 RASP 防护
- 在 `.8` 用真实 WSGI 应用 + `ly_rasp` block 模式验证：
  - 良性 200；
  - SQLi / XSS / 路径穿越 / 编码穿越 / POST SQLi 全部 **403**；
  - defense 会话 dry_run → active → stop/expire 回 monitor。
- 修复探针真实缺陷（已回源到仓库 `bridge.py`）：
  - 分离 bootstrap 配置凭据与轮换事件凭据；
  - 事件 401/403 时用 bootstrap 强制刷新配置并重试一次；
  - 把签名策略 `expires_at` 写回配置，到期自动降级 monitor。
- Agent 侧新增：
  - RASP 事件同时写 `component_alerts:v2`，XDR 不再只看 telemetry；
  - YARA 命中直接发布 component alert，修复初次扫描被 adapter 漏读；
  - 日志采集器只启动一次，修复每 30s 重复启动与 FD 泄漏。
- 实测：YARA component alert 21 条、RASP `request-sqli-owasp-crs-942270` component alert 1 条。

### 镜像检测实例
- 新建 ESXi VM `lyflow-mirror`（`10.1.18.123` 宿主）：
  - 4 vCPU / 8 GB / 40G
  - `mgmt0` 10.1.18.125/24
  - `mirror0` = `mirror port`（vmnic4，VLAN 4095，Promiscuous）
- 安装完整流影平台，升级 `server:v60` / `frontend:v46`。
- Suricata 已加载 57 条 server-zone 规则，抓 `mirror0`，4 threads。
- local-mirror 抓 `mirror0`，持续写 sessions/flows。
- 首次观测：mirror0 15万+包、EVE 8.2万行、82 alerts（77 Fscan UDP、5 DNS tunnel），9/9 服务 healthy。
- 新增每小时观测：
  - `lyflow-hourly-observe.timer`
  - `/var/log/lyflow/hourly/*.json|summary.log|latest.md`
  - 检查服务、CPU/内存、mirror0 增量、Suricata/local-mirror 错误、API/组件/引擎/RASP/流量。
- 入口：`https://10.1.18.125/`，`admin / Lyflow@2026`（自签证书）。

### 文档
- `docs/dev/MIRROR-SENSOR-125.md`
- `docs/dev/RASP-REAL-PROTECTION-2026-10-30.md`

## 2026-10-30 镜像实例首轮观测与误报修复

### 10.1.18.125 流影镜像实例
- 完整平台已部署：`server:v60` / `frontend:v46`，9/9 服务 healthy。
- `mirror0` 真实收包，Suricata 57 条规则 + local-mirror 均抓镜像口。
- 自动小时观测已跑第一轮（18:00 UTC）：
  - warnings 0
  - mirror0 rx_packets=305,268、rx_dropped=24、较上次 +7,739
  - EVE 14,889 行、3 条 alert
  - 9/9 服务 healthy
- 误报修复：
  - `LY-FSCAN-003` 原规则只有 30 包/60s 阈值，正常 DNS 被误判为 Fscan UDP 扫描，
    短时间产生 757 条告警。
  - 加 `dsize:0;` 后 90 秒 EVE 14,889 行只有 3 条 alert，Fscan 误报消失。
  - 同步更新 `rules/ly-custom/scanner.rules` 与 `.125`/`.241` compiled 规则。
- 仍需观察：`ET TROJAN High DNS Query Count Possible Tunnel`
  （10.1.0.4 → 114.114.114.114:53）是否为正常 DNS 客户端。

### Agent 检测链路
- YARA 命中现在直接发布 component alert；实测平台出现 21 条 YARA 事件。
- RASP 事件现在同时发布 component alert；实测
  `request-sqli-owasp-crs-942270` 进入 component_alerts。
- 日志采集器单次启动，FD 降到约 50，未再出现每 30s 双份采集。
- 清空损坏 spool 后，未再出现 `transport spool corrupt`。

## 2026-10-30 告警降噪与规则源码优化

### 逐条处理 8 类真实告警
- SID 9003023（792 条）：正常 DNS 被当 UDP 扫描；规则源补 `dsize:0;`。
- SID 1000050（272 条）：DNS 隧道规则改为“24+ 位、纯字母数字、含数字”
  标签，`flow:to_server`，阈值 5/60。
- SID 9002003（195 条）：同一收紧策略；`content:!"sru.edu.cn"` 排除已停用域名。
- SID 9001005（162 条）：原规则匹配所有 TLS `17 03`；重写为 FRP 默认
  控制端口 7000 的 TLS 建连检测。
- SID 9001009（46 条）：增加 `flow:to_server` + `http.request_header`。
- SID 9007022（12 条）：根因是响应包目的端口恰好为 65010；增加
  `flow:to_server` 修复。
- SID 9004301（8 条）：知网代理转发页面误报；只匹配脚本后缀响应。
- SID 9004601（6 条）：前端 JS 误报；只匹配脚本后缀响应且三标记同时出现。

### 结果
- 规则平台重新导出：suricata 57 / lyprobe 9，overlap 0。
- `.241`、`.125` 均 `suricata -T` 通过，57/57 加载。
- `.125` 新窗口：EVE 30,206 行，alert 0，9/9 服务 healthy。
- 离线 PCAP 验证：
  - 6 条长标签 DNS 查询触发 1000050、9002003；
  - `shell.php` 响应体含 `WScript.Shell` 触发 9004301 规则形态。

### ops.backup
- `server/cmd/debug.go`：空但可读的备份目录判为 `ok`，
  消息 `backup directory ready, no backups yet`。
- 新增 `server/cmd/debug_backup_test.go`（空目录 / 有文件 / 不存在）。
- 构建并部署 `server:v61` 到 `.241`、`.125`。
- 结果：`.241` ok（count=3）、`.125` ok（count=0），组件非 ok 归零。

### 文档
- `docs/dev/ALERT-TUNING-2026-10-30.md`
- `docs/dev/MIRROR-SENSOR-125.md` 更新

## 2026-10-30 确认告警：SMB Negotiate over 8080

- 告警报文：`121.43.119.139:36780 -> 10.3.10.74:8080`，222 字节。
- 解码：NetBIOS Session 头 `00 00 00 A4` + SMB1 `FF 53 4D 42 72`
  （`SMB_COM_NEGOTIATE`），方言包含 `Samba`、`NT LM 0.12`。
- 判定：真实告警。SMB 出现在 8080 属于扫描、SMB-over-HTTP 隧道或漏洞探测。
- 旧 SMB 规则经过单模式转换后丢失端口/配套条件，出现 `^.{27}`、
  `|00|` 等泛匹配；v62 门禁已将其移出运行时。
- 新增精确规则 `LY-SCAN-004` / SID 9003024：
  - 外网 → 内网；
  - 排除 139/445；
  - `content:"|FF 53 4D 42 72|"; offset:4; depth:5;`
  - 每源 5 分钟 1 条。
- 用告警原文重建 PCAP（含三次握手）离线验证：SID 9003024 命中 1 次。
- `.125`、`.241` 规则数 58，`suricata -T` 全部通过。
- 文档：`docs/dev/ALERT-TUNING-2026-10-30.md`

## 2026-10-30 规则转换自查：端口/配套条件丢失

- 审计 5 个外部源、52,453 条原始 Suricata 规则。
- 发现 531 条活动流量规则中 335 条存在端口/方向/偏移等约束丢失。
- v63 新增强制门禁：
  - 丢失端口/响应方向/offset/depth/within/byte_test/urilen/threshold
    且特征 <12 位 → `unsupported:lost_match_constraints`；
  - 裸域名、常见词、二进制 `contains`、特征 <6 位 → 拒绝。
- 处理结果：
  - 活动流量规则 531 -> 186；
  - `detection_rules` unsupported 1,097；
  - `.125` `threat_events` 0。
- 典型：IRC PRIVMSG/USERHOST、SIP REGISTER/INVITE、SMB 445、
  FTP banner、SMTP 头、OISF traffic-id 域名。
- 解析器版本升到 `2026-10-30.4`，同步时强制重建 bundle。
- 文档：`docs/dev/ALERT-TUNING-2026-10-30.md`

## 2026-10-30 默认规则降噪

- 下线 `dpi-admin-access-default`（内部 `/admin` 访问误报）。
- 下线 `log-collector-heartbeat-default`（心跳不是威胁事件）。
- 源码新增 `retiredDefaultDetectionRuleIDs`，启动/同步时禁用旧库中的同名规则，
  防止重装或重同步复活。
- `dpi-c2-domain-default` 收紧为按域名标签边界匹配，去掉 `callback/beacon/.xyz` 泛匹配。
- 已清理事件：
  - `.125` `dpi-admin-access-default` 5 条；
  - `.241` `log-collector-heartbeat-default` 155 条。
- 活动 bundle 已确认不含两条下线规则；`.125` `threat_events=0`。
- 文档：`docs/dev/ALERT-TUNING-2026-10-30.md`

## 2026-10-30 检测能力与主动防御验收

- 转换器保真审计：52,453 条原始规则；活动流量规则 531 -> 185。
- 新增门禁：丢失端口/方向/偏移等约束且特征 <12 位、裸域名、常见词、
  二进制 `contains`、特征 <6 位 -> `unsupported`。
- 默认规则：
  - 下线 `dpi-admin-access-default`、`log-collector-heartbeat-default`；
  - 收紧 `dpi-c2-domain-default`、`log-privilege-escalation-default`、
    `runtime-suspicious-download-default`；
  - 清理事件 5 + 155 条。
- Suricata：58 条规则，`overlap=0`；SMB/DNS/WebShell 合成流量命中验证通过。
- RASP 主动防御：
  - defense 会话 dry_run -> active -> stopped；
  - SQLi / XSS / 路径穿越均 403，benign 200；
  - 修复探针首个请求使用旧配置的问题（判定前刷新 + 默认 5s）；
  - 停止后 SQLi 恢复 200。
- 运行时终止：
  - `process_kill` L3 双人审批；
  - 测试 PID 被终止，`verified=true`。
- 验收：`acceptance.py` 38/38；Go 转换/默认规则测试通过；
  RASP Python 测试 31 passed。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`

## 2026-10-30 主动防御时延优化

- 问题：
  - 手动建立 block 会话到 `block_on_hit=true` 约 57.5s；
  - stop 后 bridge 回 monitor 约 24.7s，探针最长再等 30s。
- 根因：
  - Agent 配置轮询固定 30s；
  - 防御运行时 tick 固定 30s；
  - 探针配置刷新 30s。
- 修复：
  - Agent 新增 `ConfigPollInterval`，默认 5s，
    支持 `AGENT_CONFIG_POLL_INTERVAL` / `agent.config_poll_interval`；
  - `DefenseRuntime` tick 改为 2s，支持 `DEFENSE_TICK_INTERVAL_SECONDS`；
  - 探针在请求判定前刷新 `/config`，默认刷新间隔 2s。
- 结果：
  - dry_run=5s：创建会话到 `block_on_hit=true` 8.3s；
  - dry_run=10s：约 13s；
  - stop 到 bridge monitor 2.2s，SQLi 立即恢复 200。
- 部署：`server:v66`、`.8` 新 agent 二进制。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 拓扑纠正：.241 管理平台、.125 抓包环境

- 明确拓扑：
  - `.241` 管理/分析平台，不安装 Agent、不启用本地抓包；
  - `.125` 抓包镜像环境，`mirror0` 接真实流量，检测升级在此验证。
- 清理历史 `sensor-241`：
  - 删除 agents 1、hosts 1、agent_identities 3、CRUD 事件 3；
  - 均先写入备份表。
- `.241` 停止 `ly-local-mirror`，compose override 增加 `profiles: ["capture"]`，
  默认不再启动。
- `agents` 表新增 `kind`（agent/sensor）：
  - 历史 `lyprobe%` 自动迁移为 sensor；
  - `/api/v1/agents` 默认只返回 agent；
  - `include_sensors=1` 仅供诊断。
- 验收：`.241` agents 只有 ubuntu；`.125` 无 agent、mirror0 抓包正常；
  `acceptance.py` 38/38。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 .125 升级为生产测试环境

- `.241` 只做管理/分析，不再用于抓包测试。
- `.125` 升级到 `server:v67` / `frontend:v46`。
- 同步完整规则源（scenario、suricata、ly-custom、default-bundle），
  重新导出：Suricata 58 / lyprobe 9 / overlap 0。
- Suricata 重启并加载 58/58；mirror0 持续收包。
- `.125` 执行 `acceptance.py`：38/38。
- 后续检测/主动防御测试统一使用 `.125`。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 .125 传感器基础镜像重建

- 重建并部署：
  - `ly-flow/security-engine:v67`
  - `ly-flow/local-mirror:v67`
  - `ly-flow/suricata-profile:v67`
- `ly-server` 仍为 `server:v67`，前端 `v46`。
- 验证：
  - 9/9 服务 healthy；
  - Suricata 58/58；
  - `mirror0` 30,001,993 包并持续增长；
  - `threat_events=0`；
  - `.125` `acceptance.py` 38/38。
- `local-mirror` 因缺少 release 签名私钥，镜像内设置
  `AGENT_REQUIRE_BINARY_INTEGRITY=false`；后续应重新签名并移除。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`

## 2026-10-30 Agent 签名密钥更新与 .8 升级

- 生成新的 Ed25519 release key：
  `/opt/lyflow/keys/agent-release.key`（构建机，权限 600）。
- 重新签名最新 Agent：
  - `agent-integrity-root.pem`
  - `agent-binary.digest.json`
  - `agent-config.digest.json`
- `10.1.18.8`：
  - 安装新 Agent 二进制和新的 trust root/digest；
  - 开启 binary/config integrity；
  - 服务 active，RASP bridge 200。
- `10.1.18.125`：
  - `ly-flow/local-mirror:v68` 内置同一套签名文件；
  - 完整性校验开启，不再使用 `AGENT_REQUIRE_BINARY_INTEGRITY=false`；
  - mirror0 持续收包，`acceptance.py` 38/38。
- 私钥只保存在构建机，不进入仓库/镜像，需要离线备份。
## 2026-10-30 抓包运行观测与 WAF/升级包误报修复

- `.125` mirror0：约 956 pps / 690 KB/s，累计 32,025,044 包，丢包 652。
- 9/9 服务 healthy；local-mirror v68、Suricata v67、58/58 规则。
- 最近 15 分钟会话 13,017；TCP 11,376 / UDP 1,622 / ICMP 19。
- 发现并修复两类误报：
  - 华为云 WAF 随机子域被 DNS 隧道规则命中 -> 两条规则排除
    `huaweicloudwaf.com`；
  - 瑞星升级包 `.zip` 被 ET Suspicious Download 命中 -> 规则改为只匹配
    裸 IP 目标的 exe/zip 下载。
- 修复后 90 秒窗口：EVE 8,886 行，alert 0。
- 负载偏高（load 10.5 / 4 vCPU），需继续观察 EVE 轮转与 ClickHouse/Redis。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 Suricata EVE 入库与小时轮转

- 原因：local-mirror 不运行 Suricata EVE 适配器，告警只存在 eve.json，
  UI 看不到；此前 9 条告警是入库前被规则修复清掉的。
- `server:v68` 新增 EVE 入库：
  - tail eve.json，alert 写入 `threat_events`；
  - 稳定 event_uid，支持轮转/truncate；
  - source_engine=suricata，severity 映射 1/2/3。
- `.125` 新增小时轮转：
  - `lyflow-eve-rotate.timer`，logrotate 保留 48 份，gzip；
  - `lyflow-eve-search` 可同时搜索 live 和 gz 历史。
- 验证：合成告警入库成功；轮转后继续入库；旧 EVE 压缩释放约 2GB。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 全面检修与生产测试就绪

- 修复 traffic_sessions 无保留：新增 `TRAFFIC_SESSION_RETENTION_DAYS`，
  `.125` 设为 3 天，已验证旧行删除。
- 修复 EVE 入库重启漏告警：新增 ingest state（path/inode/offset），
  重启前后告警各入库一次，无重复。
- `.125` 补齐 `LYFLOW_RASP_ALLOW_BLOCK=true` 与 30 天日志保留，
  defense `allow_production_block=true`。
- 验证：9/9 服务、58/58 规则、traffic/threats API 可查、
  Redis 2h 保留/lag 0、EVE 48 份小时轮转。
- 仍有限制：local-mirror 未注册 sensor，capture/engine-health 为空；
  `.8` 仍注册在 `.241`；EVE copytruncate 可能丢少量原始行。
- 结论：数据链路闭环，可进入生产测试。
- 文档：`docs/dev/DETECTION-ACCEPTANCE-2026-10-30.md`
## 2026-10-30 ?????????? CI ??

- README ??????????
  - 9 ?????AF_PACKET ??????????????EVE ??/????????
  - ??? PF_RING?????????????
- ?????????
  - overview / incidents / events / threats / assets / health / rules / settings / mobile?
  - ?? dashboard?runtime?response?global-situation?traffic-observe ????
- ?? `docs/zh/???????????.md`?`docs/README.md`?`docs/GITHUB-CI.md`?
- CI ???
  - ?? security-engine ???
  - server/cmd ????????????EVE ????????
  - ?? Python RASP ??????????
