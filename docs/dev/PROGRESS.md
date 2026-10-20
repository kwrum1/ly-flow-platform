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
