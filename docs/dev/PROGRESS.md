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



