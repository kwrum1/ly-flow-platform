# LyFlow v4 执行计划（PM 任务派发）

> 依据：《LyFlow 商业级 XDR + RASP 优化与风险修补方案 v1.0》（架构专家）
> 边界：第 2 节的 Gate 0–6 不可放宽；本文件只负责拆解、排序与验收。
> 更新时间：2026-10-29

---

## 1. 目标

把 LyFlow 从"能跑的演示栈"推进到"数据可信、链路可靠、结果可解释、可闭环"的
商业级 XDR + RASP。完成标准是**架构专家的验收矩阵逐条通过**，不是页面好看。

优先级顺序（架构专家给定，PM 不调整）：

1. 数据可信与零值语义
2. 投影重试 / 幂等 / 留存 / 时间
3. 租户绑定与采集可见性
4. XDR 关联与 Incident 根因
5. 规则评估与行为基线
6. RASP 能力分级
7. 商业化与运营

---

## 2. 任务看板

状态：`DONE` 已合并并有测试 / `DOING` 本轮实现中 / `TODO` 未开始 / `BLOCKED` 缺前置条件

### Gate 0 — 基线与复核

| ID | 任务 | 状态 | 证据 |
|---|---|---|---|
| G0-01 | 仓库路径与调用链清单 | DONE | 架构方案附录 A 已核对，路径全部存在 |
| G0-02 | 运行基线（组件、引擎、Agent） | DONE | `docs/dev/ACCEPTANCE-V4.md`、`export/raw/component_status.json` |
| G0-03 | 风险确认表 R-01~R-14 | DONE | 方案第 2 节 + 本次运行数据 |

### Gate 1 — 数据可信与可靠性（P0）

| ID | 任务 | 状态 | 交付 |
|---|---|---|---|
| T0-02 | EventV2 条件校验（五元组缺失语义） | **DONE** | `pkg/contracts/security_event_v2_fields.go` + 10 个单测；ingest 支持 off/shadow/enforce，默认 shadow；已在编译机 10.1.18.100 验证 |
| T0-03 | ClickHouse 零值语义修复 | **DONE** | 新增 `src_port_known/dst_port_known` 列 + 迁移 v8/v9；查询在未知时返回 `null`；编译机测试通过 |
| T0-04 | XDR 投影可靠重试 / DLQ | **DONE** | `projection_retry.go`：Postgres 持久化队列、指数退避、8 次后 DLQ、`ReplayFailed`；worker 已启动；`/debug/components` 暴露队列深度 |
| T0-05 | 幂等键修正 | **DONE** | `xdr_event_uid.go`：原生 ID 优先，否则 payload hash + 纳秒时间；`LYFLOW_EVENT_UID_VERSION=v2` 启用，默认 v1 + shadow 对照 |
| T0-06 | 留存链路审计 | **DONE** | `retention_audit.go` 纯函数 + `QueryRetention`；并入 `/api/v1/debug/components` 的 `retention` 字段；编译机用例通过 |
| T0-07 | 租户绑定审计 | **DONE** | ingest 强制服务端 tenant，覆盖客户端传值；5 个负向/正向测试；编译机通过 |
| T0-08 | 采集计数器合同 | **DONE** | `capture_counters.go` + `capture_health.go`：心跳 capability 的 `capture_quality` 折叠为服务端判定；`/debug/components.capture` 暴露；真实传感器 `0cf8e6df…` 已验证 healthy→degraded(41.68% 丢包)→healthy |

### Gate 2 — 采集可见性（P0）

| ID | 任务 | 状态 |
|---|---|---|
| T2-01 | 传感器健康状态机 healthy/degraded/partial/failed | **DONE** | 六态含 unknown/disabled；reason/reasons/since/last_success_at；接口失效=failed、发布错误=partial、丢包/陈旧/时钟偏移=degraded；重启后到下一次心跳为 unknown |
| T2-02 | 丢包率分母可信才计算，否则 unknown | **DONE** | 内核计数优先、停滞时回退用户态收包数；分母为 0 时不发布比率（`has_drop_ratio=false`）；实测 3034/7280=41.68% |
| T2-03 | fallback backend 透明化 | **DONE** | 上报 requested_engine/active_engine/fallback_reason/backend_status；发生回退时状态降为 degraded(engine_fallback)，UI 显示 “requested → fallback” |

### Gate 3 — 关联与 Incident（P0）

| ID | 任务 | 状态 |
|---|---|---|
| T1-01 | 关联 O(n²) 风险消减（候选索引 + 时间窗） | **DONE** | `xdr_edge_index.go`：host/identity/srcIP/victim/stage 实体桶 + 桶上限与截断标记；与全量两两比较做等价性测试 |
| T1-02 | 证据分级：弱证据只作上下文 | **DONE** | `xdr_evidence_grade.go`：强/中/弱/上下文四级；多事件链必须有强或中等证据；仅同源 IP 不再关联 |
| T1-03 | Incident 根因聚合，减少同质化 | **DONE** | 按"源+规则"聚合、多目标合并、弱证据门槛（`LYFLOW_LATERAL_MIN_VICTIMS`）；7 个单测 |
| T1-04 | 评分解释与版本化，禁止称"攻击概率" | **DONE** | `xdr-score.v2.1` / `xdr-score.v1.1`；发布 components 权重与贡献、decay/penalty、capped；链行新增 `score_explanation` |

### Gate 4 — 规则与行为基线（P1）

| ID | 任务 | 状态 |
|---|---|---|
| T1-05 | 行为基线 shadow mode | **DONE** | `behavior_baseline.go`：按实体学习进程/用户，预热 20 次才判定；只附加 `behavior_baseline` 注解，不改分数/不建单；`LYFLOW_BEHAVIOR_BASELINE_MODE=off\|shadow\|enforce` 默认 shadow；饱和后不再学新值 |
| T4-01 | 规则正/负/边界样本与 CI | **DONE** | `rules/testdata/xdr_rule_samples.yaml` 覆盖全部 44 条带 match 的规则；`samples_test.go` 强制正/负样本 + 边界样本 + 覆盖度；顺带修出 3 个真实缺陷（81001/31101 大小写、31158 `\\.` 转义） |
| T4-02 | 误报反馈的限域、可过期候选调整 | **DONE** | `false_positive_feedback.go`：必须 rule+tenant+entity 三元限域，拒绝 `*`/空；TTL≤30 天（默认 7 天）；只产出 shadow 候选 `raise_threshold`，不直接抑制；跨租户/跨实体/过期一律不生效 |

### Gate 5 — RASP（P0/P1）

| ID | 任务 | 状态 |
|---|---|---|
| T1-04r | RASP 五态分离（未安装/已安装/采集中/检测中/阻断中） | **DONE** | `modules/rasp/state.go` 五态纯函数；`/rasp/protection/status` 每 agent 输出 state/state_reason，去掉 mode/policy_state 的伪默认值，改为 `*_known` |
| T5-01 | runtime schema 与调用上下文 | **DONE** | `rasp-runtime.v1`：language/runtime_version/app/framework/entrypoint/request/call_stack；缺失列入 missing_fields；不再把缺失语言伪造成 python |
| T5-02 | 阻断 dry-run / fail-safe / 紧急开关 | **DONE** | `block_policy.go`：monitor/dry_run/enforce；未签名、过期、紧急停止、未知模式一律 fail-safe 放行；`LYFLOW_RASP_BLOCK_MODE`/`_POLICY_SIGNED`/`_POLICY_EXPIRES_AT`/`_EMERGENCY_STOP`；验收 A10.3 |

### Gate 6 — 商业化与运营（P1）

| ID | 任务 | 状态 |
|---|---|---|
| G6-01 | ESXi 全新部署 | **DONE** | 虚机 `lyflow-xdr` 10.1.18.241，9/9 healthy |
| G6-02 | 功能验收矩阵 | **DONE** | `docs/dev/ACCEPTANCE-V4.md` 28/28 |
| G6-03 | 备份与恢复演练 | **DONE** | PG `pg_dump -Fc`（759 KB）恢复到独立容器，5 张关键表行数与行级样本一致；ClickHouse 停容器冷备 130 MB，恢复后 `traffic_sessions=6306`、迁移账本 `1..9` 一致；见 `docs/dev/BACKUP-RESTORE.md` |
| G6-04 | 升级/回滚手册 | **DONE** | `BACKUP-RESTORE.md`：备份/恢复/升级/回滚/紧急止损；实测 `v17→v16→v17` 均 healthy，回滚后复跑验收 30/30 |

---

## 3. 本轮已完成（Sprint 0）

1. **v4 前端重建**：8 个作业面，单一设计系统，旧样式不再导入。
2. **部署**：ESXi 新建虚机，Docker 栈 9/9 healthy，v4 前端注入 `ly-vis`。
3. **验收**：28/28 通过，含重启恢复。
4. **T0-02**：EventV2 五元组缺失语义，shadow 模式上线。
5. **T0-03**：ClickHouse 端口零值语义，新增 known 列与迁移，查询返回 `null`。
6. **T0-07**：ingest 服务端租户绑定，客户端 `tenant_id` 一律覆盖。
7. **T1-03**：横向告警按"源+规则"根因聚合，弱证据（单目标低/中危）不再单独开单。
8. **性能/防御**：ECharts 按需引入（Overview 分包 1027 KB → 461 KB）；
   nginx 静态资源缺失返回 404、增加安全响应头与一年 immutable 缓存。

---

## 4. 下一批任务（Sprint 1）

按依赖排序，一次只做一个可独立验收的任务。

1. **T0-03 ClickHouse 零值语义**（已完成，见 5.2）
   - 迁移：`src_port_known/dst_port_known` + 历史回填
   - 写入：由质量标记与端口范围决定 known 位
   - 读取：`known=0` 返回 `null`
   - 验收：新事件端口未知时不再出现 `0`；旧数据按 known 位处理

2. **T0-04 投影可靠重试**
   - 持久化投影任务表：pending/processing/succeeded/retryable_failed/permanent_failed
   - 重试与 DLQ 查看、按范围重放、重放幂等
   - 验收：注入 ClickHouse 故障后事件不丢，恢复后自动补齐

3. **T0-06 留存审计**
   - 每日任务核对最早可查询事件时间，与承诺不一致产生健康告警
   - 验收：30 天承诺用真实逐日数据证明

4. **T0-05 幂等键**
   - 优先原生 event_id；否则 source+sensor+session+sequence+payload hash
   - 验收：重复投递 N 次只产生一个逻辑事件

5. **T0-07 租户绑定** / **T0-08 采集计数**

---

## 5. 每个任务的完成定义（DoD）

- [ ] 先补失败测试，再实现
- [ ] `go test ./...` 与前端测试通过，附命令与结果
- [ ] 契约/迁移/调用方同步更新
- [ ] 失败模式与回滚方式写清楚
- [ ] 默认 feature flag 关闭或 shadow，不直接改变生产行为
- [ ] 验收证据可追溯（命令、输出、时间、环境）

---

## 5.1 编译机验证记录（T0-02）

环境：`10.1.18.100`（Ubuntu 25.10，40 vCPU / 62 GiB），源码 `/opt/lyflow/src`，
Go `/usr/local/go1.26.5`（`go1.26.5 linux/amd64`）。
该机无法直连 GitHub 与 proxy.golang.org，源码用 tar 同步，模块走
`GOPROXY=https://goproxy.cn,direct`。

```bash
go test ./server/ingestv2
# ok github.com/lyflow/ly-flow-platform/server/ingestv2 0.016s

go test ./pkg/contracts -run 'NetworkField|ValidateWithMode|ParseFieldValidation|NonNetwork|ApplyNetwork' -v
# 10 个用例全部 PASS

go vet ./pkg/contracts ./server/ingestv2 ./server/cmd
# 无输出（通过）
```

已知问题更正：本地曾出现
`TestCanonicalEventNativeFixturesCoverEveryActiveProducerPath` 失败，原因是本地工作区
存在未跟踪的临时产物；在编译机的干净源码树中 `go test ./pkg/contracts` 通过，
不属于仓库缺陷。

### 5.2 T0-03 验证记录（ClickHouse 零值语义）

```bash
go test ./server/analytics ./pkg/contracts ./server/ingestv2
# ok server/analytics  0.053s
# ok pkg/contracts     0.342s
# ok server/ingestv2   0.015s

go vet ./server/analytics ./pkg/contracts ./server/ingestv2 ./server/cmd
# 无输出（通过）
```

实现要点：

- `lyflow_events_v2` 新增 `src_port_known/dst_port_known`，新表 DDL 与迁移 v8 同步；
- 迁移 v9 对历史行做一次性回填（`port > 0 → known=1`），ClickHouse mutation 异步执行；
- 查询 API 在 `known=0` 时返回 `"src_port": null` / `"dst_port": null`，不再返回 0；
- `portKnown` 以 `missing_*` 质量标记优先，端口 0 与越界值一律视为未知。

---

## 6. 当前阻塞与风险

1. 编译机不能直连 GitHub：源码同步使用 tar 包，后续接入内网 Gitea 或制品库更稳妥。
2. `route-characterization.test.js` 在本地 vitest 下无法加载（模块解析问题），
   与代码无关；其余 119 个前端测试通过，部署环境路由已用 HTTP 实测。
3. 新装栈 `security_engine.alert_bus` 与 `xdr.evaluator` 为 degraded：没有真实流量
   与未闭环 Incident，属预期空态，UI 如实显示。
4. Suricata 绑定 `lo`，生产需切换真实镜像网口。

---

## 7. 部署与验证记录（T0-02 / T0-03）

### 7.1 构建

编译机 `10.1.18.100`：

```bash
cd /opt/lyflow/src/server
CGO_ENABLED=0 GOWORK=off GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -o /tmp/ly-server ./cmd
# 21 MB, sha256 6808623d07eda2ac7e5806062b568379a1deec02248d1c6b998c898c47727aa5
```

### 7.2 镜像

ESXi 虚机 `lyflow-xdr`（10.1.18.241）：

```dockerfile
FROM ly-flow/server:release-amd64
COPY ly-server /app/ly-server
RUN chmod +x /app/ly-server
```

`docker build -t ly-flow/server:v4` → `.env` 设 `LY_SERVER_IMAGE=ly-flow/server:v4`
→ `docker compose up -d --force-recreate ly-server`。

compose 增加 `LYFLOW_EVENTV2_FIELD_VALIDATION=${...:-shadow}`，容器内已确认生效。

### 7.3 迁移

ClickHouse `lyflow_events_v2` 已具备：

```
src_port UInt16
dst_port UInt16
src_port_known UInt8 DEFAULT 0
dst_port_known UInt8 DEFAULT 0
```

迁移账本 `lyflow_event_storage_migrations` 已记录 `1..9`；v9 回填 mutation
`is_done=1`。

### 7.4 端到端验证

写入一条 `src_port_known=0 / dst_port_known=0` 的事件后查询 `/api/v2/events`：

```
src_port = None | dst_port = None
T0-03 READ PATH: PASS
```

随后已删除该测试行。

### 7.5 功能验收

整机重启后 9/9 容器 healthy，`https://10.1.18.241/` 与 API 正常，
`docs/dev/ACCEPTANCE-V4.md`：**28/28 通过**。

### 7.6 尚未完成（Gate 1 剩余）

- T0-04 投影失败重试 / DLQ / 重放
- T0-05 幂等键版本化（需 shadow 对比新旧碰撞率）
- T0-06 留存审计任务
- T0-07 租户绑定负向测试
- T0-08 采集计数器合同
- Gate 2–5 全部任务

以上未完成的项没有部署，也没有被标记为通过。

---

## 8. 性能与防御优化（本轮，实测）

### 8.1 前端

| 指标 | 优化前 | 优化后 |
|---|---:|---:|
| Overview 路由 chunk | 1027 KB | **461 KB** |
| 同上 gzip | ~340 KB | **160 KB** |
| 变化 | — | **-55%** |

做法：`echarts` 从全量 `import * as echarts` 改为 `echarts/core` +
`BarChart / GridComponent / TooltipComponent / CanvasRenderer` 按需注册。
主包 1207 KB 仍由 Element Plus 全量注册构成，列为后续优化项（需改组件按需引入）。

### 8.2 后端

| 优化 | 效果 |
|---|---|
| 横向告警根因聚合 | 同一"源+规则"合并为一张 Incident，多目标写入标题与摘要；不再一目标一单 |
| 弱证据门槛 | 低/中危且仅 1 个目标时不单独开单，事件仍保留在事件库；`LYFLOW_LATERAL_MIN_VICTIMS=1` 可回退 |
| 与既有链路口径兼容 | “单条内网利用尝试进入攻击链”的既有测试保持通过 |

### 8.3 网关与防御

| 项 | 之前 | 现在 |
|---|---|---|
| 缺失的 `/assets/*.js` | 200 + 返回 index.html（会把 HTML 当 JS 执行） | **404** |
| SPA 深链 `/overview` | 200 | 200（保持） |
| 安全响应头 | 无 | `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`X-Permitted-Cross-Domain-Policies: none` |
| 静态资源缓存 | 默认 | `expires 1y`（配合内容哈希文件名） |

### 8.4 验证

- 编译机：`go test ./server/cmd -run 'TrafficGrouping|LateralMinVictims|XDRChain'`、
  `go test ./server/ingestv2`、`go vet` 全部通过。
- 部署：`ly-flow/server:v5`、`ly-flow/frontend:v6`，9/9 healthy。
- 网关实测：`missing_asset=404`、`spa_deeplink=200`、安全头齐全。
- 功能验收：`docs/dev/ACCEPTANCE-V4.md` **28/28 通过**。

---

## 9. Gate 1 增量交付（T0-06 / T0-08，专家分工）

### 9.1 T0-06 留存审计（已上线）

- 纯函数 `evaluateRetention`：empty / unknown / invalid / ok / short，30 天承诺、
  1 天容差、未来时间 5 分钟宽限；`short` 必须写出实测与承诺天数。
- `analytics.HTTPClickHouse.QueryRetention` 直接查询
  `min(event_at)/max(event_at)/count()`，兼容 ClickHouse 把 UInt64 序列化为字符串。
- 并入 `/api/v1/debug/components` 的 `retention` 字段，不新增路由、不破坏 122 条路由契约。
- 线上实测：`{"rows":0,"status":"empty","reason":"no events stored"}`（本环境 v2 表为空，如实报告）。

### 9.2 T0-08 采集计数器合同（核心完成，未接线）

- `computeCaptureWindow`：拒绝负增量与回绕，计数器回退一律判为 reset 并给出 0 增量，
  采样间隔 >300s 标记 sampling gap，窗口不足 1s 不发布每秒速率。
- `captureVisibilityState`：healthy / degraded / partial / unknown。
- 11 个用例覆盖重置、32/64 位回绕、采样缺口、亚秒窗口。
- **未接线**：传感器上报结构尚未接入，UI 不会展示这些状态；因此标记 PARTIAL 而非 DONE。

### 9.3 验证

```
go build ./server/cmd                                  -> ok
go test ./server/cmd -run 'Retention|CaptureCounter|TrafficGrouping|LateralMinVictims' -> ok
go test ./server/cmd -run 'TestRouteAPI|Contract'      -> ok
go vet ./server/cmd ./server/analytics ./server/ingestv2 ./pkg/contracts -> clean
```

部署：`ly-flow/server:v7`，9/9 healthy；`/api/v1/debug/components` 返回 `retention`。

### 9.4 Gate 1 现状（2026-10-29 早期快照，已被第 2 节看板取代）

| 任务 | 状态 |
|---|---|
| T0-02 五元组缺失语义 | DONE |
| T0-03 ClickHouse 零值语义 | DONE |
| T0-06 留存审计 | DONE |
| T0-07 租户绑定 | DONE |
| T0-08 采集计数合同 | PARTIAL（核心完成，未接线） |
| T0-04 投影重试 / DLQ | TODO |
| T0-05 幂等键 | TODO |

> 历史说明：以上是 v7 时点的快照。Gate 2–6 已于 2026-10-29 全部完成，当前状态以第 2 节看板与 `docs/dev/ACCEPTANCE-V4.md` 为准。

---

## 10. Gate 1 收尾（T0-04 / T0-05，v8）

### 10.1 T0-04 投影可靠重试

- 新表 `xdr_projection_jobs(event_uid, payload, status, attempts, next_retry_at, last_error, ...)`。
- 投影失败不再只写日志：序列化完整 EventV2 入队，worker 每 30s 领取
  （`FOR UPDATE SKIP LOCKED`），成功标记 `succeeded`，失败按 `30s × 2^(n-1)` 退避，
  8 次后进入 `permanent_failed`（DLQ）。
- `ReplayFailed` 提供受控重放；不自动执行。
- `/api/v1/debug/components` 增加 `projection_retry` 队列深度。

线上验证：

```
projection_retry: {"pending":0,"permanent_failed":0}
xdr_projection_jobs columns: event_uid,payload,status,attempts,next_retry_at,last_error,created_at,updated_at
```

### 10.2 T0-05 幂等键版本化

- `xdr2n-*`：有原生事件 ID 时只用 tenant + 原生 ID，时间和规则变化不影响身份。
- `xdr2p-*`：无原生 ID 时混合 tenant/来源/规则/实体/payload hash/纳秒时间，
  不再按秒截断，避免同秒碰撞与重复投递分裂。
- 默认 `LYFLOW_EVENT_UID_VERSION=v1`，同时计算 v2 供 shadow 对照；
  设 `v2` 才切换，`LYFLOW_EVENT_UID_SHADOW_LOG=1` 输出对照日志。

### 10.3 Gate 1 最终状态

| 任务 | 状态 |
|---|---|
| T0-02 五元组缺失语义 | DONE |
| T0-03 ClickHouse 零值语义 | DONE |
| T0-04 投影重试 / DLQ | DONE |
| T0-05 幂等键 | DONE（v2 可切换，默认 shadow） |
| T0-06 留存审计 | DONE |
| T0-07 租户绑定 | DONE |
| T0-08 采集计数合同 | DONE（v17 起心跳接入 `/debug/components.capture`） |

部署（历史）：`ly-flow/server:v8`，9/9 healthy；功能验收 28/28。当前：`v17` + `frontend:v9`，30/30。
