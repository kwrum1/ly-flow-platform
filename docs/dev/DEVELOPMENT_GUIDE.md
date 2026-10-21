# LyFlow 最新版开发指导文档（DeepSeek 专用）

> 文档版本：v1.0  
> 适用仓库：`kwrum1/ly-flow-platform`  
> 目标读者：DeepSeek 编码 Agent、以及配合它做评审的人类工程师  
> 文档性质：开发计划 + 详细设计 + 任务卡 + 执行规范  
> 基线日期：2026-10-19

---

## 0. 给 DeepSeek 的硬性规则

你在这个仓库里工作时，必须遵守以下规则。它们优先于任何“看起来更优雅”的重构冲动。

1. **一次只做一个 Task ID。** 不要在一个任务里顺手重构无关模块。
2. **先读后写。** 开始前至少阅读：
   - `AGENTS.md`（若不存在，由 T0.1 创建）
   - 本文件对应章节
   - 任务涉及的包、相邻测试、`contracts/` 下的契约
3. **先写失败测试，再实现。** 至少覆盖正常路径 + 一个失败路径。
4. **不修改第三方/GPL 源码。** 禁止改 `third_party/`、Suricata、Wazuh、Elkeid、OpenRASP、`ly_probe` 的 vendored 源码；只允许通过补丁文件、配置、包装器、适配器集成。
5. **不把 GPL 组件链接进自有二进制。** 一律独立进程/容器，通过 NetFlow、EVE、JSON、gRPC、HTTP 交互。
6. **不把 Elkeid HUB / Elkeid Console / Elkeid HIDS-RASP 规则配置放进公开构建产物。** 它们只能放在 `private/elkeid/`，通过 `full-private` profile 启用。
7. **不做破坏性变更。** 数据库只加不删；API 只增不删；旧接口保留到新接口通过契约测试并可切换。
8. **所有大改必须有 feature flag。** 默认关闭，验收后再打开。
9. **不提交密钥、证书、真实客户数据、真实 PCAP。** 测试用合成数据。
10. **每个任务结束必须运行指定测试命令**，并在 `docs/dev/PROGRESS.md` 记录：Task ID、变更文件、测试结果、风险、回滚方式。
11. **遇到架构分歧，停下来提问。** 允许提问的 Gate 见第 13 章；不要自行扩大范围。
12. **保持中文文案一致。** 用户界面文案走统一术语表，避免“登陆/登录”“帐号/账号”等混用。

### 0.0 两条硬边界（最高优先级）

**H1 编译机：`$BUILD_HOST`**

- 所有源码、编译、镜像构建、产物打包只在编译机进行。
- 目录约定：
  - `/opt/lyflow/src`：源码
  - `/opt/lyflow/artifacts`：构建产物（二进制、镜像 tar、SBOM）
  - `/opt/lyflow/logs`：构建日志
- 禁止在测试机或本地直接改代码后部署。
- 编译机上的代码修改必须提交到仓库，再由测试机拉取/接收产物。

**H2 测试机：`$TEST_HOST`（ESXi 虚拟机）**

- 所有集成测试、E2E、压测、安装/升级/回滚测试只在测试机进行。
- 目录约定：
  - `/opt/lyflow/deploy`：Compose、配置、镜像
  - `/opt/lyflow/data`：数据卷/测试数据
  - `/opt/lyflow/reports`：测试报告、日志、截图
- 测试机可随时重装/回滚快照；测试机上的修改不作为源码。
- 破坏性操作（删数据卷、重装、改网络）前必须先打快照并记录回滚步骤。

**访问信息（内网联调专用）**

| 用途 | 地址 | 用户 | 初始密码 | 说明 |
|---|---|---|---|---|
| 编译机 | `$BUILD_HOST` | `root` | `<REDACTED>` | 源码、构建、镜像 |
| 测试机 | `$TEST_HOST` | `root` | `<REDACTED>` | ESXi VM，部署与验收 |

- 首次接入后优先配置 SSH key；密码只用于首次登录，建议尽快轮换。
- 凭据只允许保存在本文件/本地受控环境，**禁止提交到公开仓库、日志、镜像、构建产物**。
- Agent 连接方式：
  ```bash
  ssh root@$BUILD_HOST
  ssh root@$TEST_HOST
  ```
- 若需要非交互式执行，先在本地生成 key 并写入两台机器的 `~/.ssh/authorized_keys`；不要把密码写进脚本。
- 任何“本地能跑、编译机/测试机不能跑”的问题，以编译机/测试机为准。

**环境验证（由 T0.0 执行）**

```bash
ssh root@$BUILD_HOST 'uname -a; docker version; go version; node -v; df -h; free -h'
ssh root@$TEST_HOST 'uname -a; docker version; docker compose version; df -h; free -h'
```

结果写入 `docs/dev/ENVIRONMENT.md`。

### 0.1 完成任务的标准（Definition of Done）

一个任务只有同时满足以下条件才算完成：

- [ ] 代码实现符合任务卡范围
- [ ] 新增/修改的测试通过
- [ ] `go test` / `npm test` / `npm run typecheck` / `npm run lint` 相关项通过
- [ ] **构建在 `$BUILD_HOST` 完成，关键集成/E2E 在 `$TEST_HOST` 通过**
- [ ] API/契约变更已更新 `contracts/` 或 `pkg/contracts/`
- [ ] 数据库变更附带可回滚 migration
- [ ] 有日志、错误处理、超时、取消
- [ ] 有 feature flag（如涉及行为变更）
- [ ] 更新 `docs/dev/PROGRESS.md`、`docs/dev/WORKQUEUE.md`
- [ ] 没有新增 secret、GPL 污染、未授权依赖
- [ ] 输出变更摘要、测试结果、风险、回滚方式

### 0.2 连续执行策略（竣工前不停止）

- 工作队列：`docs/dev/WORKQUEUE.md`，按 M0 → M4、Task ID 顺序执行。
- 每完成一个 Task：
  1. 提交代码（或生成可评审的 patch）；
  2. 在编译机 `$BUILD_HOST` 构建；
  3. 把产物同步到测试机 `$TEST_HOST` 并跑对应测试；
  4. 更新 `PROGRESS.md` / `WORKQUEUE.md`；
  5. 立即选择下一个未阻塞 Task，不等待人类“继续”指令。
- 遇到不确定的选择：
  1. 先查本文件、ADR、现有代码和测试；
  2. 仍不确定时，选择本文件标注的“推荐/默认”方案；
  3. 记录到 `docs/dev/DECISIONS.md`（背景、选项、选择、理由）；
  4. 继续执行，不因小决策停下。
- 只有在以下情况允许停止：
  - 到达里程碑 Gate，需要人类评审（评审未到时，继续做不依赖该 Gate 的 Task，不要空等）；
  - 硬阻塞：机器不可达、凭据失效、磁盘满、网络隔离、依赖下载失败且无法绕过；
  - 需要破坏性操作（删除数据卷、重装测试机、改网络）且无快照；
  - 发现需求与架构冲突，必须人类决策。
- 测试失败不等于停止：定位 → 修复 → 重跑；同一问题连续 3 次无进展，记录阻塞并转向下一个独立 Task，禁止原地空转。
- 每个里程碑结束，必须在 `$TEST_HOST` 跑完整验收；未通过不得进入下一阶段。

### 0.3 默认决策规则（不确定时使用）

按以下优先级自动选择，并记录到 `DECISIONS.md`：

1. **成本相同选维护成本低的**。
2. **都能实现选成熟度高、许可清晰的**。
3. **UI 不确定选浅色、信息密度高、不引入新框架**。
4. **性能不确定选可观测、可回滚的保守值**。
5. **规则不确定选 ET Open / OpenRASP / CRS / Nuclei / CISA KEV 等许可清晰的上游**。
6. **部署不确定选 `lean` profile**；`full-private` 只在明确需要 Elkeid HUB 时启用。
7. **任何涉及自动阻断的决策，默认人工审批**。
8. **任何涉及删除数据/重装的决策，默认先快照 + 人工确认**。

---

## 1. 产品目标与基线

### 1.1 产品定义

LyFlow 是一个**单机、容器化、主动防御型 NDR/XDR 态势感知平台**：

- 网络：`ly_probe` 主抓包/流/L7 指纹 + Suricata 签名协处理
- 主机：`ly-agent` 统一 Agent（Elkeid/Wazuh/OpenRASP/Elkeid RASP 组合）
- 应用：Java/PHP 用 OpenRASP，Python/Go/Node 用 Elkeid RASP
- 分析：统一事件 + 多源证据 + ATT&CK 阶段 + Incident
- 响应：人工审批 + 指定时间窗自动 + 回滚 + 审计
- 运营：规则/情报自动同步，不要求人工逐条写规则

### 1.2 基线参数（本版本必须满足）

| 项 | 基线 |
|---|---|
| 最大资产 | 300 台 |
| 峰值流量 | 1 Gbps |
| 日均事件 | 20k EPS |
| 部署 | 单机、Docker Compose |
| 热数据 | 30 天（ClickHouse） |
| 冷数据 | 180 天（对象存储/外部盘） |
| OS | 现代 Linux（容器化），不要求 CentOS 7 / 3.10 |
| 高可用 | 本版本不做 |
| 多租户 | 本版本不做 |

### 1.3 明确不做

- 不做多节点 HA、异地容灾、多租户
- 不支持 CentOS 7 / Linux 3.10
- 不默认部署 Kafka、OpenSearch/Elastic、Arkime/Malcolm
- 不重写 `ly_probe` 抓包/流/指纹核心
- 不重写 Suricata、Wazuh、Elkeid、OpenRASP
- 不做无审批自动封禁/隔离
- 不保存全流量 PCAP，只保留告警前后 N 秒 + 会话元数据
- 不做逐条 RASP 规则运营；只做上游自动同步与格式适配

### 1.4 成功指标

| 指标 | 目标 |
|---|---|
| 抓包丢包率 | < 1%（1 Gbps） |
| 事件写入 | 20k EPS 稳定 |
| 查询 p95 | < 2s（7 天范围） |
| Agent 安装成功率 | > 99% |
| 数据保留 | 30 天热 + 180 天冷 |
| ATT&CK 验证 | 至少 3 条链路通过 Atomic Red Team |
| 响应安全 | 100% 审批/时间窗/回滚/审计 |

---

## 2. 最终架构与选型

### 2.1 组件选型

| 层 | 组件 | License | 角色 | 默认 |
|---|---|---|---|---|
| 流量主探针 | `ly_probe` | GPLv3 | 抓包、NetFlow、L7、指纹、PCAP | 是 |
| 流量协处理 | Suricata 7 | GPLv2 | 签名 IDS、Web/Exploit 规则 | 是 |
| 采集/缓冲 | Vector | MPL-2.0 | EVE/NetFlow/JSON 采集与路由 | 是 |
| Linux Agent | Elkeid Agent + Driver | Apache-2.0 / GPLv2 | eBPF/LKM、日志、YARA、RASP 底座 | 是 |
| 日志/响应 | Wazuh Manager | GPLv2 | 解码、规则、Agent 管理、主动响应 | 是 |
| RASP Java/PHP | OpenRASP | Apache-2.0 | 运行时防护 | 是 |
| RASP Python/Go/Node | Elkeid RASP | Apache-2.0 | 运行时防护 | 是 |
| 私有规则引擎 | Elkeid HUB | Elkeid License | HIDS/RASP 规则处理、学习 | 否（full-private） |
| 核心服务 | `ly-server` / 新 core 包 | Apache-2.0 | 规范化、关联、Incident、API、响应 | 自研 |
| 事件存储 | ClickHouse | Apache-2.0 | 事件、会话、聚合 | 是 |
| 配置存储 | PostgreSQL | PostgreSQL | 账号、资产、Agent、规则、Incident | 是 |
| 证据存储 | SeaweedFS/本地盘 | Apache-2.0 | PCAP、证据包 | 是 |
| 前端 | Vue 3 + ECharts | Apache-2.0/MIT | 控制台 | 自研 |
| 总线 | Vector 磁盘缓冲 | MPL-2.0 | 默认解耦 | 是 |
| 总线（可选） | Kafka | Apache-2.0 | Elkeid 模块 | 否 |

### 2.2 部署 profile

- `lean`（默认）：ly_probe + Suricata + Vector + Wazuh + OpenRASP + Elkeid RASP + core + ClickHouse + PostgreSQL + SeaweedFS + Web。
- `full-private`（私有/学习）：在 `lean` 基础上增加 Elkeid AgentCenter、ServiceDiscovery、Manager、MongoDB、Redis、Kafka、HUB。**不得进入公开构建产物。**

### 2.3 数据流

```text
ly_probe (NetFlow/PCAP/指纹) ─┐
Suricata (EVE) ────────────────┤
Wazuh (alerts JSON) ───────────┼─> Vector ─> ly-server /ingest/v2 ─> ClickHouse
Elkeid (Kafka/JSON) ───────────┤                                   └─> PostgreSQL (Incident)
RASP (OpenRASP/Elkeid) ────────┘                                   └─> SeaweedFS (证据)
```

### 2.4 核心原则

1. **引擎复用，胶水自研。** 自研范围仅限：规范化、关联/ATT&CK、Incident、Agent 门面、响应审批、UI、内容编排。
2. **证据优先。** 每条告警必须能追溯到网络/主机/应用/日志证据。
3. **不伪造数据。** 没有真实攻击源就不画攻击线；没有证据就不升级阶段。
4. **单机优先。** 不为假想的大规模牺牲当前可运维性。

---

## 3. 仓库结构与模块边界

### 3.1 现有结构（必须尊重）

```text
agent/                当前 Go Agent（不成熟，逐步演进为 ly-agent supervisor）
server/               ly-server（API、XDR、Incident、规则生命周期）
security-engine/      规范化事件上的二次检测引擎
（原 dpi-engine 已移除；统一检测由 security-engine 与 lyprobe 承担）
frontend/             Vue 3 + Vite + Element Plus
rules/                规则与规则生命周期产物
contracts/            机器可读契约
pkg/contracts/        安全事件契约
deploy/               Docker/Suricata 部署
docs/                 架构、白皮书、API
third_party/          禁止修改
```

### 3.2 新增模块（建议）

```text
pkg/contracts/security_event_v2.go       事件 v2
pkg/contracts/evidence.go                证据模型
pkg/contracts/attack_stage.go            ATT&CK 阶段
server/ingestv2/                         接收/规范化
server/query/                            查询 API + 查询治理
server/correlation/                      实体图 + 阶段状态机
server/content/                          多引擎规则/情报编排
server/agentfacade/                      Wazuh/Elkeid 统一门面
server/response/                         审批/时间窗/回滚/审计
agent/supervisor/                        ly-agent supervisor
rules/lyprobe/                           ly_probe 规则与转换产物
rules/openrasp/                          OpenRASP 规则同步
deploy/compose/                          lean / full-private profiles
frontend/src/app/shell/                  新 UI shell（ly_vis 排版）
frontend/src/views/attack/               ATT&CK/Incident 页面
frontend/src/views/evidence/             证据面板
private/elkeid/                          HUB/Console/规则（不进公开包）
```

### 3.3 禁止事项

- 禁止在 `third_party/`、`rules/compiled/`、`rules/quarantine/` 下手写业务代码。
- 禁止删除旧的 `server/cmd` 路由；新路由用 `/api/v2/`，旧路由保留。
- 禁止把 `ly_server` 的 MariaDB 查询层重新引入。
- 禁止在公开包中包含 `private/elkeid/`。
- 禁止把 `frontend` 旧页面直接删除；先做 feature flag 切换，验收后再清理。

---

## 4. 数据模型

### 4.1 Event v2

新增 `pkg/contracts/security_event_v2.go`，保留 v1 兼容。

```go
type EventV2 struct {
    SchemaVersion string    `json:"schema_version"` // lyflow.security_event.v2
    EventUID      string    `json:"event_uid"`
    TenantID      string    `json:"tenant_id"`
    Source        SourceRef `json:"source"`
    EventType     string    `json:"event_type"`
    Timestamps    Timestamps `json:"timestamps"`
    Entities      Entities  `json:"entities"`
    Detection     Detection `json:"detection"`
    Evidence      []EvidenceRef `json:"evidence"`
    Raw           RawRef    `json:"raw"`
    Governance    Governance `json:"governance"`
}
```

`Entities` 至少包含：

```text
asset:   id, ip, mac, hostname, os, criticality, tags
user:    id, name, domain, privilege
process: pid, ppid, exe, cmdline, hash, signer, user, session, container
file:    path, hash, size, signer
net:     src_ip, src_port, dst_ip, dst_port, proto, direction
app:     protocol, method, host, uri, status, ua, request_id
```

`Detection`：

```text
rule_id, rule_version, source, severity, confidence
tactic_id, technique_id, stage, description
mapping_source
```

`EvidenceRef`：

```text
type: pcap|flow|http|process_tree|file|log|rasp|ti
ref, sha256, size, ttl, redaction, created_at
```

### 4.2 ATT&CK 阶段

```text
Recon
InitialAccess
Execution
Persistence
PrivilegeEscalation
DefenseEvasion
CredentialAccess
Discovery
LateralMovement
Collection
CommandAndControl
Exfiltration
Impact
```

规则：阶段由 `server/correlation` 计算，不由单条规则直接写入。

### 4.3 存储映射

**ClickHouse**

- `events_v2`：分区 `toDate(event_at)`，排序键 `(event_date, source, event_type, asset_id)`
- `flows_v2`：会话/流
- `events_1m` / `events_1h`：物化视图
- TTL：30 天热数据

**PostgreSQL**

- `assets`, `agents`, `agent_groups`
- `rules`, `rule_bundles`, `rule_sources`
- `incidents`, `incident_stages`, `incident_evidence`
- `response_actions`, `response_approvals`
- `audit_log`

**SeaweedFS/本地盘**

- `pcap/{date}/{sensor}/{flow_id}.pcap`
- `evidence/{incident_id}/{evidence_id}.bin`

### 4.4 迁移策略

- 新增 v2 表，不删 v1。
- `EVENT_SCHEMA_V2_ENABLED` 控制双写/读。
- 新增 `server/ingestv2/adapter_v1.go`，把 v1 事件转为 v2。
- 迁移完成前，旧 API 仍可读 v1。

---

## 5. API 契约

统一响应：

```json
{ "code": 0, "message": "success", "data": {} }
```

分页：

```json
{ "items": [], "total": 0, "limit": 50, "next_cursor": "" }
```

### 5.1 新增接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v2/ingest/events` | 批量事件 |
| POST | `/api/v2/ingest/evidence` | 证据元数据 |
| GET | `/api/v2/events` | 事件查询（游标分页） |
| GET | `/api/v2/events/{uid}` | 事件详情 + 证据 |
| GET | `/api/v2/incidents` | Incident 列表 |
| GET | `/api/v2/incidents/{id}` | 阶段/证据/时间线 |
| POST | `/api/v2/incidents/{id}/status` | 状态流转 |
| GET | `/api/v2/attack/coverage` | ATT&CK 覆盖率 |
| GET | `/api/v2/agents` | 统一 Agent 列表 |
| POST | `/api/v2/agents/{id}/tasks` | 下发任务 |
| GET | `/api/v2/rules/sources` | 规则源健康 |
| POST | `/api/v2/rules/sync` | 触发同步 |
| POST | `/api/v2/rules/bundles/{id}/activate` | 激活 |
| POST | `/api/v2/rules/bundles/{id}/rollback` | 回滚 |
| POST | `/api/v2/response/actions` | 创建响应（待审批） |
| POST | `/api/v2/response/actions/{id}/approve` | 审批 |
| POST | `/api/v2/response/actions/{id}/rollback` | 回滚 |

### 5.2 契约测试

- 更新 `contracts/product-acceptance/v1/route-api-contract.json`（或新增 v2）。
- 每个新路由必须有：成功、未授权、参数错误、空结果 4 类 fixture。
- `server/cmd/route_api_contract_test.go` 必须覆盖新路由。

---

## 6. 前端信息架构与设计规范

### 6.1 布局

复刻 `ly_vis` 的排版与信息密度，不复制代码、不追配色：

- 顶部一级导航 50px
- 二级页签 45px
- 内容区 20px 内边距
- 浅色默认，深色可切换
- 密集表格、图表卡片、右侧证据抽屉
- 不嵌套卡片、不用渐变/光晕/装饰性动画

### 6.2 页面

| 路由 | 页面 | 核心内容 |
|---|---|---|
| `/dashboard` | 总览 | KPI、阶段漏斗、ATT&CK 热力、资产风险、实时流 |
| `/events` | 事件中心 | 筛选、表格、阶段/技术/证据数 |
| `/events/:uid` | 事件详情 | 阶段条、技术卡、证据抽屉、原始 JSON |
| `/incidents` | Incident 列表 | 状态、阶段、资产、负责人 |
| `/incidents/:id` | 攻击链 | 阶段时间线、实体图、证据矩阵、响应 |
| `/assets` | 资产与 Agent | 资产 360、Agent 健康、策略 |
| `/detections` | 检测面 | 流量/主机/日志/RASP 子页 |
| `/rules` | 规则与情报 | 源健康、版本、灰度、覆盖率 |
| `/response` | 响应 | 审批、时间窗、动作历史 |
| `/admin` | 管理 | 用户、系统、审计 |

### 6.3 组件

- `AttackStageRibbon`：阶段条 + 置信度
- `TechniqueMatrix`：ATT&CK 热力图
- `EvidencePanel`：证据标签页 + 哈希 + 下载
- `EntityGraph`：实体关系图（ECharts/G6）
- `IncidentTimeline`：阶段分组时间线
- `CoverageBar`：规则/来源覆盖率
- `QueryBar`：时间范围守卫 + 保存视图

### 6.4 文案

- 统一术语表：事件、告警、攻击链、Incident、阶段、技术、处置。
- 增加 `scripts/check-copy.mjs`，扫描常见错别字。
- 所有空态/错误态/加载态必须有明确文案。

---

## 7. 规则与情报流水线

### 7.1 允许的上游

| 上游 | 用途 | 目标引擎 | 频率 | 决策 |
|---|---|---|---|---|
| ly_probe 原生指纹 | 资产/协议/威胁 | ly_probe | 随版本 | 核心 |
| ET Open | Web/Exploit/Malware/C2 | Suricata | 每日 | 核心 |
| OISF Traffic ID | 应用识别 | Suricata | 每日 | 可选 |
| Wazuh Ruleset | 日志/认证 | Wazuh | 随版本 | 核心 |
| OpenRASP 官方插件 | Java/PHP RASP | OpenRASP | 自动同步 | 核心 |
| OWASP CRS | HTTP 攻击/虚拟补丁 | Suricata/ly_probe/RASP | 每周 | 核心 |
| Nuclei templates | CVE PoC/虚拟补丁 | 转换 | 每日 | 核心（选择性） |
| CISA KEV | 已利用漏洞优先级 | 规则优先级 | 每日 | 核心 |
| Yara-Rules/rules | 恶意文件 | YARA | 每周 | 核心 |
| signature-base | 恶意文件/IOC | YARA | 每日 | 核心 |
| Abuse.ch | URL/IP/哈希/JA3 | IOC | 每小时 | 核心 |
| OTX | IOC | IOC | 每小时 | 可选 |
| Tor exit list | 出口节点 | IOC | 每日 | 核心 |
| EPSS | 漏洞利用概率 | 优先级 | 每日 | 核心 |
| DB-IP Lite | GeoIP | 地图 | 每月 | 核心 |
| MITRE ATT&CK | 战术/技术 | core | 每季度 | 核心 |
| Atomic Red Team | 检测验证 | 测试 | 每月 | 核心 |

### 7.2 禁止的上游

- PT AttackDetection（自定义许可、停更）
- Spamhaus（商业许可）
- Snort Community（与 ET Open 重叠，转换成本高）
- Elkeid HIDS/RASP 规则配置（Elkeid License，禁止分发）
- 任何需要把规则嵌入闭源二进制的商业源

### 7.3 流水线

```text
fetch -> verify(sha256/signature) -> normalize -> compile
-> lint -> replay corpus -> score -> sign -> canary
-> activate -> observe -> rollback
```

- 使用 `suricata-update`、`fresh`、`yara`、`sigma-cli`，不自研下载器。
- 每条 bundle 有 `manifest.json`：来源、版本、哈希、编译结果、隔离原因。
- 灰度：1% → 10% → 100%，失败自动回滚。
- 质量看板：来源最后更新、新增/删除、编译成功率、命中率、误报率、ATT&CK 覆盖率。

### 7.4 ly_probe 规则转换

- `rules/lyprobe/` 存放生成后的 `threat.json` / `fp-patterns`。
- 可转换：简单 HTTP URI/Header/Body 正则、DNS、TLS、服务指纹。
- 不可转换：需要流重组、flowbits、复杂 PCRE 的规则，留在 Suricata。
- 转换器必须带测试：输入样例 → 输出规则 → 命中/不命中。

---

## 8. Agent 方案

### 8.1 目标

用户看到一个 `ly-agent` 安装包、一个服务、一个管理记录；内部由成熟组件组成。

```text
ly-agent (Go supervisor)
├─ transport: mTLS + 本地加密 spool + 背压
├─ host-core
│   ├─ Linux: Elkeid Agent + Driver
├─ collect: journald/auditd/syslog
├─ scan: YARA / ClamAV（可选）
├─ rasp
│   ├─ Java/PHP: OpenRASP
│   └─ Python/Go/Node: Elkeid RASP
├─ response: 杀进程/隔离文件/主机隔离/封 IP/禁用账号
└─ self-protection: 完整性/配置签名/卸载保护/诊断包
```

### 8.2 平台矩阵

| 平台 | Host 核心 | 日志 | RASP | 响应 |
|---|---|---|---|---|
| Linux | Elkeid Agent + Driver | journald/auditd | OpenRASP（Java/PHP）+ Elkeid（Python/Go/Node） | Elkeid task + 脚本 |

### 8.3 RASP 规则

- 不逐条运营；自动同步 OpenRASP 官方插件、CRS、Nuclei、CISA KEV。
- 一个运行时只用一个引擎，避免双重插桩。
- 默认 monitor，规则验证后 protect；阻断失败 fail-open。
- 覆盖边界写进产品文档，不承诺“全漏洞覆盖”。

### 8.4 安装与自检

- 安装前：权限、端口、磁盘、时间同步、SELinux/防火墙、内核/BTF。
- 安装中：幂等、失败回滚、日志落盘。
- 安装后：心跳、采集、规则加载、上报连通性自检。
- 诊断包：配置、日志、抓包统计、连通性。
- 卸载保护：需要管理员口令/审批。

### 8.5 响应护栏

- L1 观测：自动。
- L2 遏制：人工审批；指定时间窗可自动。
- L3 清除：人工审批 + 回滚预案。
- 每个动作：目标绑定、幂等、TTL、回滚、爆炸半径、审计、总开关。

---

## 9. 查询与性能

### 9.1 ClickHouse

- 分区：`toDate(event_at)`
- 排序键：`(event_date, source, event_type, asset_id)`
- 物化视图：`events_1m`, `events_1h`
- TTL：30 天
- 跳数索引：`rule_id`, `technique_id`, `asset_id`
- 禁止 `SELECT *`；列表只查必要列

### 9.2 查询治理

- 最大时间范围 30 天
- 最大返回 10k 行
- 超时 10s，支持取消
- 游标分页，禁止深分页
- 只读账号、限流、缓存
- 慢查询日志 + p95 指标

### 9.3 前端

- 虚拟滚动
- 请求取消（AbortController）
- 防抖
- 骨架屏
- 不在前端做全量聚合

---

## 10. 安全、许可与响应护栏

### 10.1 许可

- 自有代码：Apache-2.0。
- GPL 组件：独立容器/进程，提供源码与声明，不链接。
- Elkeid HUB/Console/HIDS-RASP 规则：仅 `private/elkeid/`，不进公开包。
- 禁止把 GPLv2-only 与 GPLv3 代码编译进同一二进制。
- CI 增加 license scan（`go-licenses`、`npm license-checker`、容器 SBOM）。

### 10.2 RBAC

- `admin`：全部
- `analyst`：事件、Incident、响应（需审批）
- `viewer`：只读

### 10.3 审计

- 登录、查询导出、规则变更、响应动作、Agent 操作全部写 `audit_log`。
- 审计不可变（append-only），支持导出。

### 10.4 响应安全

- 审批人不能是发起人（四眼原则）。
- 时间窗、目标白名单、爆炸半径、TTL、回滚。
- 失联 Agent 不允许执行破坏性动作。
- 所有动作先 dry-run。

---

## 11. 测试策略

### 11.1 命令

**编译机 `$BUILD_HOST`：**

```bash
ssh root@$BUILD_HOST
cd /opt/lyflow/src

# 后端
(cd server && go test ./...)
(cd agent && go test ./...)
(cd pkg && go test ./...)
(cd security-engine && go test ./...)

# 前端
(cd frontend && npm ci && npm run typecheck && npm run lint && npm test)

# 构建产物
mkdir -p /opt/lyflow/artifacts
# 按任务卡生成二进制/镜像 tar/SBOM
```

**测试机 `$TEST_HOST`：**

```bash
ssh root@$TEST_HOST
cd /opt/lyflow/deploy

# 部署配置校验
docker compose -f lean.yml config

# 启动/升级
docker compose -f lean.yml up -d

# 集成/E2E
# 由任务卡指定：Playwright、API 冒烟、PCAP 回放、压测

# 报告
mkdir -p /opt/lyflow/reports
```

**产物同步（编译机 → 测试机）：**

```bash
# 在编译机执行；先确认目标目录，避免误删
rsync -az --info=progress2 /opt/lyflow/artifacts/ root@$TEST_HOST:/opt/lyflow/deploy/artifacts/
```

> 禁止使用 `rsync --delete` 除非先确认测试机目录与快照；禁止把 `private/elkeid/` 同步到公开构建产物。


### 11.2 测试类型

- 单元测试：纯函数、解析、映射、阶段状态机
- 集成测试：ClickHouse/Postgres/Redis（testcontainers 或 compose）
- 契约测试：路由、事件 schema、API fixture
- E2E：总览、事件、Incident、规则、响应
- 语料测试：PCAP/EVTX/JSONL 回放
- 压测：20k EPS、1Gbps、查询 p95
- 安全测试：权限、注入、路径穿越、SSRF、密钥泄漏

### 11.3 测试数据

- 合成 PCAP/日志/进程事件
- 不提交真实客户数据
- `testdata/` 下的样本必须有来源和许可说明

---

## 12. 部署与运维

### 12.1 Compose profiles

```text
deploy/compose/lean.yml          默认
deploy/compose/full-private.yml  Elkeid HUB 私有模块
deploy/compose/observability.yml 可选
```

### 12.2 健康检查

- ly-server `/api/v1/health`
- ClickHouse `/ping`
- PostgreSQL `pg_isready`
- Wazuh Manager `wazuh-clusterd`/API
- Vector internal metrics
- ly_probe 状态文件
- Suricata `suricatasc`

### 12.3 备份/恢复

- PostgreSQL 每日 dump
- ClickHouse 表备份/冷数据导出
- 规则 bundle + 签名
- 配置 `.env` 加密备份

### 12.4 升级/回滚

- 镜像不可变 tag/digest
- 数据库 migration 向前兼容
- 规则 bundle 可回滚
- Agent 灰度升级 + 回滚

---

## 13. 里程碑与任务卡

> 规则：每个 Task ID 独立提交；完成后更新 `docs/dev/PROGRESS.md`。  
> Gate：每个里程碑结束由人类评审，评审通过才能进入下一阶段。

### M0：基础与契约（2 周）

#### T0.0 环境接入与基线
- 目标：验证编译机/测试机、安装工具链、建立目录、配置 SSH、跑通最小构建/部署。
- 依赖：无。
- 步骤：
  1. SSH 登录 `$BUILD_HOST` 与 `$TEST_HOST`，记录 OS/CPU/内存/磁盘/Docker/Go/Node/内核。
  2. 编译机创建 `/opt/lyflow/{src,artifacts,logs}`。
  3. 测试机创建 `/opt/lyflow/{deploy,data,reports}`。
  4. 配置从 Agent 环境到两台机器的 SSH key（密码只用于首次登录）。
  5. 编译机 clone 仓库并跑一次空构建；测试机准备 Docker Compose 并启动最小服务（Postgres + ClickHouse）。
  6. 把环境信息写入 `docs/dev/ENVIRONMENT.md`。
- 测试：
  ```bash
  ssh root@$BUILD_HOST 'uname -a; docker version; go version; node -v; df -h; free -h'
  ssh root@$TEST_HOST 'uname -a; docker version; docker compose version; df -h; free -h'
  ssh root@$TEST_HOST 'cd /opt/lyflow/deploy && docker compose -f lean.yml config'
  ```
- 验收：两台机器可免密登录；最小 compose 健康；`ENVIRONMENT.md` 存在。
- 不要做：不要在测试机开发；不要把密码写进仓库/脚本/镜像；不要跳过环境记录。

#### T0.1 建立开发规范与进度文件

- 目标：创建 `AGENTS.md`、`docs/dev/PROGRESS.md`、`docs/adr/` 模板。
- 涉及文件：`AGENTS.md`、`docs/dev/PROGRESS.md`、`docs/adr/000-template.md`。
- 步骤：
  1. 写入本文件的硬性规则摘要。
  2. 创建 ADR 模板（背景/决策/替代方案/后果）。
  3. 创建进度表（Task/状态/负责人/测试/风险）。
- 测试：无代码测试；检查 Markdown 链接。
- 验收：文件存在，内容与本文一致。
- 不要做：不要改业务代码。

#### T0.2 Feature flags 与配置
- 目标：新增 `EVENT_SCHEMA_V2_ENABLED`、`QUERY_V2_ENABLED`、`UI_SHELL_V2_ENABLED`、`CORRELATION_V2_ENABLED`、`AGENT_FACADE_ENABLED`、`RESPONSE_APPROVAL_ENABLED`。
- 涉及文件：`server/cmd/main.go`、`server/cmd/config.go`（如拆分）、`frontend/src/config`。
- 步骤：
  1. 在 Go 配置结构体加字段，默认 `false`。
  2. 前端用 `import.meta.env.VITE_*` 或运行时配置。
  3. 每个 flag 有注释和默认值。
- 测试：配置单元测试；`docker compose config`。
- 验收：默认关闭时行为与现在一致。
- 不要做：不要默认开启。

#### T0.3 Event v2 契约
- 目标：新增 `pkg/contracts/security_event_v2.go` + 测试。
- 涉及文件：`pkg/contracts/`。
- 步骤：
  1. 定义结构体、枚举、校验函数。
  2. 写正常/缺字段/非法 ATT&CK/非法证据的测试。
  3. 提供 v1 → v2 adapter。
- 测试：`cd pkg && go test ./contracts/...`。
- 验收：schema 校验通过；adapter 有测试。
- 不要做：不要删除 v1。

#### T0.4 证据模型与存储 schema
- 目标：新增 `pkg/contracts/evidence.go`、ClickHouse/Postgres migration。
- 涉及文件：`pkg/contracts/`、`server/analytics/`、`server/sql/`。
- 步骤：
  1. 定义 EvidenceRef。
  2. 新增 `incident_evidence`、`evidence_blobs` 表。
  3. 新增 ClickHouse `events_v2`、`flows_v2` migration。
- 测试：schema migration 在测试库执行；回滚脚本。
- 验收：迁移可重复执行；旧表不受影响。
- 不要做：不要删旧表。

#### T0.5 CI/测试脚本与许可检查
- 目标：新增 `scripts/dev/test-all.sh`、CI license scan。
- 涉及文件：`scripts/`、`.github/workflows/`。
- 步骤：
  1. 聚合各模块测试命令。
  2. 加 `go-licenses` / `npm license-checker`。
  3. 加 `private/elkeid` 排除检查。
- 测试：本地运行脚本。
- 验收：脚本可执行；CI 通过。
- 不要做：不要引入付费扫描器。

### M1：数据主链与 UI shell（4 周）

#### T1.1 Ingest v2
- 目标：实现 `/api/v2/ingest/events`，接收 Vector/Wazuh/Elkeid 事件并规范化。
- 涉及文件：`server/ingestv2/`、`server/cmd/`。
- 步骤：
  1. 定义请求体（批量、压缩可选）。
  2. 实现 source adapter：suricata、lyprobe、wazuh、elkeid、rasp。
  3. 写入 ClickHouse `events_v2`，失败落 spool。
  4. 加背压、超时、限流。
- 测试：单测 + 集成测试（ClickHouse）。
- 验收：20k EPS 压测通过；错误可重试。
- 不要做：不要解析所有字段；先保留 raw + 关键字段。

#### T1.2 Query v2 + 查询治理
- 目标：实现 `/api/v2/events`、`/api/v2/events/{uid}`，游标分页、超时、限流。
- 涉及文件：`server/query/`、`server/cmd/`。
- 步骤：
  1. 定义查询参数（时间、source、stage、severity、asset、technique、cursor）。
  2. 生成 ClickHouse SQL，禁止 `SELECT *`。
  3. 加最大范围/行数/超时。
  4. 返回 `next_cursor`。
- 测试：SQL 注入、超时、空结果、分页。
- 验收：7 天查询 p95 < 2s。
- 不要做：不要复用 ly_server 的 MariaDB 查询。

#### T1.3 新 UI shell
- 目标：按 ly_vis 排版实现顶部导航 + 二级页签 + 内容区。
- 涉及文件：`frontend/src/app/shell/`、`frontend/src/App.vue`、`frontend/src/router`。
- 步骤：
  1. 设计 token：颜色、间距、字号。
  2. 实现 `AppShell`、`TopNav`、`PageTabs`、`ContentFrame`。
  3. 保留旧 shell 通过 `UI_SHELL_V2_ENABLED` 切换。
  4. 浅色默认，深色 class 切换。
- 测试：Vitest 组件测试；Playwright 截图 375/768/1280。
- 验收：导航可达；无布局跳动；对比度达标。
- 不要做：不要复制 ly_vis 的 GPL 代码。

#### T1.4 总览页
- 目标：KPI、阶段漏斗、ATT&CK 热力、资产风险、实时流。
- 涉及文件：`frontend/src/views/situation/`、`frontend/src/api/`。
- 步骤：
  1. 接 `/api/v2/attack/coverage`、`/api/v2/events` 聚合。
  2. 实现 4 个组件。
  3. 空态显示“暂无数据”，不造假。
- 测试：组件测试 + E2E。
- 验收：数据为空时布局稳定。
- 不要做：不要在前端做全量聚合。

#### T1.5 事件中心 + 详情 + 证据面板
- 目标：事件列表、筛选、详情、证据抽屉。
- 涉及文件：`frontend/src/views/events/`、`frontend/src/components/evidence/`。
- 步骤：
  1. 列表：服务端分页、虚拟滚动。
  2. 详情：阶段条、技术卡、证据标签页。
  3. 证据：哈希、下载、原始 JSON。
- 测试：E2E 覆盖筛选/分页/详情。
- 验收：1000 条列表滚动流畅。
- 不要做：不要一次性加载全部。

#### T1.6 统一搜索
- 目标：IP/域名/哈希/进程/用户搜索。
- 涉及文件：`frontend/src/views/search/`、`server/query/`。
- 步骤：
  1. 识别输入类型。
  2. 查询 v2 事件/资产/Incident。
  3. 结果分组。
- 测试：各类输入 + 空结果。
- 验收：搜索 7 天数据 < 2s。
- 不要做：不要扫描全表。

#### T1.7 M1 验收
- 目标：E2E、契约、性能报告。
- 步骤：
  1. 跑全部测试。
  2. 生成 `docs/dev/M1-REPORT.md`。
- 验收：Gate G2 通过。
- 不要做：不要带入 M2 功能。

### M2：ATT&CK 与 Incident（4 周）

#### T2.1 ATT&CK 元数据与映射
- 目标：规则/事件补 tactic/technique/stage/confidence。
- 涉及文件：`pkg/contracts/attack_stage.go`、`server/correlation/mapping/`。
- 步骤：
  1. 内置 ATT&CK v16 战术/技术表。
  2. 解析 Suricata metadata、Wazuh `<mitre>`、OpenRASP 标签。
  3. 缺失映射用规则 ID 表补。
- 测试：映射覆盖率、非法 ID。
- 验收：Top 50 规则有映射。
- 不要做：不要猜技术 ID。

#### T2.2 阶段状态机
- 目标：实现阶段进入/退出/置信度。
- 涉及文件：`server/correlation/stage/`。
- 步骤：
  1. 定义阶段枚举、进入条件、时间窗。
  2. 实现状态机 + 证据门控。
  3. 输出可解释的置信度。
- 测试：正常链、缺证据、跨阶段跳变。
- 验收：3 条示例链通过。
- 不要做：不要单事件升级为 Incident。

#### T2.3 实体图与关联
- 目标：按资产/用户/进程/IP/哈希关联。
- 涉及文件：`server/correlation/graph/`。
- 步骤：
  1. 实体解析（IP↔资产、进程↔网络）。
  2. 滑动窗口 + 图查询。
  3. 关联结果写 `incidents`。
- 测试：NAT、共享账号、扫描噪声。
- 验收：误关联率可控。
- 不要做：不要引入 Neo4j；先用内存 + ClickHouse。

#### T2.4 Incident API/生命周期
- 目标：Incident 列表/详情/状态流转。
- 涉及文件：`server/incidentlifecycle/`、`server/cmd/`。
- 步骤：
  1. 阶段分组、证据挂载、时间线。
  2. 状态：open/investigating/resolved/closed。
  3. 审计。
- 测试：状态机、权限、并发。
- 验收：四眼原则/审计可用。
- 不要做：不要删除旧 Incident 接口。

#### T2.5 攻击链/时间线 UI
- 目标：阶段时间线、证据矩阵、实体图。
- 涉及文件：`frontend/src/views/attack/`。
- 步骤：
  1. 接入 `/api/v2/incidents/{id}`。
  2. 实现时间线/证据矩阵。
  3. 点击证据打开抽屉。
- 测试：E2E。
- 验收：3 条链可读。
- 不要做：不要画无证据的边。

#### T2.6 ATT&CK 覆盖率
- 目标：总览页矩阵 + 规则覆盖。
- 涉及文件：`server/query/`、`frontend/src/views/attack/`。
- 步骤：
  1. 聚合 tactic/technique 计数。
  2. 显示盲区。
- 测试：空数据/部分数据。
- 验收：矩阵可过滤。
- 不要做：不要伪造覆盖率。

#### T2.7 关联验证
- 目标：Atomic Red Team + 合成 PCAP 验证。
- 步骤：
  1. 选取 3 条链（Web→C2、SSH→横向、WebShell→提权）。
  2. 记录预期阶段/证据。
  3. 生成报告。
- 验收：Gate G3 通过。

### M3：Agent、RASP、响应（4 周）

#### T3.1 `ly-agent` supervisor
- 目标：一个安装包/服务/管理记录。
- 涉及文件：`agent/supervisor/`、`agent/cmd/`。
- 步骤：
  1. 定义插件接口/生命周期。
  2. 实现 transport、spool、健康、日志。
  3. 复用现有 `agent/cmd` 的可靠传输代码。
- 测试：进程崩溃重启、spool 重放。
- 验收：一个服务管理全部子进程。
- 不要做：不要重写 Elkeid/Wazuh。

#### T3.2 Linux Elkeid 集成
- 目标：Elkeid Agent/Driver 作为 Linux host-core。
- 涉及文件：`agent/supervisor/providers/elkeid/`。
- 步骤：
  1. 安装/配置/健康检查。
  2. 事件转 v2。
  3. 与 `ly-server` 对接。
- 测试：真实/容器 Linux。
- 验收：进程/网络/文件事件可见。
- 不要做：不要改 Elkeid 源码。

#### T3.3 Windows Wazuh 集成（CANCELLED）
- 2026-10-19 用户决策：放弃 Windows 端，不再构建/下载/安装 Windows Agent。
- 本节仅保留历史记录，不再包含设计、测试或验收项。

#### T3.4 OpenRASP Java/PHP
- 目标：Java/PHP RASP 接入。
- 涉及文件：`agent/supervisor/rasp/openrasp/`。
- 步骤：
  1. 安装/注入/配置。
  2. 事件转 v2。
  3. monitor 默认。
- 测试：示例应用 + 攻击用例。
- 验收：攻击可检测，业务无感。
- 不要做：不要默认 protect。

#### T3.5 Elkeid RASP Python/Go/Node
- 目标：Python/Go/Node RASP。
- 涉及文件：`agent/supervisor/rasp/elkeid/`。
- 步骤：
  1. 注入/配置。
  2. 事件转 v2。
  3. 与 OpenRASP 按运行时分工。
- 测试：Python 示例。
- 验收：命令执行/文件/网络 hook 可见。
- 不要做：不要在同一运行时双引擎。

#### T3.6 Agent 门面/API/UI
- 目标：统一 Agent 列表/详情/任务。
- 涉及文件：`server/agentfacade/`、`frontend/src/views/assets/`。
- 步骤：
  1. 聚合 Wazuh/Elkeid。
  2. 统一 ID/健康/版本。
  3. 任务下发/诊断。
- 测试：分页/过滤/权限。
- 验收：一个 Agent 记录。
- 不要做：不要暴露两个后端给 UI。

#### T3.7 安装器/自检/回滚
- 目标：安装前检查、幂等、自检、诊断包。
- 涉及文件：`agent/installer/`、`scripts/`。
- 步骤：
  1. 预检（权限/端口/磁盘/时间/内核）。
  2. 失败回滚。
  3. 自检报告。
- 测试：干净机/断网/权限不足。
- 验收：安装成功率 >99%。
- 不要做：不要静默失败。

#### T3.8 响应审批/时间窗/回滚
- 目标：L1 自动、L2 审批、时间窗、回滚、审计。
- 涉及文件：`server/response/`、`frontend/src/views/response/`。
- 步骤：
  1. 动作目录/风险级别。
  2. 审批流（四眼）。
  3. 执行器（Wazuh/Elkeid/防火墙）。
  4. 回滚/TTL/爆炸半径。
- 测试：越权、重复执行、失联。
- 验收：所有动作有审计。
- 不要做：不要自动隔离生产主机（默认）。

#### T3.9 横向移动检测
- 目标：SMB/RDP/WinRM/SSH/PsExec/WMI 关联。
- 涉及文件：`rules/`、`server/correlation/`。
- 步骤：
  1. 网络规则 + 主机事件。
  2. 序列关联。
  3. 误报抑制。
- 测试：合成链。
- 验收：3 条横向链可复现。
- 不要做：不要只靠端口判断。

### M4：内容、抓包、性能、交付（4 周）

#### T4.1 内容同步服务
- 目标：自动同步 ET Open/OpenRASP/CRS/Nuclei/CISA KEV 等。
- 涉及文件：`server/content/`、`rules/`。
- 步骤：
  1. 源注册/许可 gate。
  2. 下载/校验/编译/灰度/回滚。
  3. 健康看板。
- 测试：源失败、签名失败、回滚。
- 验收：每日自动更新。
- 不要做：不要抓取禁止源。

#### T4.2 Suricata/ET Open 集成
- 目标：每日更新 + 重载。
- 涉及文件：`deploy/suricata/`、`server/content/`。
- 步骤：
  1. `suricata-update` 配置。
  2. 规则校验/重载。
  3. 指标。
- 测试：1Gbps 压测。
- 验收：丢包 <1%。
- 不要做：不要手写下载器。

#### T4.3 ly_probe 产品化补丁
- 目标：配置校验/健康/热加载/日志/容器化。
- 涉及文件：`probe`/`ly_probe` 的补丁目录、`deploy/`。
- 步骤：
  1. 维护薄补丁集，不改核心算法。
  2. 加 `--check-config`、JSON 日志、状态文件。
  3. 热加载 `threat.json`/`fp-patterns`。
- 测试：配置错误/热加载/重启。
- 验收：抓包失败可诊断。
- 不要做：不要重写 nProbe 核心。

#### T4.4 ly_probe 规则转换
- 目标：ET/CRS/Nuclei → ly_probe JSON 规则。
- 涉及文件：`rules/lyprobe/`、`server/content/`。
- 步骤：
  1. 实现简单正则转换器。
  2. 生成规则 + 测试样例。
  3. 不可转换的标记为 Suricata-only。
- 测试：命中/不命中/性能。
- 验收：每周自动生成。
- 不要做：不要强行转换复杂规则。

#### T4.5 Capture doctor
- 目标：抓包预检/运行时监控/自动回退。
- 涉及文件：`deploy/`、`scripts/`。
- 步骤：
  1. 检查网卡/驱动/权限/ring buffer/GRO/LRO。
  2. 指标：pps/drops/queue。
  3. 异常重启/告警。
- 测试：错误网卡/权限不足。
- 验收：故障可定位。
- 不要做：不要静默重启。

#### T4.6 查询性能与压测
- 目标：20k EPS、1Gbps、p95 <2s。
- 步骤：
  1. 造 30 天数据。
  2. 跑查询基准。
  3. 调优物化视图/索引。
- 验收：Gate G5。
- 不要做：不要用采样掩盖问题。

#### T4.7 打包与 Compose profiles
- 目标：lean/full-private 两套 Compose。
- 涉及文件：`deploy/compose/`。
- 步骤：
  1. 拆服务。
  2. 加 healthcheck/资源限制。
  3. 一键安装/升级/回滚。
- 测试：干净机安装。
- 验收：一键可起。
- 不要做：不要把 private 打进公开包。

#### T4.8 文档/许可/安全审计
- 目标：发布前检查。
- 步骤：
  1. SBOM/license scan。
  2. 安全审计（权限/注入/SSRF/密钥）。
  3. 更新 README/ARCHITECTURE/API。
- 验收：无高危许可/安全问题。
- 不要做：不要带真实数据/密钥。

---

## 14. DeepSeek 执行模板

每个任务开始前，使用以下模板：

```text
Task: T{x.y} {名称}
Context: 读取 AGENTS.md、docs/dev/PROGRESS.md、docs/dev/WORKQUEUE.md、本任务相关包与测试。
Constraints: 只改任务范围；不改 third_party/GPL；不删旧 API；默认 feature flag 关闭。
Environment:
  Build: ssh root@$BUILD_HOST; /opt/lyflow/src
  Test:  ssh root@$TEST_HOST; /opt/lyflow/deploy
Plan:
  1. ...
  2. ...
Tests:
  - 编译机单元/构建
  - 测试机集成/E2E
Implementation:
  - ...
Result:
  - 变更文件
  - 测试命令与结果
  - 风险
  - 回滚方式
  - 未决事项（如有）
```

### 14.1 分支/提交

- 分支：`feat/T{x.y}-{short-name}` 或 `fix/...`
- 提交：Conventional Commits，例如 `feat(ingest): add event v2 endpoint`
- 一个 Task 一个 PR（或一个提交序列），不混入无关格式化。

### 14.2 提问 Gate

只在以下情况停下提问：

- 需要改变本文的架构选型
- 需要引入新的 GPL/AGPL 组件
- 需要改数据库主键/删除字段
- 需要改公开 API 的语义
- 需要启用自动响应
- 发现现有代码与本文冲突且无法兼容

其他情况自行决策，并在 PR 中说明。

**连续执行要求：**

- 竣工前不停止。每个 Task 完成后立即从 `WORKQUEUE.md` 取下一个未阻塞 Task。
- 小决策不提问：按 0.3 的默认规则选择，写入 `DECISIONS.md`，继续。
- 机器不可达/凭据失效：记录阻塞，先做不依赖该机器的 Task；恢复后继续。
- 测试失败：修复并重跑；同一问题连续 3 次无进展，记录并切换独立 Task。
- Gate 评审未到：继续做不依赖该 Gate 的 Task，不空等。

### 14.3 代码质量

- Go：`gofmt`、`go vet`、错误包装、context 超时、日志脱敏。
- Vue：`<script setup>`、组合式函数、无全局状态滥用、可访问性。
- SQL：参数化、索引、LIMIT、超时。
- 配置：环境变量优先，敏感值不落盘明文。

---

## 15. 风险与 ADR

| 风险 | 影响 | 缓解 |
|---|---|---|
| GPL/Elkeid License 混用 | 法律风险 | 进程隔离；private 不进公开包；CI 扫描 |
| ly_probe 抓包不稳定 | 主链中断 | Suricata 兜底；capture doctor；自动重启 |
| RASP 规则覆盖不足 | 检测盲区 | 自动同步 + CRS/Nuclei 虚拟补丁；写明边界 |
| Agent 双栈复杂 | 运维成本 | 一个 supervisor/安装包/管理记录 |
| 查询性能 | 死机 | ClickHouse + 预聚合 + 查询治理 |
| 关联误报 | 运营负担 | 证据门控 + 置信度 + 白名单/时间窗 |
| 主动防御误杀 | 业务风险 | 默认审批；dry-run；TTL/回滚；爆炸半径 |
| 范围膨胀 | 交付延期 | 严格按 M0–M4；非目标不做 |

ADR 建议：

- ADR-001：ly_probe 主探针 + Suricata 协处理
- ADR-002：Event v2 与证据模型
- ADR-003：ATT&CK 阶段状态机
- ADR-004：ly-agent supervisor 组合式 Agent
- ADR-005：默认 Wazuh + 可选 Elkeid 私有模块
- ADR-006：RASP 引擎分工与规则自动同步
- ADR-007：查询层迁移 ClickHouse/Postgres
- ADR-008：开源许可与私有模块边界

---

## 16. 附录

### 16.1 术语

| 术语 | 含义 |
|---|---|
| 事件 | 单条安全遥测/告警 |
| Incident | 多源关联后的案件 |
| 阶段 | ATT&CK 战术/攻击链阶段 |
| 证据 | 可追溯的原始数据引用 |
| Bundle | 一次规则发布包 |
| Lean | 默认轻量部署 |
| Full-private | 含 Elkeid HUB 的私有部署 |

### 16.2 常用命令

```bash
# 编译机
ssh root@$BUILD_HOST
cd /opt/lyflow/src
(cd server && go test ./...)
(cd pkg && go test ./...)
(cd frontend && npm run typecheck && npm test)

# 测试机
ssh root@$TEST_HOST
cd /opt/lyflow/deploy
docker compose -f lean.yml config
```

### 16.3 关键文件

- 架构：`ARCHITECTURE.md`
- 设计系统：`DESIGN.md`
- API：`docs/API.md`
- 功能边界：`docs/zh/当前功能盘点与能力边界.md`
- 事件契约：`pkg/contracts/security_event.go`
- 路由策略：`server/cmd/route_registry.go`
- 前端 shell：`frontend/src/app/AppShell.vue`
- 规则：`rules/`
- 开发环境记录：`docs/dev/ENVIRONMENT.md`
- 工作队列：`docs/dev/WORKQUEUE.md`
- 决策记录：`docs/dev/DECISIONS.md`

### 16.4 发布前检查清单

- [ ] 编译机 `$BUILD_HOST` 干净构建通过
- [ ] 测试机 `$TEST_HOST` 全量验收通过
- [ ] lean/full-private 均可启动
- [ ] 抓包丢包 <1%
- [ ] 20k EPS 稳定
- [ ] 查询 p95 <2s
- [ ] Agent 安装/回滚通过
- [ ] 3 条 ATT&CK 链验证
- [ ] 响应审批/回滚/审计通过
- [ ] 许可扫描通过
- [ ] 无 secret/真实数据
- [ ] 文档更新

### 16.5 环境与凭据（敏感）

| 用途 | 地址 | 用户 | 初始密码 | 目录 |
|---|---|---|---|---|
| 编译机 | `$BUILD_HOST` | `root` | `<REDACTED>` | `/opt/lyflow/src`、`/opt/lyflow/artifacts` |
| 测试机 | `$TEST_HOST` | `root` | `<REDACTED>` | `/opt/lyflow/deploy`、`/opt/lyflow/reports` |

**安全要求：**

- 本文件不包含凭据；实际地址与凭据见 `/opt/lyflow/ENVIRONMENT.local.md`（不入库）。
- 首次登录后配置 SSH key，轮换密码；密码只用于首次接入。
- 禁止把密码写入脚本、Dockerfile、镜像、日志、构建产物。
- 若凭据失效或机器不可达，记录到 `docs/dev/DECISIONS.md` 并暂停依赖该机器的任务，转向不依赖的任务。
- 测试机操作前尽量打快照；删除数据卷/重装前必须人工确认。


---

> 本文件是 LyFlow 最新版的开发基线。任何偏离本文件的架构变更，必须先写 ADR 并经人类确认。
