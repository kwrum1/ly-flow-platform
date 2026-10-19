# G5 全栈验收报告

日期：2026-10-19  
测试机：`lyflow-test` / `10.1.18.126`  
规格：6 vCPU / 8 GiB / 120 GiB  
结果：**PASS_WITH_EXCEPTIONS**

## 1. 部署形态

验收使用 `deploy/compose/g5-host.yml`（测试专用 host-network 拓扑）：

- Pingora 前端（`ly-flow/frontend:latest`）
- `ly-server`
- `ly-agent-center`
- `ly-security-engine`
- PostgreSQL 15.18（本地 `safeline-postgres` 镜像，标准 entrypoint）
- Redis 7.2（本地构建，BSD-3）
- ClickHouse 26.9.21.9（测试机原生进程）
- `lyprobe-sensor`
- `suricata-sensor` 7.0.3
- `ly-flow-rulecompiler`
- `ly-flow-capturedoctor`

## 2. 服务状态

```text
lyflow-g5-ly-server-1             healthy
lyflow-g5-ly-agent-center-1       healthy
lyflow-g5-ly-security-engine-1    healthy
lyflow-g5-ly-vis-1                healthy
lyflow-g5-postgres-1              healthy
lyflow-g5-redis-1                 healthy
lyflow-g5-lyprobe-sensor-1        healthy
lyflow-g5-suricata-sensor-1       healthy
lyflow-g5-lyflow-rulecompiler-1   healthy
lyflow-g5-lyflow-capturedoctor-1  healthy
```

原生 ClickHouse 另由 systemd 管理，`clickhouse-client SELECT version()` = `26.9.21.9`。

## 3. 前端与 API

Pingora 前端替换 nginx：

- HTTP 80：`308 Permanent Redirect` 到 HTTPS
- HTTPS 443：返回 Vue 控制台 `index.html`
- `/api/v1/health`：`{"status":"healthy"}`
- `/api/v1/auth/login`：成功，强制首次改密
- `/api/v1/auth/change-password`：成功
- `/api/v1/agents`：成功返回 agent 列表
- `/api/v1/stats`：成功
- `/api/v2/events`：成功
- `/api/v2/events/`：成功（详情路由）
- `/api/v1/agent/install.sh`：返回 `https://...` 安装脚本，Host 注入防护生效
- `/api/v1/engine-runtime/status`：配置 `SECURITY_ENGINE_HEALTH_URL=http://127.0.0.1:8082/health`
  后返回 200，XDR/运行态页面不再出现 503

控制台默认启用 ly_vis 排版与 ATT&CK V2 视图：

- 一级导航 50px、二级页签 45px、内容区 20px
- 默认浅色
- `/dashboard` 使用运营总览（KPI、阶段分布、ATT&CK 热力、最近事件）
- `/events` 使用事件中心 V2，支持筛选、详情抽屉、证据与原始载荷
- `/incidents` 使用攻击链 V2，支持阶段时间线、证据矩阵和状态更新

## 4. 自签证书 UI 验收

生产 dist 由 Vite preview 提供，`/api`、`/ws` 反向代理到自签 HTTPS 测试机
（`secure:false` / `ignoreHTTPSErrors:true`）。自签证书不再作为阻塞项。

Playwright Firefox 实测：

- 1440×900 桌面 + 390×844 移动端
- 17 个页面：登录、总览、全球态势、XDR、Incident、资产、事件、运行态、
  规则中心、规则更新、控制中心、安装配置、流量、RASP
- 192 个请求状态正常，0 console error、0 page error、0 失败请求、0 4xx/5xx
- 所有页面无水平溢出
- 总览、事件列表、Incident 列表和详情时间线均有真实 G5 数据
- 截图与 `validation.json` 位于 `/opt/lyflow/reports/G5/ui-production/`

## 5. API 冒烟

使用 admin token 实测以下端点全部 HTTP 200：

```text
/api/v1/health
/api/v1/stats
/api/v1/events
/api/v1/incidents
/api/v1/rules
/api/v1/rules/inventory
/api/v1/rules/sources
/api/v1/assets
/api/v1/assets/stats
/api/v1/traffic/threats
/api/v1/traffic/flows
/api/v1/traffic/sessions
/api/v1/agents
/api/v2/events
```

`/api/v1/assets` 返回 G5 注册的 Agent；`/api/v2/events` 返回 G5 写入事件。

## 6. 端到端事件闭环

通过真实 API 完成：

1. 管理员登录并修改密码。
2. 管理员签发一次性 enrollment token。
3. `g5-agent` 注册，获得 agent credential。
4. 使用 agent credential 调用 `POST /api/v2/ingest/events`。
5. 事件写入 ClickHouse。
6. 管理员通过 `GET /api/v2/events` 查询到同一 `event_uid`。
7. `GET /api/v1/agents` 返回该 agent。
8. `POST /api/v1/agent/heartbeat` 后 `/api/v1/assets/stats` 显示 `online=2`，
   `/api/v1/agents` 返回在线 agent。

结果：

```text
ingest: accepted=1
agent: g5-agent online
event_uid: g5-e2e-1792396452
G5_E2E_OK
```

## 7. Event v2 → Incident 闭环

本轮修复了 v2 事件与旧 XDR/Incident 管线之间的断点：

- `WriteEventsV2` 在写 ClickHouse 后生成 canonical 投影，供既有 XDR graph 消费。
- 投影保留 `agent_id`、ATT&CK tactic/technique/stage、网络五元组、规则和治理字段。
- XDR graph 生成攻击链，`/api/v1/incidents` 同步为持久化 Incident。
- 路径包含 `weak_same_ip` 时不提升为 Incident，避免同源 IP 的不同资产被误并。
- 不改变 v2 ClickHouse 主写入路径；投影失败只记录日志，不影响事件入库/查询。

实测写入 2 条同资产、不同阶段的 v2 事件（`initial_access` + `execution`）：

```text
v2 events: 2
incidents: 3（含本轮新增）
incident evidence: 2
stages: initial_access, execution
G5_INCIDENT_OK
```

控制台 `/events` 可查询并打开详情抽屉；`/incidents` 显示攻击链、阶段时间线和证据矩阵。

## 8. 重启持久化

执行：

```bash
docker compose --env-file lean.env -f g5-host.yml restart
```

重启后 10 个服务全部回到 healthy，使用 admin token 再次查询 `/api/v2/events` 仍返回
`g5-e2e-...`，PostgreSQL/ClickHouse/Redis 数据保留。

## 9. 采集面

- lyprobe 加载 106 条 pattern，并完成 `Hot-reloaded 106 patterns`。
- Suricata 7.0.3 在 `ens160` 上启动，加载 11 条规则；出现 af-packet 配置回退提示，
  但引擎正常启动。
- rulecompiler 生成 6 条转换规则、2 条跳过。
- capturedoctor 输出 `process=true`，`status=warn`，问题为 RX ring 1024、GRO on、
  PF_RING 未加载，和 T4.5 基线一致。

## 10. 例外与限制

1. **Docker Hub 镜像不可稳定拉取**：`docker.1ms.run` 可拉取 Rust 镜像，但
   PostgreSQL/ClickHouse 镜像多次超时。G5 使用本地 `safeline-postgres:15.18` 和
   原生 ClickHouse，Redis/Pingora/服务镜像均本地构建。
2. **生产 lean 还未走上述例外路径**：`lean.yml` 仍以标准镜像 tag 为目标，正式发布前
   必须补齐可复现镜像源/离线包。
3. **Elkeid/Wazuh/OpenRASP 原生产品未接入**：当前已验证 `ly-agent` 真实注册、心跳、
   资产采集、Suricata EVE 适配；YARA 因测试机缺二进制处于 degraded，RASP 未启用。
4. **Vector 未进入 lean**：当前实际告警链路由 Agent EVE adapter 承担；Vector 打包
   仍是后续项，不能把现有链路称为 Suricata→Vector→ly-server。
5. **未做 ESXi 快照**：发布前必须补快照。
6. **容量**：T4.6 结论保持不变；6 vCPU/8 GiB 不是正式 20k EPS + 1Gbps 保证配置。
7. **XDR weak_same_ip 关联**：已阻止包含 `weak_same_ip` 的新路径提升为 Incident；
   测试机历史合成 Incident 仍保留在测试库中，正式验收前需清理测试数据。
8. **YARA/RASP 运行时**：测试机未安装 yara；RASP probe manager 未启用，UI 已按
   Agent capability 显示未启用原因。

## 11. 证据

```text
/opt/lyflow/reports/G5/
├── ps.txt
├── health.json
├── login.json
├── agents.json
├── stats.json
├── events-v2.json
├── g5-incident-e2e.out
├── g5-heartbeat.out
├── real-agent.out
├── runtime-integration.out
├── suricata-alert-chain.out
├── real-integration.txt
├── restart-check.json
├── restart-check-final.json
├── ui-acceptance.txt
├── ui-production/
│   ├── validation.json
│   ├── dashboard-1440x900.png
│   ├── events-1440x900.png
│   ├── incidents-1440x900.png
│   └── *-390x844.png
├── install.sh
├── g5-restart.txt
├── *.log
├── capture-doctor.json
├── images.txt
└── disk.txt
```

## 12. 真实 Agent / 告警 / UI 联调增量

### 12.1 真实 Agent

- 在 `10.1.18.126` 部署 `/opt/ly-agent/ly-agent`，使用自签 HTTPS + 忽略证书校验。
- 注册 ID `g5-real-agent`，状态 `online`，心跳正常。
- 资产数据来自真实 Agent：
  - CPU / 内存 / 磁盘 / 主机名 / 网卡 / 进程数
  - 资产页面显示 `fresh`
- 能力上报：
  - `runtime_sensor=enabled`（eBPF fallback，monitor）
  - `yara_scanner=degraded`（测试机未安装 yara）
  - `rasp_probe_manager=disabled`
  - `traffic_collector=disabled`
- 结果：`G5_REAL_AGENT_OK`。

### 12.2 告警链路

实际打通：

```text
Suricata 7.0.11 EVE
  → ly-agent Suricata profile adapter
  → Redis component_alerts:v2
  → ly-server 持久化
  → /api/v1/threats/traffic
  → UI /traffic-threats
```

真实 PCAP 回放命中 SID `9000001`，Agent 适配器 `parsed_lines=3`、
`status=healthy`；API 返回 1 组威胁，UI 流量页显示 Suricata 告警。
当前链路由 Agent EVE adapter 承担；Vector 仍未加入 lean，作为后续打包项。

### 12.3 UI 后端能力对齐

- 总览在线 Agent/资产总数改用 `/api/v1/assets/stats`。
- 全球态势在公网地理数据为空时回退到真实 Incident 列表。
- 运行威胁页改查 `/api/v1/component-alerts/runtime`，显示真实 HIDS/Wazuh 事件；
  RASP 页在 Agent 未启用 RASP 时显示明确原因。
- 资产页增加“能力”列，按 Agent capabilities 显示运行/YARA/日志/RASP。
- 事件页/流量页/XDR 页均直接从对应后端 API 读取，不使用静态前端数据。
- 导航补 XDR 调查入口。
- 安装页 Linux 支持范围改为 Ubuntu 22.04+ / Debian 12+ / 现代 Linux。
- 自签证书 UI 验收：生产 dist 17 页，0 console/page/network error，
  0 4xx/5xx，0 水平溢出。
