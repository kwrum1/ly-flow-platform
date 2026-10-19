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

控制台默认启用 ly_vis 排版与 ATT&CK V2 视图：

- 一级导航 50px、二级页签 45px、内容区 20px
- 默认浅色
- `/dashboard` 使用运营总览（KPI、阶段分布、ATT&CK 热力、最近事件）
- `/events` 使用事件中心 V2，支持筛选、详情抽屉、证据与原始载荷
- `/incidents` 使用攻击链 V2，支持阶段时间线、证据矩阵和状态更新

## 4. API 冒烟

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

## 5. 端到端事件闭环

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

## 6. Event v2 → Incident 闭环

本轮修复了 v2 事件与旧 XDR/Incident 管线之间的断点：

- `WriteEventsV2` 在写 ClickHouse 后生成 canonical 投影，供既有 XDR graph 消费。
- 投影保留 `agent_id`、ATT&CK tactic/technique/stage、网络五元组、规则和治理字段。
- XDR graph 生成攻击链，`/api/v1/incidents` 同步为持久化 Incident。
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

## 7. 重启持久化

执行：

```bash
docker compose --env-file lean.env -f g5-host.yml restart
```

重启后 10 个服务全部回到 healthy，使用 admin token 再次查询 `/api/v2/events` 仍返回
`g5-e2e-...`，PostgreSQL/ClickHouse/Redis 数据保留。

## 8. 采集面

- lyprobe 加载 106 条 pattern，并完成 `Hot-reloaded 106 patterns`。
- Suricata 7.0.3 在 `ens160` 上启动，加载 11 条规则；出现 af-packet 配置回退提示，
  但引擎正常启动。
- rulecompiler 生成 6 条转换规则、2 条跳过。
- capturedoctor 输出 `process=true`，`status=warn`，问题为 RX ring 1024、GRO on、
  PF_RING 未加载，和 T4.5 基线一致。

## 9. 例外与限制

1. **Docker Hub 镜像不可稳定拉取**：`docker.1ms.run` 可拉取 Rust 镜像，但
   PostgreSQL/ClickHouse 镜像多次超时。G5 使用本地 `safeline-postgres:15.18` 和
   原生 ClickHouse，Redis/Pingora/服务镜像均本地构建。
2. **生产 lean 还未走上述例外路径**：`lean.yml` 仍以标准镜像 tag 为目标，正式发布前
   必须补齐可复现镜像源/离线包。
3. **未验证真实 Agent/RASP**：只验证了 enrollment + v2 ingest；Elkeid/Wazuh/OpenRASP
   真实主机链路仍是 M3 残余。
4. **生产 HTTPS 浏览器自动验收**：Playwright Chromium 在构建机受 GPU 限制，生产
   前端又是自签证书；本轮改用 Vite HTTP 验收代理完成真实登录、总览、事件详情、
   Incident 时间线验证。正式发布前仍需在可信证书环境补一次截图冒烟。
5. **未验证 Suricata → Vector → ly-server 真实告警链**：T4.2 已验证 PCAP 回放，
   Vector 尚未加入 lean。
6. **未做 ESXi 快照**：发布前必须补快照。
7. **容量**：T4.6 结论保持不变；6 vCPU/8 GiB 不是正式 20k EPS + 1Gbps 保证配置。

## 10. 证据

```text
/opt/lyflow/reports/G5/
├── ps.txt
├── health.json
├── login.json
├── agents.json
├── stats.json
├── events-v2.json
├── g5-incident-e2e.out
├── ui-acceptance.txt
├── install.sh
├── g5-restart.txt
├── *.log
├── capture-doctor.json
├── images.txt
└── disk.txt
```
