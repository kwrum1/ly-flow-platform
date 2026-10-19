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
- `lyflow-vector` 0.49.0（Suricata EVE → component alert）
- Wazuh manager 4.9.2（测试机 systemd，本机 native alerts）
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
lyflow-g5-lyflow-vector-1         healthy
lyflow-g5-lyflow-rulecompiler-1   healthy
lyflow-g5-lyflow-capturedoctor-1  healthy
```

Wazuh manager 4.9.2 由 systemd 管理，状态 `active`，使用
`/var/ossec/logs/alerts/alerts.json` 作为 ly-agent 输入。

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

重启后 11 个服务全部回到 healthy，使用 admin token 再次查询 `/api/v2/events` 仍返回
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
2. **生产 lean 还未走上述例外路径**：`lean.yml` 已有 SeaweedFS `evidence`
   profile 和本地构建服务，但标准 PostgreSQL/ClickHouse/Redis 镜像仍需固定
   digest 或离线包。
3. **Wazuh/OpenRASP/Elkeid 边界**：Wazuh manager 4.9.2 已本地安装并进入
   NDR/XDR；OpenRASP 1.3.7 engine 已通过 Jetty 9.4 真实 alarm 并接入
   component alerts；原生安装脚本在 `deploy/native/`；Elkeid 集成按当前决策放弃。
   LyFlow 自身 Agent/HIDS/YARA/多语言 RASP/Vector 链路真实运行。
4. **ESXi 快照/干净 VM 被凭据阻塞**：测试机旧 lab 密码和 `esxi_lab` 公钥均
   无法登录 10.1.18.124，当前没有有效 ESXi root 凭据；已备份当前 Agent
   `/opt/lyflow/backups/g5-agent-pre-wazuh-20261019-2221.tgz`。
5. **容量**：T4.6 结论保持不变；6 vCPU/8 GiB 不是正式 20k EPS + 1Gbps 保证配置。
6. **XDR weak_same_ip 关联**：已阻止包含 `weak_same_ip` 的新路径提升为 Incident；
   测试机历史合成 Incident 仍保留在测试库中，正式验收前需清理测试数据。
7. **多语言 RASP**：Python/Java/PHP/Node/dotnet 已完成真实运行时 attach 和事件入库；
   上游 OpenRASP engine 已 attach，并已通过 Jetty 真实 alarm 接入；Go RASP probe
   仍未做真实应用联调。
8. **Installer 完整安装**：安装资产和下载端点已验证；干净 VM 创建被 ESXi 凭据阻塞，
   未重跑 systemd 全套安装。
9. **Pingora FD 上限**：测试容器曾达到 nofile 上限；已把 `ly-vis` 的 nofile
   提升到 65536 并验证恢复。长期连接压力仍需单独观察。
10. **响应执行范围**：`block_ip`、`process_kill`、`file_delete`、
    `account_disable`、`isolate_host`、`namespace_isolate` 均已实现
    审批、执行、回滚；破坏性动作由 `RESPONSE_ENABLE_*` 默认关闭，
    测试时显式开启。`process_kill` 不可回滚。
11. **Windows 端已砍掉**：不再构建/下载/安装 Windows Agent；只保留
    Linux amd64/arm64。Elkeid 同样放弃。
12. **旧兼容路径已关闭**：Event v1 和旧 response candidate/advisory
    入口返回 403；内部数据迁移代码仍保留用于既有数据，但不再对外暴露。

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
├── vector-integration.txt
├── rasp-integration.txt
├── rasp-multilang.txt
├── native-integration.txt
├── wazuh-native.txt
├── wazuh-manager.txt
├── openrasp-engine.txt
├── openrasp-adapter.txt
├── response-integration.txt
├── response-expanded.txt
├── evidence-object-store.txt
├── lateral-integration.txt
├── legacy-retirement.txt
├── clean-vm.txt
├── yara-integration.txt
├── installer-integration.txt
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
- 能力上报（2026-10-19 最终态）：
  - `runtime_sensor=enabled`（eBPF fallback，active）
  - `yara_scanner=enabled`（native-yara-cli，active）
  - `rasp_probe_manager=enabled`（monitor）
  - `log_collector=enabled`
  - `traffic_collector=enabled`
- 结果：`G5_REAL_AGENT_OK`。

### 12.2 告警链路

实际打通：

```text
Suricata 7.0.11 EVE
  → Vector 0.49.0 file source + VRL component alert mapping
  → HTTP POST /api/v1/agent/component-alert
  → Redis component_alerts:v2
  → ly-server 持久化
  → /api/v1/component-alerts/traffic
  → UI /traffic-threats
```

真实 PCAP 回放命中 SID `9000001`，Vector 生成
`vector-suricata-...-9000001`；服务端接受单对象和 JSON 数组，写入 canonical
并发布 `component_alerts:v2`。UI 流量页显示 Vector 告警，XDR 事件模块为 `dpi`。

Agent Suricata EVE adapter 仍保留作为无 Vector 环境的备用路径；当前 G5/lean
默认启用 Vector，测试 Agent 已关闭自己的 Suricata profile 以避免重复告警。
服务端同时补了数组请求支持，兼容 Vector HTTP sink 的批量编码。

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

### 12.4 多语言 RASP 真实检测

- `ly-agent` RASP manager 已进入 monitor 模式并监听 `127.0.0.1:17891`。
- 测试机安装并实际挂载：
  - Java 17.0.20.1：`-javaagent:/opt/ly-agent/rasp/java/ly-rasp-agent.jar`
  - PHP 8.3.6：`auto_prepend_file=/opt/ly-agent/rasp/php/ly_rasp_prepend.php`
  - Node 18.19.1：`--require /opt/ly-agent/rasp/nodejs/ly_rasp.js`
  - .NET 8.0.131：`DOTNET_STARTUP_HOOKS=.../LyRaspProfiler.dll`
  - Python 3.12：`sitecustomize` / `ly_rasp`
- Python 命令注入命中 `;\s*rm\s`；Java/PHP/Node/.NET 分别产生
  `rasp.command`、`rasp.sql`、`rasp.file` 事件。
- 修复内容：
  - Python `ly_rasp.enable` 现在注册 reporter；
  - Node probe 修复 `http.request` 自递归；
  - Java/PHP/Node/.NET probe 自动获取 bridge 轮换 token 和 agent id；
  - Agent bridge 兼容 legacy probe payload 并归一化为 RASP 事件；
  - RASP policy 默认语言扩展到 python/java/php/nodejs/dotnet/go。
- 实测 component alerts：Python 5、Java 6、PHP 6、Node 13、.NET 6；
  `/rasp` 页面显示 39 组，语言/应用字段可见，过滤 heartbeat 后无噪声。
- 详细证据：`/opt/lyflow/reports/G5/rasp-multilang.txt`。

### 12.5 YARA 与 Installer 资产

- YARA 4.5.0 已安装；规则包由 `rules/yara` 中可编译规则合并为
  `/opt/ly-agent/yara/rules.yar`（约 5.8 MB），Agent capability 为 active。
- 安装端点无 JWT 即可访问：
  - `install.sh` 200
  - `uninstall.sh` 200
  - `agent/download?os=linux&arch=amd64` 200（约 13.1 MB）
  - `agent/download?os=linux&arch=arm64` 200（约 12.9 MB）
  - `agent/download?os=windows&arch=amd64` 400（Windows 支持已砍掉）
  - `agent/rasp/policy-root` 200（RASP 策略根证书）
  - Python/PHP/Java/Node.js/.NET RASP probe 均 200
  - .NET probe 为可挂载的 `LyRaspProfiler.dll`
- 安装脚本自动下载 `/api/v1/agent/rasp/policy-root` 到
  `/etc/lyflow/trust/policy-root.pem`，干净主机可验证 RASP 签名策略。
- `scripts/build-agent-binaries.sh` 统一构建三平台二进制，`build-core-images.sh`
  在构建镜像前自动执行。
- `server-lean.Dockerfile` 已包含 Agent 二进制和 `probe/` 资产。
- 安装令牌流程：
  - 安装页调用 `/api/v1/agent/identity` 生成 10 分钟一次性 token；
  - 命令使用 `/api/v1/agent/install.sh?enrollment_token=...`；
  - 脚本写入 `/opt/ly-agent/etc/agent.env`，systemd 通过 `EnvironmentFile` 注入；
  - token 只允许安全字符，服务端拒绝危险字符。
- 实测安装脚本 200，token 已嵌入且 `EnvironmentFile` 存在。
- 未在运行中的测试 Agent 上重跑整套 systemd 安装，避免覆盖当前联调实例；
  干净主机安装仍作为发布前动作。

### 12.6 原生 Wazuh / OpenRASP / Elkeid 适配

- Wazuh：测试机已本地安装 `wazuh-manager 4.9.2-1`，systemd active；
  已关闭 rootcheck/syscheck/sca/indexer/vulnerability 等高开销模块，并增加
  2 GiB swap。manager 写入 `/var/ossec/logs/alerts/alerts.json`，
  `ly-agent` native alerts JSON 适配器将其映射为 `source_engine=wazuh` 的
  ComponentAlert。实测 component alerts 231 条（wazuh 41）、XDR events 中
  wazuh 13 条、UI 运行威胁 67 组；Incident 从 39 增至 149。
- OpenRASP：已下载官方 `v1.3.7` `rasp-java.tar.gz`，解压到测试机
  `/opt/openrasp`；Java 17 使用 `--add-opens` + `-javaagent:rasp.jar`
  初始化 `[OpenRASP] Engine Initialized`。已用 Jetty 9.4 部署真实请求
  `/?cmd=cat /etc/passwd`，OpenRASP 产生 `command_userinput` alarm；
  `scripts/native/openrasp-alarm-bridge.py` + `lyflow-openrasp-bridge.service`
  将 alarm 归一化并送入 component alerts，UI `/rasp` 显示 42 组。
- Elkeid：按当前决策**放弃 Elkeid 集成**；私有 HUB/Console/HIDS-RASP 包
  不进入公开构建，现有 provider 代码保留但不作为验收项。
- 详细边界：`/opt/lyflow/reports/G5/native-integration.txt`、
  `wazuh-manager.txt`、`openrasp-engine.txt`、`openrasp-adapter.txt`。

### 12.7 响应执行 / 审批 / 回滚

- 新增持久化响应动作 API：
  - `GET/POST /api/v1/response/actions`
  - `POST /api/v1/response/actions/{id}/approve`
  - `POST /api/v1/response/actions/{id}/rollback`
- 响应策略：
  - L1 观察类自动；
  - L2 `block_ip` 默认需要不同已认证 approver；
  - L3 `process_kill` / `file_delete` / `account_disable` /
    `namespace_isolate` / `isolate_host` 始终需要审批；
  - 自动时间窗由 `RESPONSE_AUTO_WINDOW_ENABLED` 和窗口环境变量控制，
    有单测覆盖；生产默认关闭。
- Agent 执行器：
  - `block_ip` / `unblock_ip`：nftables set；
  - `process_kill`：PID 校验，拒绝 PID 1/Agent/父进程，signal + 进程消失校验；
  - `file_delete` / `file_restore`：隔离到
    `/var/lib/lyflow/quarantine/<sha256(path)>`，可恢复原文件；
  - `account_disable` / `account_enable`：`chage -E` 过期/恢复，不处理 root/Agent 账户；
  - `isolate_host` / `host_unisolate`：nftables input/output drop，
    保留 loopback、established 和 `RESPONSE_MANAGEMENT_CIDRS` 管理网；
  - `namespace_isolate` / `namespace_restore`：Docker 网络断开/恢复，
    状态文件保存原网络。
- 安全默认：
  - 所有破坏性动作由 `RESPONSE_ENABLE_*` feature flag 控制，默认关闭；
  - 文件动作默认只允许 `/tmp/lyflow-response`、`/var/tmp/lyflow-response`；
  - `isolate_host` 必须显式提供管理网 CIDR。
- 实测：
  - `203.0.113.77` / `198.51.100.88`：block → nft 元素 → rollback 清空；
  - 文件：quarantine → restore 内容一致；
  - 进程：kill 后 PID 消失；
  - 账号：expire → restore；
  - 主机隔离：管理网 SSH 保持，rollback 删除 nft 表；
  - 容器隔离：bridge 网络断开 → rollback 恢复 IP。
  - 证据：`/opt/lyflow/reports/G5/response-expanded.txt`。

### 12.8 证据对象存储 / SeaweedFS

- G5 增加 SeaweedFS 3.80：master `19333`、volume `18080`、
  filer `18888`、S3 `18333`，数据卷 `g5_seaweed_data`。
- `ly-server` 使用 `EVIDENCE_OBJECT_STORE=filer`，对象字节写入
  SeaweedFS filer；元数据、bundle 索引和接收记录保存在
  `g5_evidence_data`。
- 新增 API：
  - `POST/GET /api/v1/evidence/artifacts`
  - `GET /api/v1/evidence/artifacts/{id}`
  - `POST/GET /api/v1/evidence/bundles`
  - `GET /api/v1/evidence/bundles/{id}`
  - `GET /api/v1/evidence/bundles/{id}/download`
- 实测 artifact + bundle 创建、Filer 对象读取、下载 SHA256、列表均通过。
- 证据：`/opt/lyflow/reports/G5/evidence-object-store.txt`。

### 12.9 横向移动实时接入 / 旧路径清理

- `lateral.Tracker` 已接入 `StorageEventRuntime.WriteEventsV2`：
  滚动窗口、去重、5000 条上限；发现横向移动时生成
  `event_type=lateral.movement`、`stage=lateral_movement` 的派生事件，
  进入 ClickHouse 和 XDR 投影。
- 实测 3 个 SMB 目标产生 Incident：
  `inc-hyp-lateral-acceptance-1792428563-2`，
  stages 为 `["detection","lateral_movement"]`。
- 旧响应只读入口关闭：
  `/api/v1/response/candidates`、`/policy`、`/advisories` 返回 403；
  执行只保留 `/api/v1/response/actions`。
- Event v1 兼容入口关闭：
  `/api/v1/events`、`/api/v1/security-events`、`/api/v1/event-migration`
  返回 403；Dashboard 使用 `/api/v1/unified/events`，事件页使用
  `/api/v2/events`。
- Windows Agent 支持已砍掉：构建、下载、安装页、离线包不再包含 Windows；
  Windows 专用 Agent 文件已删除。
- 删除未接线的 `server/xdr/mock` 生成器。
- 证据：`/opt/lyflow/reports/G5/lateral-integration.txt`、
  `legacy-retirement.txt`。
