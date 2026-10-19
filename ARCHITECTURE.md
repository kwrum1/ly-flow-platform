# 流影 LyFlow 软件架构

> 更新日期：2026-08-02
> 当前形态：单机一体化 XDR 安全设备
> 正式部署：Docker Compose 服务端 + 无容器主机 Agent

## 0. 2026-10 v2 实现状态

v2 主链已落地：Event v2、ClickHouse/PostgreSQL 存储、ATT&CK/Incident、ly_vis 风格 UI、Agent supervisor、内容源许可门、Suricata/ET Open、ly_probe 产品化与规则热加载、Capture doctor、性能压测基线和 lean/full-private Compose profiles。

当前默认部署使用 `deploy/compose/lean.yml`：

- core：`ly-vis`、`ly-server`、`agent-center`、`ly-security-engine`、PostgreSQL、ClickHouse、Redis。
- capture：`lyprobe-sensor`、`suricata-sensor`、`lyflow-rulecompiler`、`lyflow-capturedoctor`。
- `full-private.yml` 是私有 Elkeid overlay，不进入公开产物。

与早期文档的差异：

- 默认不再使用 `ly-local-mirror` 作为唯一采集入口；ly_probe 是主探针，Suricata 是签名协处理。
- 目标 Linux 为现代发行版（Ubuntu 22.04+/Debian 12+/RHEL 9+），不再要求 CentOS 7 / 3.10。
- 事件/会话查询以 ClickHouse 为主，PostgreSQL 保存配置、账号、资产、Incident 和处置；不恢复 MariaDB 查询层。
- 公开 lean 固定 Redis 7.2（BSD）；`full-private` 才引入 Elkeid 私有组件和 MongoDB（SSPL，非公开分发）。

历史拓扑章节保留用于兼容旧部署；新部署请以 `deploy/compose/README.md` 和 `docs/dev/T4.7-REPORT.md` 为准。

## 1. 产品边界

流影把网络、主机、应用和安全规则产生的事件统一为可查询、可关联、可处置的安全数据。它不是全包取证平台，也不承诺多节点高可用；当前重点是单机旁路流量审计、主机 Agent 审计、XDR/ATT&CK 关联和长期会话溯源。

已实现主链路：采集 -> Redis 事件总线 -> 统一检测 -> PostgreSQL/ClickHouse 持久化 -> XDR 关联 -> Incident -> Web 处置。

## 2. 正式拓扑

```text
浏览器
  │ HTTP 80 自动跳转 HTTPS 443
  ▼
ly-vis / Nginx
  │ /api /ws
  ▼
ly-server :8080 ───────── PostgreSQL（账号、资产、规则、告警、处置）
  │        │
  │        ├───────────── ClickHouse（长期会话、分析事件、溯源）
  │        │
  │        └───────────── Redis Streams（实时事件总线、短期缓冲）
  │
  ├── agent-center :8081（Agent 注册、配置、任务）
  └── ly-security-engine（统一规则检测与告警）

镜像口 ──> ly-local-mirror(PF_RING) ──> ly-suricata-sensor ──> 流量遥测/告警

外部主机 ly-agent（无容器）
  ├── HTTPS 注册、心跳、配置与遥测
  ├── AF_PACKET 小流量采集
  ├── Runtime / auditd
  ├── 日志审计
  ├── YARA 文件扫描
  └── Python RASP
```

## 3. 默认容器

| 容器 | 责任 | 对外端口 |
|---|---|---:|
| `ly-vis` | HTTP 跳转、HTTPS 控制台、API/WS 代理 | 80、443 |
| `ly-server` | 认证、REST API、XDR、Incident、规则生命周期 | 内网 8080 |
| `agent-center` | Agent 注册、在线状态、配置和任务 | 内网 8081 |
| `ly-local-mirror` | 本机 PF_RING 镜像采集 | host network |
| `ly-suricata-sensor` | Suricata IDS 与 EVE 输出 | 无 |
| `ly-security-engine` | 多源遥测检测和统一告警 | 内网 8080 |
| `postgres` | 事务数据与配置 | 内网 5432 |
| `clickhouse` | 长期会话与分析数据 | 内网 8123/9000 |
| `redis` | 实时流与短期缓冲 | 内网 6379 |

`ly-engine-lab` 已退出默认生产栈。容器 Agent 和 legacy DPI 只通过 QA/兼容 profile 启用。

## 4. 数据职责

### PostgreSQL

保存账号、角色、首次改密状态、Agent、资产、规则版本、告警、攻击链、Incident、处置和审计记录。需要事务一致性和状态变更的数据以 PostgreSQL 为主。

### ClickHouse

保存高容量、追加写的会话和规范化安全事件，用于长期留存、查询和溯源。事件存储采用 UID 去重和分阶段迁移；切换规则见 [ClickHouse 事件迁移](docs/CLICKHOUSE_EVENT_MIGRATION.md)。

### Redis

承担 `telemetry:*`、`alerts:*`、会话流和控制健康流的实时解耦及短期缓冲。Redis 不是正式数据仓库，服务重启或 Redis 清理不能造成 PostgreSQL/ClickHouse 正式数据丢失。

## 5. 检测数据流

### 流量

1. 管理员在控制中心选择镜像接口；管理访问口从候选列表中排除，镜像流量标识默认启用。
2. AMD64 服务端由 PF_RING 本机探针采集，Suricata 生成 EVE 网络事件。
3. 会话写入 ClickHouse，流量遥测进入统一安全引擎。
4. ET Open、OISF、Snort、Stamus、PT 等兼容规则经编译后参与检测；不兼容项隔离并记录。
5. 流量告警保留源/目的 IP、端口、协议、原始引用和规则来源。

ARM64 服务端包可部署完整控制与分析栈；PF_RING 镜像路径以 AMD64 为主要生产目标，ARM64 本机采集使用当前可构建的兼容镜像实现，仍需要具体 ARM 网卡和驱动现场认证。

### 主机与应用

Agent 使用一次性注册令牌取得持久身份，通过控制中心下发日志、Runtime、YARA、RASP 和流量开关。Linux 3.10 不具备现代 eBPF 条件时回退到 auditd；AF_PACKET、日志、资产快照和本地加密 spool 继续工作。

Python RASP 已具备 monitor/protect 策略、签名配置、健康状态和事件上报。Java RASP 仍为实验能力；未完成真实业务框架兼容矩阵前，不扩大阻断承诺。

### XDR 与 ATT&CK

统一事件包含来源、实体、时间、规则、证据引用和 ATT&CK 信息。关联器按共享实体、时间窗口和阶段连续性形成候选链；只有满足关联条件的链升级为 Incident，单条普通事件留在对应检测面。处置支持研判、处理中、解决和审计记录，当前不自动封禁网络或隔离主机。

## 6. 规则生命周期

规则中心负责版本发现、固定来源下载、摘要校验、格式转换、编译预览、签名、激活、热加载和回滚。流量规则和安全引擎规则分别适配其运行时；上游最新不等于直接可运行，编译失败的单条规则进入隔离区，不阻塞可用规则生效。

正式服务端包在每次 GitHub 构建时重新获取五个公开规则源，不使用跨运行缓存。运行中在线更新仍通过规则中心执行并保留版本与审计记录。

## 7. Agent 兼容架构

- Linux AMD64/ARM64：静态 Go 二进制，目标 Linux 3.10/CentOS 7 及以上。
- Windows AMD64：单文件 Agent；Npcap 单独下载和安装。
- Linux 抓包：AF_PACKET/TPACKET，适合 Agent 小流量采集，可在控制中心关闭。
- 本机镜像：AMD64 生产路径使用 PF_RING，承担高流量旁路镜像。
- 容器 Agent：仅用于 QA，不是现场安装方式。
- legacy DPI：仅用于旧 `flows:raw` 迁移对账，不与统一安全引擎长期并行。

## 8. 正式部署包

`lyflow-server-amd64.tar.gz` 和 `lyflow-server-arm64.tar.gz` 内部结构一致：

```text
ly-flow-platform/
├── docker-compose.yml
├── images/
│   ├── architecture
│   ├── image-pins.txt
│   └── lyflow-images.tar.gz
├── rules/
├── scripts/
│   ├── install-docker-bundle.sh
│   └── init-db.sql
└── server/sql/asset_tables.sql
```

安装器要求 root、Docker Engine 和 Compose Plugin，校验架构后安装到 `/opt/ly-flow-platform`，生成内部凭据并启动正式栈。首次登录固定为 `admin/password`，强制修改密码；80 自动跳转 443。

## 9. 当前限制

1. 当前是单机部署，不包含多节点 HA、异地容灾或集中多租户管理。
2. CentOS 7/Linux 3.10、ARM64 服务端和 ARM64 Agent 已具备构建能力，但仍需对应真实硬件长期运行认证。
3. 全量会话指完整语义会话元数据长期留存，不等于保存所有原始 PCAP 字节。
4. Wazuh、YARA、Suricata 和 RASP 适配器可消费真实引擎输出，但规则覆盖与检测质量仍需持续 corpus、误报率和召回率评估。
5. 自动响应当前以人工处置建议为主；自动隔离和封禁需要审批、回滚及失联保护后才能进入生产。
