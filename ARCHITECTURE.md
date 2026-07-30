# 流影软件架构 README

> 当前状态：验收阶段稳定版  
> 默认入口：`https://<server>/`  
> 部署方式：Docker Compose / 离线镜像包一键安装

## 1. 架构目标

流影的设计目标不是做全量包取证系统，也不是单点 IDS。它的核心是把多个安全观测面转换成统一、可持久化、可关联的安全事件：

1. 资产与 Agent 状态可验收：在线/离线、最近上报、资产快照一致。
2. 流量威胁可解释：只展示有网络上下文的流量威胁，降噪识别类和无上下文事件。
3. 攻击链可信：Incident 必须来自 XDR 关联链，证据按阶段展示并带时间。
4. 规则可运营：规则库同步、更新、编译、热加载、回滚闭环。
5. 安装可交付：离线包包含运行镜像和脚本，目标机一键导入并启动。

## 2. 服务拓扑

```text
用户浏览器
  │ HTTPS 443
  ▼
ly-vis / Nginx
  │ /api, /ws 反向代理
  ▼
ly-server :8080 ───────────────┐
  │                             │
  ├─ PostgreSQL                 │
  │   ├─ agents / hosts          │
  │   ├─ threat_events           │
  │   └─ traffic_sessions        │
  │                             │
  ├─ Redis Streams              │
  │   ├─ telemetry:*             │
  │   ├─ flows:*                 │
  │   ├─ sessions:semantic       │
  │   └─ alerts:*                │
  │                             │
  ├─ ClickHouse                  │
  │                             │
  └─ ly-security-engine :8080 ◄──┘
        consumes telemetry:* and emits alerts:*

agent-center :8081
  └─ Agent gRPC 管理面

ly-local-mirror
  └─ 本机旁路镜像抓包，host network

外部主机 ly-agent
  ├─ HTTPS enroll/config/heartbeat
  ├─ traffic capture
  ├─ runtime/log audit/RASP
  └─ authenticated HTTPS telemetry delivery
```

## 3. 容器与端口

| 服务 | 镜像 | 默认端口 | 责任 |
|---|---|---:|---|
| `ly-vis` | `ly-flow/frontend:latest` | 443 | 深色控制台、HTTPS、自签证书、API/WS 代理 |
| `ly-server` | `ly-flow/server:latest` | 8080 | REST API、认证、持久化、XDR、规则中心、安装脚本 |
| `agent-center` | `ly-flow/server:latest` | 8081 | Agent gRPC 管理服务 |
| `ly-security-engine` | `ly-flow/security-engine:latest` | 内网 8080 | 消费 `telemetry:*`，输出 `alerts:*` |
| `ly-engine-lab` | `ly-flow/security-engines:latest` | 无公开端口 | 外部引擎状态输出与规则运行时 |
| `ly-local-mirror` | `ly-flow/agent:latest` | host network | 本机旁路流量镜像 |
| `postgres` | `postgres:16-alpine` | 5432 | 关系数据、威胁、会话、资产 |
| `redis` | `redis:7-alpine` | 6379 | 事件总线 |
| `clickhouse` | `clickhouse/clickhouse-server:24.8-alpine` | 8123 / 9000 | 分析存储 |

## 4. 数据流

### 4.1 Agent 注册与资产

1. 外部主机执行 `https://<server>/api/v1/agent/install.sh`。
2. 安装脚本使用 `curl -kfsSL` / `wget --no-check-certificate` 适配自签证书。
3. 管理员签发短时、一次性、绑定 Agent ID 的 enrollment token。
4. Agent 调用 `/api/v1/agent/enroll` 消费令牌，取得持久身份并写入 `agents`。
5. 心跳 `/api/v1/agent/heartbeat` 更新 Agent 状态。
6. 资产快照 `/api/v1/agent/snapshot` 更新 `hosts.metadata`。
7. 资产 API 返回前同步超时 Agent 和 Host 状态，避免 Agent 离线但资产仍显示实时。

### 4.2 流量会话与威胁

1. Agent 或本机镜像采集 TCP/UDP 包。
2. 原始与语义数据写入 `flows:raw`、`flows:semantic`、`sessions:semantic`、`telemetry:traffic`。
3. `ly-server` 消费 `sessions:semantic`，持久化到 `traffic_sessions`。
4. `ly-security-engine` 消费 `telemetry:traffic`，规则命中后写 `alerts:dpi`。
5. `ly-server` 消费 `alerts:*`，标准化并持久化到 `threat_events`。
6. Nmap 风格 SYN 端口扫描在 Agent 抓包层、限速前聚合，触发 `traffic.port_scan`。

### 4.3 XDR 与 Incident

1. DPI、Runtime、RASP、Log Audit 告警进入统一事件模型。
2. XDR 关联器按实体、阶段、证据和时间窗口生成攻击链。
3. Incident 只来自关联链，不由单条普通事件直接升级。
4. 前端按阶段展示证据和日期。

### 4.4 规则中心

1. 规则源同步到平台规则目录和数据库视图。
2. 规则编译生成 `rules/security-engine/active-bundle.json`。
3. `ly-server` 调用 `ly-security-engine /reload` 热加载。
4. 前端提供版本、预览、更新、回滚入口。

## 5. 持久化模型

| 表 / 存储 | 内容 |
|---|---|
| `agents` | Agent 注册、能力、状态、心跳、显示名 |
| `hosts` | 资产信息、性能快照、metadata、状态同步 |
| `traffic_sessions` | 语义流量会话，支持关键字和 Agent 查询 |
| `threat_events` | 统一威胁事件，按 category 聚合展示 |
| Redis Streams | 热路径事件总线与异步解耦 |
| ClickHouse | 版本化 UID 去重的事件分析存储；仅在校验和一致且完成读切换后成为搜索权威 |

ClickHouse 事件迁移的阶段权威、显式一致性和回滚约束见 [ClickHouse event-storage migration](docs/CLICKHOUSE_EVENT_MIGRATION.md)。

## 6. 部署包架构

离线安装包包含：

```text
lyflow-offline-install-*/
├── docker-compose.yml
├── images/lyflow-images.tar.gz
├── rules/
├── scripts/
│   ├── install-offline.sh
│   └── init-db.sql
├── server/sql/asset_tables.sql
└── README.md
```

安装脚本会：

1. 检查 root 权限。
2. 检查 Docker；缺失时尝试安装 Docker 与 compose plugin。
3. 复制包内容到 `/opt/ly-flow-platform` 或 `LYFLOW_INSTALL_DIR`。
4. 写入 `.env`。
5. `docker load` 导入镜像。
6. `docker compose up -d` 启动流影。

## 7. 当前边界

- 默认使用自签证书，生产环境可替换为正式证书。
- 离线包不内置 Docker 安装包；没有 Docker 的机器需要可访问 Docker 软件源，或提前安装 Docker。
- 容器化 `ly-agent` 和 legacy `ly-dpi-engine` 是 profile-gated QA/兼容项，默认运行面不依赖它们。
- 现场主机使用无容器的静态 Linux Agent；Linux 3.10/CentOS 7 运行时监控回退到 auditd，详见 `docs/zh/AGENT与LEGACY-DPI兼容边界.md`。
- 远端 Agent 的目标网络边界只开放平台 HTTPS；仍直接依赖 Redis 的兼容状态路径属于待清理技术债，不能作为远端部署前提。
- 流量威胁默认保留有网络上下文的安全告警，不展示纯识别类噪声。
