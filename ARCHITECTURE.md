# 流影安全态势感知平台 - 技术架构文档

> 版本: v2.0.1
> 更新日期: 2026-05-08
> 状态: 已确定

---

## 一、产品定位

一站式开源安全产品：
- DPI 流量检测（Go + Suricata 规则，Server端）
- 自定义域名审计（挖矿/涉诈/自定义标签）
- RASP 检测（**Java/Python** 优先支持）
- 日志检测（Wazuh + Elkeid 规则）
- EDR 主动防御（ly-agent + eBPF）
- Elkeid 风格资产管理可视化
- 漏洞扫描（Xray + YARA）
- SOAR 处置响应
- AI 智能分析（DeepSeek 优先）

部署：单机 Docker Compose

### 1.1 部署模式

| 模式 | 说明 | 组件 |
|------|------|------|
| 旁路分析 | TAP/SPAN 镜像流量 | ly-dpi-engine (Server端消费Redis) |
| Agent 主动监控 | 服务器安装 Agent | ly-probe + ly-agent |
| 混合模式 | 两者结合 | 全部组件 |

---

## 二、系统架构图

### 2.1 数据流架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Agent 节点 (Linux)                                │
│                                                                             │
│  ┌──────────────┐     ┌───────────┐     ┌──────────────┐                   │
│  │ ly-probe     │────▶│flows:raw  │────▶│ly-dpi-engine │                   │
│  │ (Go+PF_RING) │     │(Redis)    │     │(Server端)    │                   │
│  │ + nDPI       │     └───────────┘     └──────┬───────┘                   │
│  │ + Suricata   │                              │                           │
│  └──────────────┘                              ▼                           │
│                                                ┌──────────────┐             │
│  ┌──────────────┐     ┌───────────┐           │alerts:dpi    │             │
│  │ ly-agent     │────▶│endpoint   │           │(Redis)       │             │
│  │ (Go+eBPF)    │     │events     │           └──────┬───────┘             │
│  └──────────────┘     └───────────┘                  │                     │
└─────────────────────────────────────────────────────│─────────────────────┘
                                                      │
┌─────────────────────────────────────────────────────│─────────────────────┐
│                           Server 节点 (Docker Compose)│                     │
│                                                      ▼                     │
│  ┌──────────────┐     ┌───────────┐     ┌──────────────────────────────┐ │
│  │log-analyzer  │────▶│alerts:log │     │  ly-server (:8080)            │ │
│  │(日志分析)    │     │(Redis)    │     │  - REST API                  │ │
│  └──────────────┘     └───────────┘     │  - WebSocket 实时推送         │ │
│                                         │  - 消费 alerts:*             │ │
│  ┌──────────────┐                       │  - PostgreSQL 存储            │ │
│  │AgentCenter   │                       └──────────────┬───────────────┘ │
│  │(:8081 gRPC)  │                       ┌──────────────┴───────────────┐ │
│  └──────────────┘                       │  PostgreSQL + Redis          │ │
│                                         │  - events表                  │ │
│                                         │  - assets表                   │ │
│                                         │  - alerts表                   │ │
│                                         └───────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Vue3 前端 (:3000)                                                   │ │
│  │  Element Plus + AntV G6                                             │ │
│  │  态势总览 │ 资产管理 │ 流量事件 │ 日志分析 │ 威胁情报 │ AI分析       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Manager 节点（Docker Compose）

```
┌─────────────────────────────────────────────────────────────────┐
│  Vue3 前端（Element Plus + AntV G6）                               │
│  态势总览 │ 资产管理 │ 流量事件 │ 日志分析 │ 威胁情报 │ 漏洞管理  │
│  基线检查 │ RASP防护 │ 行为溯源 │ 处置响应 │ 端上监控 │ 报告中心  │
│  AI 分析（DeepSeek）│ Webhook 推送                                   │
├─────────────────────────────────────────────────────────────────┤
│  ly-server（Go HTTP API）：8080                                   │
│  Auth │ Events │ Assets │ Alerts │ Config │ Reports │ Webhook   │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────┬───────────┬───────────┬────────────┐            │
│  │AgentCenter│  ti-sync  │RuleManager│ly-scanner │            │
│  │  :8081   │ 情报同步  │ 规则管理  │ Xray/YARA  │            │
│  │   gRPC   │ MISP/OTX  │Suricata   │ 漏洞扫描   │            │
│  └─────┬─────┘ └────┬────┘ └────┬────┘ └──────┬─────┘            │
│        └───────────┴──────────┴──────────┴────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│  PostgreSQL + Redis（统一存储）                                    │
│  events │ log_events │ endpoint_events │ assets │ vulnerabilities  │
│  ti_ips │ ti_domains │ baselines │ configs │ tasks │ reports       │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Agent 节点（安装包）

```
┌─────────────────────────────────────────────────────────────────┐
│  ly-probe（Go + PF_RING）                                       │
│  - DPI 抓包 + nDPI 协议解析                                      │
│  - Suricata 规则匹配（ET Open + Wazuh + 自定义）                  │
│  - 自定义域名审计（挖矿/涉诈/自定义标签）                         │
│  - HTTP/HTTPS TLS 解析（SNI/JA3/证书指纹）                       │
│  - DNS Tunnel 检测（熵值分析）                                    │
│  - Redis Stream 上报到 flows:raw                                 │
├─────────────────────────────────────────────────────────────────┤
│  ly-agent（Go + eBPF）                                          │
│  ├─ Driver Plugin（eBPF）                                       │
│  │   ├─ 进程监控（execve/fork/exit）                            │
│  │   ├─ 文件监控（open/read/write）                            │
│  │   └─ 网络监控（socket/connect/accept）                       │
│  ├─ Collector Plugin（Go）                                       │
│  │   ├─ 系统日志（journald/syslog）                            │
│  │   ├─ 进程列表                                               │
│  │   └─ 端口/连接列表                                          │
│  ├─ RASP Plugin（Java Agent + Go）                              │
│  │   ├─ Java（javaagent）                                      │
│  │   └─ Python（sys.settrace）                                  │
│  ├─ Journal Watcher（systemd journal）                          │
│  ├─ Baseline Plugin（CIS 基线）                                │
│  └─ Log Monitor（Wazuh Decoders）                              │
├─────────────────────────────────────────────────────────────────┤
│  安装：./install.sh --manager=<addr> --plugins=all               │
│  (仅支持 Linux，Windows暂不支持)                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 三、核心模块设计

### 3.1 ly-probe（流量采集，Agent端）

```
网卡 --> PF_RING --> nDPI 解析 --> Flow聚合 --> Redis Stream (flows:raw)

ly-probe 功能：
├─ PF_RING 抓包（特权模式）
│   └─ pcap fallback（非特权模式）
├─ nDPI 协议识别
│   ├─ DNS 解析
│   ├─ HTTP Host 提取
│   ├─ TLS SNI / JA3 提取
│   └─ 其他应用协议
├─ Suricata 规则匹配（本地）
├─ Domain Reputation（本地）
│   ├─ 挖矿域名库
│   ├─ 涉诈域名库
│   └─ 自定义标签
└─ Redis Stream 上报
    └─ XADD flows:raw
```

### 3.2 ly-dpi-engine（Server端，DPI分析）

```
Redis Stream (flows:raw) --> XREADGROUP --> Domain Auditor --> Suricata Rules --> Redis (alerts:dpi)

ly-dpi-engine 功能：
├─ Redis Consumer（XREADGROUP consumer group）
│   └─ XACK 确认处理
├─ Domain Auditor
│   ├─ 挖矿域名库匹配
│   ├─ 涉诈域名库匹配
│   ├─ DGA 检测（熵值分析）
│   ├─ DNS Tunnel 检测（子域名数量+熵值）
│   └─ 可疑 TLD 检测
├─ Suricata 规则引擎（Server端）
│   ├─ content 匹配
│   ├─ pcre 正则匹配
│   ├─ dns.query 匹配
│   ├─ http.host 匹配
│   └─ tls.sni 匹配
└─ 输出模块
    └─ XADD alerts:dpi
```

### 3.3 日志分析引擎

```
Sources: syslog/journald/File/Agent

Decoder Layer：
├─ sshd decoder
├─ nginx decoder
├─ apache decoder
├─ mysql decoder
├─ systemd decoder
├─ kernel decoder
└─ docker decoder

Rule Engine：
├─ Wazuh Rules（200+）
├─ Elkeid Rules（行为规则）
└─ 自定义规则

Output：JSON/CSV --> 统一 Event --> alerts:log --> ly-server --> PostgreSQL
```

### 3.4 RASP 支持矩阵

| 语言 | 注入方式 | Hook 点 |
|------|---------|---------|
| Java | javaagent | SQL注入/命令注入/文件/反序列化 |
| Python | sys.settrace | SQL注入/命令注入/文件/反序列化 |

导出：OTEL --> Redis --> Log Analyzer --> PostgreSQL

### 3.5 AI 智能分析

```
┌─────────────────────────────────┐
│ AI 分析模块                       │
├─────────────────────────────────┤
│ 告警聚合 │ 误报识别 │ 处置建议  │
│ 时间窗口  │ DeepSeek   │ DeepSeek   │
│ SimHash去重│            │            │
├─────────────────────────────────┤
│ 攻击链构建（ATT&CK 阶段映射）    │
│ 侦察->武器化->投递->利用->持久化  │
│ ->通信->目标达成                   │
├─────────────────────────────────┤
│ 安全日报 + Webhook 推送           │
│ 钉钉/飞书/企业微信/Email/自定义   │
├─────────────────────────────────┤
│ LLM 优先级：1.DeepSeek 2.Claude 3.GPT-4│
└─────────────────────────────────┘
```

---

## 四、项目结构

```
C:\root\ly\platform\
├── ARCHITECTURE.md          # 本文档
├── TODO.md                  # 开发进度追踪
├── docker-compose.yml        # 统一部署文件
├── Dockerfile.*             # 各组件镜像
│
├── pkg/                     # 共享模型
│   └── model/
│       ├── flow.go          # FlowData 消息格式
│       ├── alert.go         # Alert 结构
│       └── event.go         # Event 结构
│
├── probe/                   # ly-probe（Agent端流量采集）
│   ├── cmd/
│   │   ├── main.go          # 主入口
│   │   └── mock.go           # Mock 测试
│   ├── core/
│   │   ├── capture/         # PF_RING 抓包
│   │   ├── processor/       # nDPI 解析
│   │   ├── domain/          # 域名审计（本地）
│   │   ├── rules/           # Suricata 规则（本地）
│   │   └── redis/           # Redis 生产者
│   ├── config/
│   └── go.mod
│
├── dpi-engine/              # ly-dpi-engine（Server端）
│   ├── cmd/
│   │   └── main.go
│   ├── core/
│   │   ├── engine/          # 引擎主逻辑
│   │   ├── redis/           # Redis 消费者
│   │   ├── domain/          # 域名审计
│   │   └── rules/           # Suricata 规则引擎
│   ├── config/
│   └── go.mod
│
├── server/                  # ly-server（后端API）
│   ├── cmd/
│   │   └── main.go
│   ├── api/
│   │   ├── handlers/        # REST API
│   │   └── websocket/      # WebSocket
│   ├── consumer/            # Redis 消费者（alerts:*）
│   ├── models/              # DB 模型
│   ├── config/
│   └── go.mod
│
├── agent/                   # ly-agent（端点安全）
│   ├── cmd/
│   │   └── main.go
│   ├── ebpf/                # eBPF 监控
│   ├── rasp/                # RASP（Java/Python）
│   ├── collector/           # 日志采集
│   ├── config/
│   └── go.mod
│
├── frontend/               # Vue3 前端
│   ├── src/
│   │   ├── views/           # 页面
│   │   ├── components/      # 组件
│   │   ├── api/             # API 调用
│   │   └── router/
│   └── package.json
│
├── rules/                   # 规则库
│   ├── suricata/
│   │   └── et-open.rules
│   ├── domain/
│   │   ├── mining.txt
│   │   ├── fraud.txt
│   │   └── custom.txt
│   └── wazuh/
│
└── scripts/
    ├── init-db.sql          # PostgreSQL 初始化
    └── install.sh           # Agent 安装脚本
```

---

## 五、AgentCenter 策略配置

```yaml
# 全局开关
agent:
  enabled: true

# 流量检测模块（ly-probe）
traffic_analysis:
  enabled: true
  config:
    capture_interface: eth0
    bpf_filter: "tcp or udp"
    suricata_rules: true
    custom_domains:
      - /etc/ly-agent/domain-lists/mining.txt
      - /etc/ly-agent/domain-lists/fraud.txt
      - /etc/ly-agent/domain-lists/custom.txt
    dpi_threshold: 1000
    redis_stream: "flows:raw"
    redis_addr: "10.1.18.100:6379"

# 日志审计模块
log_audit:
  enabled: true
  config:
    sources:
      - type: syslog
        port: 514
        protocol: udp
      - type: journald
        enabled: true
    wazuh_rules: true
    elkeid_rules: true

# 端点检测模块（ly-agent）
endpoint_detection:
  enabled: true
  config:
    driver:
      enabled: true
      events:
        - process_create
        - file_create
        - network_connect
        - container_create
    collector:
      enabled: true
      interval: 60s
    baseline:
      enabled: true

# RASP 防护模块
rasp:
  enabled: false
  config:
    java:
      enabled: false
      agent_jar: /opt/ly-agent/plugins/rasp/java/ly-rasp.jar
    python:
      enabled: false

# 漏洞扫描模块
vulnerability_scan:
  enabled: false
  config:
    xray:
      enabled: false
    yara:
      enabled: false
      rules_path: /etc/ly-agent/yara
    schedule: "0 2 * * *"
```

---

## 六、数据库 Schema

### 6.1 事件表

```sql
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    source VARCHAR(64),
    severity VARCHAR(16),
    src_ip INET,
    dst_ip INET,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(16),
    domain VARCHAR(256),
    tags TEXT[],
    mitre_tactic VARCHAR(32),
    mitre_technique VARCHAR(32),
    raw_data JSONB,
    metadata JSONB,
    status VARCHAR(16) DEFAULT 'new',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_tags ON events USING GIN(tags);
```

### 6.2 资产表

```sql
CREATE TABLE assets (
    id BIGSERIAL PRIMARY KEY,
    hostname VARCHAR(256) UNIQUE,
    ip INET,
    os VARCHAR(128),
    agent_id UUID,
    tags TEXT[],
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_ip ON assets(ip);
```

### 6.3 漏洞表

```sql
CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT REFERENCES assets(id),
    cve VARCHAR(32),
    severity VARCHAR(16),
    scanner VARCHAR(32),
    title VARCHAR(256),
    description TEXT,
    remediation TEXT,
    status VARCHAR(16) DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
```

### 6.4 情报库

```sql
CREATE TABLE ti_domains (
    domain VARCHAR(256) PRIMARY KEY,
    category VARCHAR(64),
    source VARCHAR(32),
    tags TEXT[],
    confidence FLOAT,
    last_seen TIMESTAMPTZ
);

CREATE TABLE ti_ips (
    ip INET PRIMARY KEY,
    category VARCHAR(64),
    source VARCHAR(32),
    tags TEXT[],
    confidence FLOAT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ
);

CREATE TABLE custom_tags (
    id SERIAL PRIMARY KEY,
    tag VARCHAR(64) UNIQUE,
    category VARCHAR(64),
    description TEXT,
    auto_block BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 6.5 Agent 表

```sql
CREATE TABLE agents (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL,
    hostname VARCHAR(256),
    ip INET,
    os VARCHAR(128),
    agent_version VARCHAR(32),
    status VARCHAR(16) DEFAULT 'offline',
    last_heartbeat TIMESTAMPTZ,
    config JSONB,
    tags TEXT[],
    enrolled_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE agent_tasks (
    id BIGSERIAL PRIMARY KEY,
    agent_uuid UUID REFERENCES agents(uuid),
    task_type VARCHAR(32),
    task_params JSONB,
    status VARCHAR(16) DEFAULT 'pending',
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_tasks_agent ON agent_tasks(agent_uuid);
```

### 6.6 报告表

```sql
CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,
    report_type VARCHAR(32),
    title VARCHAR(256),
    content JSONB,
    summary TEXT,
    stats JSONB,
    webhook_urls TEXT[],
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 七、Redis 数据流

```
flows:raw              --> 探针上报的原始流量（XADD by ly-probe）
                       --> XREADGROUP by ly-dpi-engine

alerts:dpi             --> DPI检测告警（XADD by ly-dpi-engine）
                       --> XREADGROUP by ly-server

alerts:log             --> 日志分析告警（XADD by log-analyzer）
                       --> XREADGROUP by ly-server

alerts:endpoint        --> 端点安全告警（XADD by ly-agent）
                       --> XREADGROUP by ly-server

ti:domains:cache       --> 域名情报缓存（HASH，TTL 1h）
ti:ips:cache           --> IP情报缓存（HASH，TTL 1h）
agent:tasks            --> Agent任务队列
agent:heartbeat        --> Agent心跳（PUB/SUB）
```

---

## 八、API 端点

### 8.1 ly-server（:8080）

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | /api/v1/auth/login | 用户登录 |
| GET | /api/v1/events | 事件列表 |
| POST | /api/v1/events/search | 事件搜索 |
| GET | /api/v1/assets | 资产列表 |
| GET | /api/v1/assets/:id | 资产详情 |
| GET | /api/v1/vulnerabilities | 漏洞列表 |
| GET | /api/v1/ti/domains | 域名情报 |
| POST | /api/v1/ti/domains/import | 导入自定义域名库 |
| GET | /api/v1/reports/daily | 每日报告 |
| POST | /api/v1/webhook/test | 测试 Webhook |

### 8.2 AgentCenter（:8081）

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | /api/v1/agents/enroll | Agent 注册 |
| POST | /api/v1/agents/heartbeat | Agent 心跳 |
| GET | /api/v1/agents | Agent 列表 |
| GET | /api/v1/agents/:uuid/config | 获取配置 |
| PUT | /api/v1/agents/:uuid/config | 下发配置 |
| DELETE | /api/v1/agents/:uuid | 删除 Agent |
| POST | /api/v1/tasks | 创建任务 |
| GET | /api/v1/tasks/pending/:uuid | 待执行任务 |
| PUT | /api/v1/tasks/result | 上报任务结果 |

### 8.3 RuleManager

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | /api/v1/rules/suricata | Suricata 规则列表 |
| POST | /api/v1/rules/suricata | 添加 Suricata 规则 |
| GET | /api/v1/rules/wazuh | Wazuh 规则列表 |
| POST | /api/v1/rules/custom | 添加自定义规则 |
| POST | /api/v1/rules/sync | 同步规则 |

---

## 九、开发计划

### Phase 1：核心引擎（Week 1-4）

| 任务 | 内容 | 周期 | 优先级 |
|------|------|------|--------|
| 1.1 | 项目结构初始化 + Docker Compose | 1 周 | 🔴 |
| 1.2 | 共享模型定义（pkg/model） | 0.5 周 | 🔴 |
| 1.3 | PostgreSQL Schema | 0.5 周 | 🔴 |
| 1.4 | ly-probe（PF_RING + nDPI + Redis） | 2 周 | 🔴 |
| 1.5 | ly-dpi-engine（Redis消费 + Domain审计） | 2 周 | 🔴 |
| 1.6 | ly-server（alerts消费 + API） | 2 周 | 🔴 |

### Phase 2：Agent 系统（Week 3-6）

| 任务 | 内容 | 周期 | 优先级 |
|------|------|------|--------|
| 2.1 | AgentCenter（gRPC + 策略下发） | 2 周 | 🟡 |
| 2.2 | ly-agent eBPF（进程/文件/网络监控） | 2 周 | 🔴 |
| 2.3 | RASP Java Agent | 1 周 | 🔴 |
| 2.4 | RASP Python Hook | 1 周 | 🔴 |
| 2.5 | Collector + Journal | 1 周 | 🟡 |
| 2.6 | 一键安装脚本（Bash + PowerShell for Linux） | 1 周 | 🟡 |

### Phase 3：前端（Week 3-6）

| 任务 | 内容 | 周期 | 优先级 |
|------|------|------|--------|
| 3.1 | Vue3项目 + 登录 + JWT | 1 周 | 🟡 |
| 3.2 | 态势总览仪表盘（ECharts） | 1 周 | 🟡 |
| 3.3 | 资产管理页面（Elkeid 风格 G6 拓扑） | 2 周 | 🟡 |
| 3.4 | 流量/日志事件页面 | 1 周 | 🟡 |
| 3.5 | 威胁情报 + 漏洞管理 + 报告中心 | 1 周 | 🟢 |

### Phase 4：AI + SOAR（Week 7-8）

| 任务 | 内容 | 周期 | 优先级 |
|------|------|------|--------|
| 4.1 | 告警聚合 + SimHash 去重 | 1 周 | 🟢 |
| 4.2 | 攻击链构建（ATT&CK 阶段映射） | 1 周 | 🟢 |
| 4.3 | DeepSeek API 集成（误报识别/处置建议） | 1 周 | 🟢 |
| 4.4 | Webhook 推送（钉钉/飞书/企业微信） | 1 周 | 🟢 |

### Phase 5：集成测试（Week 9-10）

| 任务 | 内容 | 周期 |
|------|------|------|
| 5.1 | 端到端数据流测试 | 1 周 |
| 5.2 | 性能压测 | 1 周 |
| 5.3 | 跨平台安装测试（Linux） | 1 周 |
| 5.4 | 故障恢复测试 | 1 周 |

---

## 十、技术栈

| 组件 | 语言/框架 | 说明 |
|------|-----------|------|
| ly-probe | Go | PF_RING + nDPI + Suricata（Agent端） |
| ly-dpi-engine | Go | Redis Consumer + Domain Auditor（Server端） |
| 日志分析 | Go | Wazuh + Elkeid 规则 |
| AgentCenter | Go | gRPC + Protobuf |
| ly-agent | Go + eBPF + Java Agent | 多插件架构 |
| RASP | Java Agent + Go | Java/Python 支持 |
| 前端 | Vue3 + Element Plus + AntV G6 | 单模式 |
| 数据库 | PostgreSQL + Redis | 统一存储 |
| AI | DeepSeek API | 告警降噪 + 处置建议 |

---

## 十一、安装命令

### Manager 节点

```bash
curl -sL http://<server>:8080/api/v1/install/docker-compose.yml -o docker-compose.yml
docker-compose up -d
```

### Agent 节点（仅 Linux）

```bash
curl -sL http://<server>:8081/api/v1/agent/install.sh | bash -s -- --manager=http://<server>:8081

# 指定插件
./install.sh --manager=http://<server>:8081 --plugins=all
```

---

## 十二、FlowData 消息格式

### flows:raw 消息结构

```json
{
  "id": "uuid-string",
  "timestamp": 1715123456,
  "sensor_id": "agent-uuid",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "app_protocol": "HTTPS",
  "dns_query": "",
  "http_host": "malicious-domain.com",
  "tls_sni": "malicious-domain.com",
  "ja3": "d4e4f0a2...",
  "bytes_in": 1024,
  "bytes_out": 2048,
  "packets": 10,
  "duration_ms": 500,
  "direction": "egress"
}
```

### alerts:dpi 消息结构

```json
{
  "id": 12345,
  "timestamp": "2026-05-08T10:30:00Z",
  "type": "dpi",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "signature": "DomainAudit.mining",
  "category": "mining",
  "severity": 1,
  "score": 100,
  "status": "new",
  "sensor_id": "agent-uuid",
  "domain": "cryptomining-pool.com"
}
```

---

## 文档更新记录

| 版本 | 日期 | 修改内容 |
|------|------|---------|
| v1.0.0 | 2026-05-08 | 初始版本 |
| v2.0.0 | 2026-05-08 | 架构调整：PF_RING移至ly-probe，ly-dpi-engine改为Server端Redis消费；RASP仅支持Java/Python；Windows Agent暂不支持 |
| v2.0.1 | 2026-05-09 | 系统集成验证通过：ly-server、ly-vis、PostgreSQL、Redis 全部运行正常；API 端点 /api/v1/health、/api/v1/alerts、/api/v1/assets 均返回正确响应；前端静态资源正常加载 |
