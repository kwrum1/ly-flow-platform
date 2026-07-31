# 流影 LyFlow XDR Security Console

流影是面向中小型安全运营场景的一体化 XDR 平台。系统把资产、Agent、旁路流量、运行时、RASP、日志审计、规则中心和攻击链处置整合到同一个控制台，默认通过 HTTPS 443 对外服务，并支持离线镜像包一键安装。

## 核心能力

- **资产与 Agent 运维**：一次性令牌注册、心跳、能力开关、在线/离线同步、资产性能快照。
- **流量可观测**：本机旁路镜像与外部终端探针分离展示，DNS/HTTP/TLS/TCP 会话持久化查询。
- **流量威胁检测**：规则引擎 + Agent 侧流量特征检测，包含 Nmap 风格端口扫描识别与误报降噪。
- **运行威胁 / 应用威胁**：运行时事件、日志审计和 RASP 事件统一进入安全引擎。
- **XDR 攻击链**：Incident 只来自关联链，阶段下挂对应证据和时间，不把单条普通事件升级为攻击链。
- **规则中心**：规则源同步、编译预览、版本管理、热加载、回滚。
- **离线验收安装包**：打包应用和数据服务镜像，安装脚本校验来源、导入镜像并启动服务。

## 快速安装

离线包生成后：

```bash
tar -xzf lyflow-offline-install-*.tar.gz
cd lyflow-offline-install-*
sudo bash scripts/install-offline.sh \
  --trust-root /path/outside/package/release-root.pem \
  --generate-admin-password
```

安装完成后访问：

```text
https://<服务器IP>/
```

管理员账号为 `admin`。安装器生成初始密码并写入权限为 `0600` 的
`initial-admin-credentials`，首次登录要求修改密码。

## 开发与验收构建

```bash
# 构建离线验收包
scripts/build-offline-release.sh

# 使用本地镜像执行隔离容器烟雾测试
scripts/container-smoke.sh

# 后端测试
cd server && GOWORK=off go test ./...

# Agent 测试
cd agent && GOWORK=off go test ./cmd

# 前端构建
cd frontend && npm run build
```

生成的离线包位于 `release/lyflow-offline-install-*.tar.gz`。

## 文档

- [文档索引与维护规则](docs/README.md)
- [软件架构](ARCHITECTURE.md)
- [当前功能盘点与能力边界](docs/zh/当前功能盘点与能力边界.md)
- [后续工作计划](docs/zh/后续工作计划.md)
- [API 文档](docs/API.md)
- [白皮书](docs/WHITEPAPER.md)
- [发布来源、签名与可复现性](docs/RELEASE_PROVENANCE.md)

## 默认运行拓扑

默认 `docker compose up -d` 启动：

- `ly-vis`：HTTPS 前端，443。
- `ly-server`：核心 API，8080。
- `agent-center`：Agent gRPC 管理，8081。
- `ly-security-engine`：统一检测引擎。
- `ly-engine-lab`：外部引擎状态与规则运行时。
- `ly-local-mirror`：本机旁路镜像抓包。
- `postgres`、`redis`、`clickhouse`：持久化、事件总线与分析存储。

容器化 QA Agent 与 legacy DPI 通过 Compose profile 启用，不属于默认生产启动面。
政企现场采集端使用无容器、静态链接的 Linux Agent；当前生产兼容目标为
Linux 3.10/CentOS 7 及以上内核。

## 当前交付基线

- 默认生产编排为 `docker-compose.yml`；容器化 Agent、legacy DPI 和实验性组件不属于默认生产组件。
- ClickHouse 用于长期保存全量会话和溯源数据，PostgreSQL 用于配置、资产、规则和生命周期数据。
- 本机旁路镜像抓包使用 PF_RING；Agent 侧使用 Linux AF_PACKET，兼容 CentOS 7 / Linux 3.10。
- XDR Incident 只由关联攻击链产生，普通单点检测事件保留在检测面。
- 规则源支持版本发现、固定版本同步、编译校验和热生效；不支持安全编译的单条规则会被隔离，不阻塞整包更新。
- 首次登录账号为 `admin`，默认密码为 `password`，首次登录必须修改密码。

## 工作流

Gitea Actions 工作流位于 `.gitea/workflows/ci.yml`，不执行 Docker 构建；每次推送执行后端、Agent、前端测试和前端构建。推送到 `main` 时额外生成 Linux 服务端、Linux x86_64/ARM64 Agent、Windows x86_64 Agent、前端静态包及安装脚本，并作为 Gitea 构建产物提供下载。发布前仍需在目标主机执行容器级验收，CI 不代替真实网卡、PF_RING、ClickHouse 和 Agent 场景验证。
