# 流影 LyFlow XDR Security Console

流影是面向中小型安全运营场景的一体化 XDR 平台。系统把资产、Agent、旁路流量、运行时、RASP、日志审计、规则中心和攻击链处置整合到同一个控制台，默认通过 HTTPS 443 对外服务，并支持离线镜像包一键安装。

## 核心能力

- **资产与 Agent 运维**：Agent 自注册、心跳、能力开关、在线/离线同步、资产性能快照。
- **流量可观测**：本机旁路镜像与外部终端探针分离展示，DNS/HTTP/TLS/TCP 会话持久化查询。
- **流量威胁检测**：规则引擎 + Agent 侧流量特征检测，包含 Nmap 风格端口扫描识别与误报降噪。
- **运行威胁 / 应用威胁**：运行时事件、日志审计和 RASP 事件统一进入安全引擎。
- **XDR 攻击链**：Incident 只来自关联链，阶段下挂对应证据和时间，不把单条普通事件升级为攻击链。
- **规则中心**：规则源同步、编译预览、版本管理、热加载、回滚。
- **离线验收安装包**：导出数据库与应用运行镜像，安装脚本自动检查 Docker、导入镜像并启动服务。

## 快速安装

离线包生成后：

```bash
tar -xzf lyflow-offline-install-*.tar.gz
cd lyflow-offline-install-*
sudo bash scripts/install-offline.sh
```

安装完成后访问：

```text
https://<服务器IP>/
```

默认账号：`admin / password`，首次登录要求修改密码。

## 开发与验收构建

```bash
# 构建离线验收包
scripts/build-offline-release.sh

# 后端测试
cd server && GOWORK=off go test ./...

# Agent 测试
cd agent && GOWORK=off go test ./cmd

# 前端构建
cd frontend && npm run build
```

生成的离线包位于 `release/lyflow-offline-install-*.tar.gz`。

## 文档

- [软件架构](ARCHITECTURE.md)
- [API 文档](docs/API.md)
- [白皮书](docs/WHITEPAPER.md)

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
