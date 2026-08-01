# 流影 LyFlow XDR 安全态势感知平台

流影是面向单机安全设备和中小型安全运营场景的一体化 XDR 平台。服务端通过本机镜像口分析流量，外部主机通过无容器 Agent 上报运行时、日志、RASP、YARA 和小流量网络遥测；平台统一完成存储、检测、ATT&CK 关联、Incident 处置与可视化。

## 当前能力

- 本机镜像流量：AMD64 使用 PF_RING，Suricata 与统一安全引擎完成流量审计。
- 主机 Agent：Linux AMD64/ARM64、Windows AMD64；Linux 使用 AF_PACKET，可独立开关流量采集。
- 主机审计：日志、Runtime、YARA 文件扫描、Python RASP；Java RASP 仍为实验能力。
- 数据存储：PostgreSQL 保存账号、资产、规则、告警和处置状态；ClickHouse 保存长期会话与分析事件；Redis 只承担实时事件总线和短期缓冲。
- XDR：多源事件按实体、时间和 ATT&CK 阶段关联，只有关联链生成 Incident。
- 规则中心：在线发现版本、下载、编译、签名、热加载和回滚；不兼容规则会隔离并记录原因。
- 控制台：资产、Agent、流量、运行威胁、应用威胁、会话、规则、攻击链、处置和全球态势。

能力限制与尚未完成的现场认证见 [当前功能盘点与能力边界](docs/zh/当前功能盘点与能力边界.md)。

## 正式服务端安装

GitHub Release 固定提供两个文件：

- `lyflow-server-amd64.tar.gz`
- `lyflow-server-arm64.tar.gz`

选择与服务器 CPU 架构一致的文件，在已安装 Docker Engine 与 Compose Plugin 的 Linux 服务器上执行：

```bash
tar -xzf lyflow-server-amd64.tar.gz
cd ly-flow-platform
sudo bash scripts/install-docker-bundle.sh
```

安装器会校验主机架构、导入镜像、生成本机 `.env` 并启动正式 Compose 栈。安装完成后访问 `https://<服务器IP>/`；HTTP 80 自动跳转到 HTTPS 443。

首次登录账号为 `admin`，密码为 `password`。首次登录必须修改密码，修改后不会在服务重启时恢复默认密码。

## 默认生产拓扑

默认运行 9 个容器：

1. `ly-vis`：HTTP 跳转、HTTPS 控制台和 API/WS 代理。
2. `ly-server`：认证、业务 API、规则生命周期、XDR 与 Incident。
3. `agent-center`：Agent 注册、上线、配置和任务管理。
4. `ly-local-mirror`：本机 PF_RING 镜像采集。
5. `ly-suricata-sensor`：网络 IDS。
6. `ly-security-engine`：统一检测与告警输出。
7. `postgres`：事务与配置数据。
8. `clickhouse`：长期会话和分析数据。
9. `redis`：实时事件总线。

`ly-engine-lab`、容器化 Agent 和 legacy DPI 不属于默认生产组件，只保留为 QA/兼容 profile。

## Agent 使用边界

政企现场使用直接安装到宿主机的 Agent，不要求 Docker。Linux Agent 以静态二进制构建，面向 CentOS 7 / Linux 3.10 及以上内核；抓包使用 AF_PACKET，运行监控在旧内核回退到 auditd。容器 Agent 只用于自动化测试。

Agent 安装、卸载和 Windows/Npcap 下载入口由控制台“安装配置”页面提供。Npcap 单独分发，不集成到 Windows Agent 包中。

## 正式发布

GitHub Actions 工作流为 `.github/workflows/release.yml`，名称为“正式服务端发布”。工作流在每月 1 日和 16 日自动运行，也可手动触发；每次从公网重新获取规则和基础环境，无跨构建缓存，同时原生构建 AMD64 与 ARM64 服务端包。

新版本构建成功后，工作流删除旧 Actions 运行记录、旧 Release 和旧发布标签，只保留 `latest-server` 正式发布及本次两个服务端包。Gitea 继续作为内部源码和恢复仓库，不承担默认自动发布。

## 文档

- [软件架构](ARCHITECTURE.md)
- [白皮书](docs/WHITEPAPER.md)
- [当前功能盘点与能力边界](docs/zh/当前功能盘点与能力边界.md)
- [Agent 与 legacy DPI 兼容边界](docs/zh/AGENT与LEGACY-DPI兼容边界.md)
- [GitHub 正式发布](docs/GITHUB-CI.md)
- [发布来源与交付边界](docs/RELEASE_PROVENANCE.md)
- [API 摘要](docs/API.md)
