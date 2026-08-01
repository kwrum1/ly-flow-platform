# 流影 LyFlow XDR 安全态势感知平台白皮书

> 版本状态：2026-08-02 当前代码基线

## 摘要

流影是一套单机一体化 XDR 安全态势感知平台。它把旁路网络流量、主机运行时、日志、文件扫描和应用 RASP 事件统一到同一事件模型，通过规则检测、ATT&CK 映射、跨源关联和 Incident 处置形成安全运营闭环。

当前产品由 Docker Compose 服务端和无容器主机 Agent 组成。服务端支持 AMD64 与 ARM64 构建；政企业务主机不要求安装 Docker，Linux Agent 面向 CentOS 7/Linux 3.10 及以上内核。

## 1. 使用场景

- 安全设备通过本机镜像口接收交换机旁路流量，完成会话留存和 IDS/DPI 审计。
- Agent 部署到受保护主机，完成资产、日志、Runtime、YARA、RASP 和可选小流量抓包。
- 多个检测面产生的事件由 XDR 关联为 ATT&CK 攻击链，安全人员在控制台分诊和闭环。
- 规则中心在线更新规则、编译校验、热加载并保留回滚版本。

## 2. 核心设计

### 证据优先

流量告警保留源/目的 IP、端口、协议、规则来源和原始事件引用。XDR Incident 必须来自关联链，不把单条普通事件包装成攻击链。

### 存储分工

PostgreSQL 负责账号、资产、规则、告警、Incident 和审计等事务数据；ClickHouse 负责高容量会话与分析事件的长期留存；Redis 只负责实时事件总线和短期缓冲。三者职责互补，不互相替代。

### 采集分层

服务端 AMD64 高流量镜像采集使用 PF_RING。Linux Agent 小流量采集使用 AF_PACKET，可由控制中心关闭；旧内核运行监控回退到 auditd。Windows 抓包依赖用户单独安装 Npcap。

### 规则可运营

规则更新不是简单覆盖文件。平台记录来源版本与摘要，转换并编译规则，隔离不兼容项，成功后热加载；失败可回滚到上一激活版本。

## 3. 已实现能力

### 网络安全

- 本机镜像接口识别与管理口排除。
- PF_RING/兼容本机采集、Suricata EVE、网络会话与统一流量告警。
- DNS、HTTP、TLS、TCP/UDP 等语义会话查询。
- Nmap 风格扫描聚合与识别类噪声抑制。
- ClickHouse 长期保存语义会话，用于溯源查询。

### 主机与应用安全

- Agent 一次性令牌注册、心跳、能力开关、任务与资产快照。
- Linux 日志和认证行为审计、Runtime/auditd 事件。
- YARA 文件扫描，事件包含规则、路径和文件哈希。
- Python RASP monitor/protect 策略、配置签名、健康状态和事件上报。
- AF_PACKET 小流量采集，旁路镜像承担流量时可关闭。

### XDR 与运营

- 多源规范化事件、ATT&CK 战术/技术映射和阶段证据。
- 基于实体、时间和连续性的攻击链关联。
- Incident 研判、处理中、解决和不可变审计。
- 资产、Agent、威胁、会话、规则、攻击链和全球态势 UI。

### 规则与更新

- ET Open、OISF Traffic ID、Snort Community、Stamus Lateral 和 PT AttackDetection 公共流量规则源构建链路。
- 安全引擎规则的版本、编译、签名、激活、热加载与回滚。
- GitHub 正式构建每次重新获取公网规则，不复用历史规则缓存。

## 4. 部署与发布

正式 Release 只发布：

- `lyflow-server-amd64.tar.gz`
- `lyflow-server-arm64.tar.gz`

服务端包包含正式 Compose、应用镜像、数据库镜像、规则、双架构 Linux Agent、Windows Agent 和一键安装脚本。目标机需预装 Docker Engine 与 Compose Plugin。

```bash
tar -xzf lyflow-server-amd64.tar.gz
cd ly-flow-platform
sudo bash scripts/install-docker-bundle.sh
```

安装完成后，HTTP 80 跳转 HTTPS 443。首次登录为 `admin/password`，系统强制改密。

GitHub Actions 在每月 1 日和 16 日自动构建，也可手动触发。AMD64 与 ARM64 使用原生 runner；新版本成功后清理旧构建记录和旧 Release，只保留当前正式服务端。

## 5. 安全边界

- 默认自签 HTTPS 证书适合初装和内网验收，正式环境应替换为组织证书。
- 内部数据库、Redis、JWT 和控制令牌由安装器生成并保存在目标机 `.env`，不进入源码或发布说明。
- 外部 Agent 的目标网络模型是访问平台 HTTPS；遗留 Redis 兼容代码不应成为现场部署前提。
- Python RASP protect 已打通，但尚未完成全部框架兼容矩阵；Java RASP 仍为实验能力。
- ARM64 可完整构建，真实 ARM 网卡、PF_RING替代路径和长期性能仍需现场认证。
- 当前不提供多节点 HA、自动主机隔离或网络封禁承诺。
- 长期会话留存保存语义会话，不等于保存全部原始 PCAP。

## 6. 结论

当前代码已经形成可部署的网络与主机多面采集、统一检测、长期存储、XDR 关联、Incident 处置和规则运营主链路。产品成熟度的下一阶段不是继续增加页面，而是完成 CentOS 7、ARM 实机、真实业务 RASP、检测效果和持续性能基线认证。
