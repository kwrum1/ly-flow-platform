# 流影 LyFlow 1.0 发布说明

- 版本：**1.0.0 正式版**
- 发布日期：2026-10-31
- 适用场景：单机安全设备、中小型安全运营中心、南北向流量 + 主机侧遥测

## 本版亮点

### 检测能力

- Suricata 传感器加载 ET Open 全量签名（约 3.8 万条，每日自动刷新）+ 自写规则，
  覆盖 SQL 注入、路径穿越、WebShell 上传、CVE 利用、C2、扫描等；
- 流量聚合引擎保留 182 条可忠实转换的规则，lyprobe 6 条，两套引擎互不耦合；
- 检测面统一为流量 / 主机运行时 / 应用 RASP / YARA 四类，阻断状态以端侧证据为准；
- Suricata 告警落库时写入规则 SID、规则族与 classtype，分诊可直接看到规则编号。

### 降噪

- ET INFO / POLICY / HUNTING / USER_AGENTS / DNS 启发式等低价值家族默认剔除；
- 转换器保留 Sigma 的 AND 语义，通用分支（GET/POST/root/...）直接拒收；
- 已退役的误报规则（IIS 短名爆破、snort upload 路径、CobaltStrike CDN 哈希等）
  有退役清单与同步合并门禁，升级或重新同步不会回归。

### 运营闭环

- 攻击链处置改为三步：确认情报 → 分诊（诊断人 + 诊断意见）→ 处理
  （处理人 + 已处理/不需要处理）→ 闭环，全程审计；
- 事件详情展示规则 SID、源/目的、端口、原始载荷；
- 规则中心按四类引擎展示规则量，流量聚合引擎包含传感器签名总数。

### 平台与交付

- 9 容器默认拓扑：控制台、服务端、Agent 中心、镜像采集、Suricata、
  安全引擎、PostgreSQL、ClickHouse、Redis；
- 镜像采集 AF_PACKET（可选 PF_RING），默认排除内网 ↔ 内网；
- Agent 仅 Linux AMD64/ARM64，二进制/配置/策略签名校验；
- 保留策略：EVE 48 小时、traffic_sessions 3 天、threat_events 30 天、Redis 2 小时；
- CI 覆盖 Go、前端构建、Python RASP 与策略检查。

## 升级与安装

- 全新安装：从 GitHub Release `latest-server` 下载 `lyflow-server-{amd64,arm64}.tar.gz`；
- 已部署环境：替换 `LY_SERVER_IMAGE` / `LY_FRONTEND_IMAGE` 后
  `docker compose up -d --no-deps ly-server agent-center ly-vis`；
- 升级规则库：`systemctl start lyflow-et-open-refresh.service`（或等待每日 03:30 定时任务）。

## 已知边界

- RASP 生产验证覆盖 Python WSGI；PHP/Java/Node/.NET 仍需真实业务框架验证；
- 单机部署，不提供多节点高可用与集中管理；
- Sigma 等上游存在部分不可解析规则，会按 unsupported 记录，不影响已支持规则；
- 流量侧只分析南北向，不做内网东西向审计。
