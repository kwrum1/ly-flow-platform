# 流影 LyFlow 1.1 发布说明

- 版本：**1.1.0 正式版**
- 发布日期：2026-11-11
- 适用场景：单机安全设备、中小型安全运营中心、南北向流量 + 主机侧遥测

## 本版重点

### 验收缺陷修复

- 流量检测页不再返回 500：修复 `triaged_at`（timestamptz）与 `asset_id`
  （bigint）按字符串扫描导致的整页失败。
- 启动不再重建两个 GIN 索引，`ly-server` 从“超过 25 分钟无法启动”恢复到
  约 15 秒 healthy。
- ClickHouse 读取改用 `flexibleUint64`，兼容 `JSONEachRow` 把 `UInt64`
  输出为字符串的行为；历史会话 30 天 TTL 已生效。
- Incident 生命周期工作线程、分诊状态、方向与资产范围按生产数据重新校验。

### 四个检测面与攻击链可读化

- 流量、主机运行时、应用 RASP、YARA 四类检测结果均给出中文结论：
  谁对谁做了什么、属于哪类攻击、判定等级。
- 未命中已知攻击类型时明确写“该规则未归入已知攻击类型”，不硬分类。
- 详情抽屉顺序为：结论 → 请求内容 → 原始载荷（仅用于核对）。
- 攻击链每条证据都有同样的叙述，时间线可逐条阅读。

### 受害地址与归因修正

- **受害服务器 = 报文目的地址**。请求域名（HTTP Host / TLS SNI / DNS 名）
  单独展示，并明确说明“域名只说明客户端想访问谁，不等于被打的服务器”。
- **X-Forwarded-For 仅作参考**，标注“客户端自述，未经核实”，不再被当作
  真实客户端，也不替代观测到的源地址。
- 主机侧检测没有目的地址时点名主机（“主机 X 上触发…”），
  `victim_ip` 保持为空，不把主机名塞进 IP 字段。
- 历史事件不重写数据库，叙述在读取时推导。

### 性能与运维

- 列表查询不读取 `raw_event`，趋势页与列表页响应保持稳定。
- 镜像、前端、服务端均带 `org.opencontainers.image.revision` 标签，
  便于核对线上 revision。
- 文档补充 `PROGRESS.md`、`DECISIONS.md` D-020 与本次验收证据。

## 升级与安装

- 全新安装：从 GitHub Release `latest-server` 下载
  `lyflow-server-{amd64,arm64}.tar.gz`。
- 已部署环境：替换 `LY_SERVER_IMAGE` / `LY_FRONTEND_IMAGE` 后执行
  `docker compose up -d --no-deps ly-server agent-center ly-vis`。
- 规则库：`systemctl start lyflow-et-open-refresh.service`，或等待每日
  03:30 定时任务。

## 已知边界

- RASP 生产验证覆盖 Python WSGI；PHP/Java/Node/.NET 仍需真实业务框架验证。
- 单机部署，不提供多节点高可用与集中管理。
- 流量侧只分析南北向，不做内网东西向审计。
- 主机侧检测的目标是产生证据的主机；没有网络目的地址时不虚构地址。
