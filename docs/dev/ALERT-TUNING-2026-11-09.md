# 巡检、优化与降噪（2026-11-09）

实例：`10.1.18.125`

## 0. 系统状态

- 磁盘：`/` 991G，已用 38G，可用 954G（4%），10-31 的 1TB 扩容已生效。
- Redis：used 1.82G / 5G；`lyflow-redis-prune.timer` 正常。
- Suricata：37,967 条规则，0 failed，0 skipped；近期 14.7M 包 / 504 drops。
- 安全引擎：容器 `RestartCount=0`（本轮重建后），健康；此前 24h 内因
  `runtime CPU budget exceeded` 重启多次。

## 1. 优化

### 1.1 安全引擎 CPU 预算

- 源码 `docker-compose.yml` 已有 `SECURITY_ENGINE_CPU_BUDGET_MS: "1000"`，
  但 `.125` 部署的 compose 缺失，引擎回落到默认 100ms，频繁
  `runtime CPU budget exceeded` → 容器重启（本轮前 `RestartCount=67`）。
- 已在 `.125` 的 compose `ly-security-engine` 服务补上
  `SECURITY_ENGINE_CPU_BUDGET_MS: "1000"`，重建容器；
  当前 `Status=running Restarts=0`，引擎健康。

## 2. 降噪

### 2.1 Bare IP 下载（20 条 Defender/BITS 更新）

- 事件为 `10.1.2.17 -> 172.18.0.1`，URL
  `/IXC.../d/msdownload/update/software/defu/.../am_delta_*.exe`，
  UA `Microsoft BITS/7.8`，是 Windows Defender 定义更新，不是恶意下载。
- `rules/suricata/et-open.rules` 的 SID 1000040/1000041 增加负向 UA：
  `Microsoft BITS`、`Microsoft-Delivery-Optimization`、`Windows-Update-Agent`，
  rev 4；保留真实 `.exe`/`.zip` 裸 IP 下载检测。
- 历史记录已备份并清理；当前 24h 仅剩 1 条 `ChromeSetup.exe`（内网软件分发）。

### 2.2 privilege-use（26 条 root cron）

- 原始日志：`CRON[...]: pam_unix(cron:session): session opened for user root`。
- 来源不是 `.125` 本地 `local-mirror`，而是 **DNS-8（10.1.18.8）的 Agent
  `v2.0.0`**；`.125` 的 `local-mirror:v69` 已包含 cron 早退修复，但不覆盖
  远端 Agent。
- 历史 26 条已备份清理；要彻底停止新增，需要更新 DNS-8 上的 Agent 到包含
  `classifyAuthSignal` cron 早退的版本，或在服务端入库时过滤
  `metadata.log_line` 含 `pam_unix(cron:session)` 的 privilege-use。

### 2.3 保留的正常告警

- `10.1.1.181` 24h 内 281 条：SNMP 192、SSH OUTBOUND 59、Oracle/MySQL/
  PostgreSQL/SSH 扫描等，按用户要求全部保留正常告警，不做源抑制。
- 其他单条：WordPress CVE、SSDP、FRP-009、SMB 非标端口等，保留观察。

## 3. 事件备份

`threat_events_noise_20261109_backup`：82 条（Defender BITS + root cron
privilege-use）。当前 24h 的 Bare IP 降为 1 条，privilege-use 为 0。

## 4. 待处理

- DNS-8 Agent `v2.0.0` 更新（privilege-use 的根因）。
- 安全引擎 CPU 预算 1000ms 的持续观察（24h 重启次数应明显下降）。
- `10.1.1.181` 的 SNMP/SSH 扫描保持正常告警。
