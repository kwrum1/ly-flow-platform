# 巡检与降噪（2026-11-06）

实例：`10.1.18.125`（Suricata 8.0.7，镜像口 `mirror0`）

## 0. 系统状态

- 磁盘：91%（3.8G 可用）→ **74%（10G 可用）**。
  - 截断 ClickHouse 系统日志表；
  - EVE 归档保留最近 12 个 `.gz`；
  - 清理后 `docker system df` 的卷占用从 23.42GB 降到 17.52GB。
- Redis：`used_memory ≈ 2.51G / 5G`，`noeviction`；每日 04:10
  `lyflow-redis-prune.timer` 正常。
- 安全引擎：`RestartCount=36`，最近一次为
  `security-engine runtime CPU budget exceeded` 后自动恢复；当前 healthy。
- Suricata：37,956 条规则（ET Open 37,899 + 自定义 57），0 failed；
  86.7M 包 / 4,033 drops（约 0.005%），属可接受范围。

## 1. 24 小时告警

| 告警 | 数量 | 判定 |
|---|---:|---|
| `ET WEB_SERVER Next.js Middleware Authorization Bypass` | 53 | 真实外部扫描，保留 |
| `ET SCAN Potential SSH Scan` | 11 | 10.1.2.52 定时任务 + 10.1.1.181 扫描 |
| `GPL SNMP public access udp` | 6 | 10.1.1.181 扫描的一部分 |
| Oracle/PostgreSQL/MySQL 扫描 | 16 | 真实扫描 |
| `LY-CS-003`（jddebug） | 7 | **CDN/SDK 噪声，已排除** |
| `ET PHISHING Successful Generic .EDU Phish` | 1 | **内部登录页误报，已删除家族** |
| `PCAnywhere` | 2 | 历史事件，当前 ET 文件已无此规则 |
| `Clear or Disable Kernel Ring Buffer Logs` | 2 | **Sigma 误报**（SSH logout 行含 `syslogin`） |
| `privilege-use` | 27 | **root cron 自身噪声** |
| `LY-FRP-009` | 1 | 外部直连代理认证，保留观察 |
| `LY-SCAN-004` | 1 | SMB 非标端口，保留 |

### 1.1 XFF 已在实际事件上生效

Next.js 扫描事件的 `raw_event` 已包含：

```text
src_ip=10.1.18.252（代理）
proxy_ip=10.1.18.252
client_ip=35.203.79.75
source_attribution.reason=trusted_proxy_chain_resolved
confidence=0.95
```

`threat_events.src_ip` 已写成 `35.203.79.75`，说明反代 XFF 归因在真实流量上工作。

## 2. 本轮降噪

### 2.1 `LY-CS-003` 排除 `jddebug.com`

- 事件名：`3fd3f1e1...jddebug.com`，来自 JD 调试/遥测 SDK；
- `rules/ly-custom/c2.rules` rev 8，在 pcre 排除列表加入 `jddebug.com`。

### 2.2 `ET PHISHING .EDU` 家族

- 命中 `kygln.sru.edu.cn` 的正常内部登录页；
- `deploy/suricata/et-open-refresh.sh` 加入
  `ET PHISHING Successful Generic .EDU Phish`；
- 刷新时删除 2 条规则。

### 2.3 `privilege-use` root cron

- `agent/cmd/main.go` 的 `classifyAuthSignal` 增加 cron session 早退：
  `pam_unix(cron:session)` / `CRON[...] session opened` 不再归为
  `privilege-use` 或 `persistence-scheduler`；
- 保留 `sudo:`、`su: pam_unix`、`sudo su`、`sudo -i`；
- 新增测试覆盖 CRON 反例、sudo/su 正例。
- **注意**：需要更新 `.125` 的 Agent 二进制后才会停止新增；当前历史事件已清理。

### 2.4 Kernel Ring Buffer Sigma 误报

- 原始日志是 `sshd-session: syslogin_perform_logout: logout() returned an error`；
- 规则把 `syslogin` 中的 `syslog` 当成内核 ring buffer 清理；
- 该规则不在仓库源码内（来自安全引擎的 Sigma bundle），本轮先清理历史事件，
  未改规则包；下一轮可在安全引擎侧加 `syslogin_perform_logout` 例外。

## 3. 历史事件清理

备份表：`threat_events_noise_20261106_backup`，共 **182** 条：

- `LY-CS-003` + `jddebug.com`
- `ET PHISHING Successful Generic .EDU Phish`
- `GPL POLICY PCAnywhere Attempted Administrator Login`
- `Clear or Disable Kernel Ring Buffer Logs via Syslog Syscall`
- `privilege-use` 且 `raw_event` 含 `cron:session`

清理后 24h 剩余真实告警：Next.js 53、SSH 11、数据库/SNMP 扫描 22、
FRP 1、SMB 1；`jddebug`/phishing/PCAnywhere/kernel 已归零。

## 4. 仍需确认

- `10.1.1.181` 是否为授权扫描器；`10.1.2.52 → 10.20.215.161:22` 是否为定时任务。
- Agent 二进制更新（privilege-use 修复）。
- 安全引擎 `runtime CPU budget exceeded` 的阈值与主机负载（load average ≈ 6.4）。
- 反代 XFF 只覆盖 Suricata 告警；流量会话页仍无 HTTP 头，显示代理。
