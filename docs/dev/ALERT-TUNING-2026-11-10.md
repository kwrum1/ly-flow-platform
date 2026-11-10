# 巡检、优化与降噪（2026-11-10）

实例：`10.1.18.125`

## 0. 系统状态

- 磁盘：991G，已用 42G，可用 950G（5%）。
- Redis：2.01G / 5G；prune timer 正常。
- Suricata：37,965 条规则，0 failed，0 skipped；50.7M 包 / 1,879 drops。
- 安全引擎：`RestartCount=0`，**连续 30 小时无重启**；上次的
  `SECURITY_ENGINE_CPU_BUDGET_MS=1000` 优化生效。
- 负载：6.35；容器全部 healthy。

## 1. 优化效果

- 11-09 把 `.125` 的 `SECURITY_ENGINE_CPU_BUDGET_MS` 补为 1000ms 后，
  引擎从“每 1-3 小时 CPU budget 重启”变为 **30h 0 重启**。
- 当前无需继续调 CPU 预算，保持 1000ms 观察。

## 2. 新增降噪

### 2.1 ET PHISHING Meta HTTP-Equiv Refresh（27 条）

- `10.1.0.78 -> 10.2.16.9`，Host `10.1.0.78`，URL `/menu.asp`，
  UA 正常 Chrome 132；是内部页面的 meta refresh，不是钓鱼。
- ET Open 刷新脚本加入
  `ET PHISHING Successful Generic Phish (Meta HTTP-Equiv Refresh)`。

### 2.2 iebar Spyware User Agent（2 条）

- 外部客户端访问 `cgzb.sru.edu.cn`，UA 为
  `MSIE 6.0; MyIE2; SV1; iebar`，是老旧浏览器/工具栏 UA，不是有效攻击。
- ET Open 刷新脚本加入 `ET MALWARE iebar Spyware User Agent`。

### 2.3 LY-CS-003 + chinacloudapi.cn（1 条）

- `10.1.0.4` 查询
  `apic...chinanorth3.cloudapp.chinacloudapi.cn`，属于 Azure China
  cloud-app 主机名。
- `rules/ly-custom/c2.rules` rev 9，在排除列表加入 `chinacloudapi.cn`。

### 2.4 privilege-use（26 条）

- 来源仍是 DNS-8（`10.1.18.8`）的 Agent `v2.0.0`，不是 `.125`
  `local-mirror:v69`；远端 Agent 更新前会按小时产生。
- 历史 26 条已备份清理；彻底停止需更新 DNS-8 Agent，或在服务端入库时
  过滤 `metadata.log_line` 含 `pam_unix(cron:session)` 的 privilege-use。

### 2.5 保留

- `10.1.1.181` 24h 内 283 条：SNMP 192、SSH OUTBOUND 59、
  Oracle/MySQL/PostgreSQL/SSH 扫描等，按用户要求保留正常告警。
- 新增的 `failed-auth` / `SSH Authentication Failure` 6+6+2 条，来自
  SSH 扫描/失败登录，保留观察。
- Bare IP 2 条为内网 `ChromeSetup.exe` 软件分发，保留。

## 3. 事件备份

`threat_events_noise_20261110_backup`：**61 条**
（Meta Refresh 27、iebar 2、chinacloudapi 1、root cron privilege-use 26、
其他同条件历史 5）。

清理后当前 24h 的 PHISHING/iebar/LY-CS-003/privilege-use 均为 0。

## 4. 存储余量

当前 950G 可用。EVE 归档 12 个 `.gz`、`traffic_sessions` 3 天保留期
尚未调整；如需保留更久，可把 EVE 提到 48h、会话表提到 7 天。
