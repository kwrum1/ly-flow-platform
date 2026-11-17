# 巡检与降噪（2026-11-17）

实例：`10.1.18.125`，服务端 revision `main-1a44dd6`（1.1.0）

## 0. 系统状态

- 9 个容器全部 healthy；`ly-server` / `agent-center` 已稳定运行 4 天。
- 负载 6.98 / 6.57 / 6.89（8 核）；内存 4.4G used / 5.3G available；
  磁盘 57G / 991G（6%）。
- EVE 入库：state offset 92,768,340 / 93,031,790，持续追平；无
  `ingest skipped`。
- Suricata：38,063 条规则，0 failed；SNMP threshold 1 条。
- cron privilege-use 24h **0**，SNMP public 24h **1**（阈值生效）。

## 1. 24 小时告警

共 **53 条**，1 小时 0 条。Top：

| 告警 | 数量 | 判定 |
|---|---:|---|
| `[LY-CS-003] CobaltStrike DNS Beacon Long Subdomain` | 17 | 需区分 CDN 误报与可疑域名 |
| ET SCAN MySQL / Oracle / PostgreSQL | 19 | 扫描器 `10.1.1.181`，保留 |
| ET SCAN 其他（SSH/VNC/IMAP/POP3/SSDP） | 5 | 保留 |
| `LY-FRP-009` | 1 | 保留观察 |
| HeartBleed / Malformed HeartBeat | 2 | 保留 |
| 其他 | 9 | 保留 |

7d 共 3,781 条；Top 仍是扫描器 `10.1.1.181` 的 Web 探测
（`/etc/passwd` 436、SQLi 354、ECSHOP 313 等）。该扫描器告警按既定
决策保留。

## 2. LY-CS-003 域名分析

17 条命中来自 8 个后缀：

| 后缀 | 数量 | 判定 |
|---|---:|---|
| `wmzfylgdsz.com` | 6 | **保留/待研判**：完整域名解析到 58.17.23.87，标签随机且重复，疑似隧道/C2 |
| `bdcgslb.com` | 3 | 百度 GSLB CDN，误报 |
| `cdntips.net` | 2 | 腾讯 CDN，误报 |
| `pkoplink.com` | 2 | 完整域名不解析，保留观察 |
| `tcdn.qq.com` | 1 | 腾讯 CDN，误报 |
| `wuchucloud.cn` | 1 | 云厂商，误报 |
| `sdk.myapp.com` | 1 | 应用 SDK，误报 |
| `qrstuvwxyzab.com` | 1 | 完整域名不解析，保留观察 |

本轮只排除明确的 CDN/SDK 后缀：

```
bdcgslb.com  cdntips.net  tcdn.qq.com  wuchucloud.cn  sdk.myapp.com
```

`rules/ly-custom/c2.rules` rev 10 → **11**。**不排除**
`wmzfylgdsz.com`、`pkoplink.com`、`qrstuvwxyzab.com`，避免把真实隧道
误当噪声。

## 3. 历史清理

已备份并删除上述 5 个后缀的 **43 条历史误报**（其中 24h 内 8 条）：

```sql
-- 条件：rule_name LIKE '%CobaltStrike DNS Beacon%'
--       AND dns.queries[0].rrname LIKE 任一误报后缀
-- 备份表：threat_events_noise_20261117_backup（43 条）
```

`wmzfylgdsz.com` 的 6 条保留，作为待研判证据。

## 4. 性能

- `traffic/threats?limit=5` 5.29s，`traffic/sessions?limit=5` 2.38s；
  ClickHouse 仍是最忙的组件（前次采样 83% CPU）。
- 24h 告警量已从 11-16 的 2,294 降到 53，扫描器静默期；接口无报错。
- 建议后续单独评估 ClickHouse 合并/索引，本轮不改。

## 5. 验证

- 规则导出 57 条、lyprobe 8 条、overlap 0；容器内
  `sid:9002003; rev:11`。
- `suricatasc` socket 不可用，使用 `SIGUSR2` reload；日志显示
  38,063 条规则加载、0 failed、threshold 1 条。
- 清理后 24h LY-CS-003 从 **17 降到 9** 条（剩余 6 条
  `wmzfylgdsz.com` + 2 条 `pkoplink` + 1 条 `qrstuvwxyzab`）；
  7d 剩余 10 条。
- 历史误报 43 条已备份到 `threat_events_noise_20261117_backup`。
