# 巡检与降噪（2026-11-12）

实例：`10.1.18.125`，服务端 revision `bed6df9b`（1.1.0）

## 0. 系统状态

- 9 个容器全部 healthy；`ly-server` / `ly-vis` / `agent-center` 均为
  `main-bed6df9` / `main-05d2b20`，Agent 在线 1 台。
- 磁盘 38G / 991G（4%）；ClickHouse 占用 11.37 GiB。
- 负载 8 核约 11：主要来自 ClickHouse 61% CPU 与 Redis 后台 RDB 保存，
  暂无容器异常。
- Suricata：37972 条规则成功加载，0 failed，0 skipped；规则 reload 完成。
- 事件量：24h 138 条，7d 9702 条。

## 1. 噪声分布（巡检）

24h 前 5：

| 告警 | 数量 | 判定 |
|---|---:|---|
| `GPL SNMP public access udp` | 96 | 扫描器 30 秒内扫 140 个目标的 SNMP public，重复刷屏 |
| `component.alert` + `privilege-use` | 30 | 旧 Agent 把 root cron 会话报成提权 |
| `[LY-CS-003] CobaltStrike DNS Beacon` | 4 | 阿里云 WAF / Azure Traffic Manager 长标签误报 |
| ET SCAN（MySQL/Oracle/VNC/SSDP/TS） | 7 | 扫描器正常扫描，保留 |
| 其他 | 1 | 保留 |

7d：9702 条中 **9492 条（97.8%）来自 `10.1.1.181`**，命中 140 个目标；
这些是扫描器漏洞探测/Web 攻击，按既定决策保留，不做源抑制。

## 2. 本轮降噪

### 2.1 root cron privilege-use（30 条/天）

旧 Agent 上报：

```
component.alert
authentication signal detected: privilege-use
pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
```

这是 cron 自己的会话，不是提权。服务端 `xdrEventIsAuthPrivilegeNoise`
扩展为同时识别 `component.alert` 形态，并在 `persistThreatEvent` 入库前过滤。
`sudo`/`su`/root SSH 登录行不匹配，仍保留；high 严重度也不隐藏。

历史 47 条已备份并清理。当前 24h 仍保留 4 条 **root SSH session**，
属于真实提权信号，未清理。

### 2.2 LY-CS-003 CDN/WAF 误报（4 条/天）

排除列表加入：

- `*.yundunwafN.com`（阿里云 WAF）
- `*.<hash>.trafficmanager.cn`（Azure Traffic Manager）

`rules/ly-custom/c2.rules` rev 9 → 10。历史 7 条误报已备份并清理。

### 2.3 GPL SNMP 扫描刷屏（30 秒 96 条）

只对 SID `2101411` 加全局阈值：

```
threshold gen_id 1, sig_id 2101411, type limit, track by_src, count 1, seconds 3600
```

每源每小时 1 条，扫描本身仍由 ET SCAN 规则记录；扫描器的漏洞利用与
Web 攻击告警全部保留。模板见 `deploy/suricata/threshold.config`。

## 3. 规则源漂移修复

应用导出时发现 `.125` 上的规则源文件比已编译规则旧，直接导出会把
11-09/11-10 的修复回退：

- `rules/suricata/et-open.rules`：Bare IP rev 2 → **rev 4**（BITS/Windows Update UA 例外）
- `rules/ly-custom/frp.rules`：FRP-009 rev 2 → **rev 3**（X-Forwarded-For 例外）
- `rules/ly-custom/webshell.rules`：rev 2/1 → **rev 3/2**
- `rules/ly-custom/proxy.rules`：rev 1 → **rev 2**
- `rules/ly-custom/c2.rules`：rev 4 → **rev 10**

已把仓库 `rules/ly-custom/*.rules` 与 `rules/suricata/et-open.rules` 同步到
`.125`，重新导出后 57 条 Suricata 规则、8 条 lyprobe 规则、overlap 0，
关键 rev 全部正确。历史编译文件已备份为
`suricata.rules.bak.pre-export2.*`。

## 4. 验证

- `install` 后 `suricatasc` 不可用（socket 未启用），改用 `SIGUSR2` 触发
  在线 reload：`rule reload complete`，37972 条规则，0 failed。
- `threshold-config: Threshold config parsed: 1 rule(s) found`。
- 编译规则关键 rev：
  ```
  1000040 rev:4   1000041 rev:4   9001009 rev:3
  9002003 rev:10  9004301 rev:3   9004302 rev:2
  9007051 rev:2   9007111 rev:2
  ```
- 备份表：`threat_events_noise_20261112_backup`，**54 条**
  （47 条 cron + 7 条 CDN/WAF）。
- 清理后 24h：108 条（SNMP 96、root SSH 4、扫描 8）。

## 5. 保留与待办

- `10.1.1.181` 的扫描/漏洞探测告警按既定决策保留；如需按“已知扫描器”
  单独视图，建议在产品层加标签与默认过滤，而不是删告警。
- 下一次 02:17Z 的 cron 会话后应不再产生 root cron privilege-use；
  单元测试已覆盖旧 `component.alert` 形态、嵌套 `raw_event`、sudo 反例与
  high 严重度。
- 远端 Agent 更新后可以在 Agent 侧继续早退 cron 会话，服务端过滤保留作为兜底。
- 负载偏高（ClickHouse/Redis），本轮不改；建议后续单独评估 Redis
  `maxmemory` 与 ClickHouse 合并策略。
