# 巡检与告警分析（2026-11-04）

实例：`10.1.18.125`（Suricata 8.0.7，镜像口 `mirror0`，规则 37,945 条）

## 0. 系统健康

### Redis 达到 maxmemory，安全引擎崩溃循环

- 现象：`ly-security-engine` 重启 **1,772 次**，日志反复出现
  `create consumer group for telemetry:traffic: OOM command not allowed when used memory > 'maxmemory'`。
- 根因：Redis `maxmemory=4gb`、`maxmemory-policy=noeviction`，而
  `transport_reliability:*` 去重/记账 hash 已占用约 4GB，且没有保留期。
- 处置：把 `.env` 的 `REDIS_MAXMEMORY` 恢复为 profile 计算的 `5gb`，
  重建 Redis，安全引擎恢复 `healthy`；Redis 载入后 used_memory ≈ 4.01G，
  仍有约 1GB 余量。
- 已做：先快照 Redis，再 `UNLINK` 六个
  `transport_reliability:accounting:*:{seen,materialized}` 键；安全引擎保持
  healthy，内存回收后继续下降。
- 已加：`deploy/redis/prune-transport-reliability.sh` +
  `lyflow-redis-prune.timer`，每天 04:10 按 message ID 时间戳删除超过
  24 小时的 `transport_reliability:*` 条目；默认 dry-run，systemd 以
  `RUN=1` 执行。
- 建议：观察一周内存曲线；如果仍增长，把 retention 降到 12h，或把
  `transport_reliability` 去重改成带 TTL 的实现。

### 其他

- 磁盘：38G 总量，30G 已用，**8.6G 可用（78%）**。
- 内存：9.9G 总量，6.4G 已用，3.5G 可用。
- Suricata：17.4M 包，**0 drops**；BPF 仍为 `not ( host 10.1.18.125)`。
- 所有容器在 Redis 修复后均为 `healthy`。

## 1. 24 小时告警概览

共 74 条：

| 告警 | 数量 | 判定 |
|---|---:|---|
| `authentication signal detected: privilege-use` | 27 | 自身 cron 噪声 |
| `ET SCAN Potential SSH Scan` | 8 | 扫描/自动化，需确认 |
| `LY-CS-003 CobaltStrike DNS Beacon` | 7 | 2 条 Google 广告误报；5 条 `sdk.myapp.com` 待确认 |
| `ET SCAN ... mySQL 3306` | 6 | 真实扫描 |
| `ET SCAN ... Oracle 1521` | 6 | 真实扫描 |
| `GPL SNMP public access udp` | 6 | 扫描的一部分，弱配置 |
| `ET SCAN ... PostgreSQL 5432` | 5 | 真实扫描 |
| `ET MALWARE Observed Coruna User-Agent` | 4 | **误报** |
| `ET MALWARE Suspicious Download from Bare IP` | 3 | 软件分发/更新，需确认 |
| `ET WEB_SPECIFIC_APPS ActiveMQ ... M2` | 2 | **误报** |

## 2. 攻击链

### 2.1 `10.1.1.181` 内网扫描（真实，非误报）

时间集中在 2026-11-03 16:00–16:02（本地 00:00–00:02），目标：

- `10.1.16.10`：1521、3306、5432、22、161
- `10.199.0.3`：1521、3306、22、161

行为是典型的资产发现/端口扫描：同一源在 1 分钟内对多台主机的数据库、
SSH、SNMP 端口发起连接，没有看到后续利用、登录成功或横向移动。
`10.1.1.181` 也是 11-01 漏扫的来源，优先确认它是否为授权的漏洞扫描器；
如果是，建议把扫描窗口和源加入白名单/维护窗口，避免和真实攻击混淆。

### 2.2 `10.1.2.52 -> 10.20.215.161:22`（疑似定时任务）

04:00–04:06、16:02–16:06 两个时间窗，每次 4 条 SSH 建连，形态更像
每 12 小时一次的自动化/备份任务，而不是暴力破解。建议向资产负责人确认
`10.1.2.52` 的用途；若为合法任务，可按源+目的+端口加抑制。

## 3. 误报判定

### 3.1 Coruna User-Agent（4 条，误报）

- 事件全部是 `10.1.18.252 -> 10.1.0.192`，访问 `www.sru.edu.cn` 的普通新闻页；
- UA 是正常的 iPhone Safari 16.0：
  `Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) ... Version/16.0 Mobile/15E148 Safari/604.1`；
- ET 规则 `sid:2068009` 用 `bsize:135` + 完整 UA 匹配，任何同版本 iPhone
  都会命中，不能作为 Coruna 恶意判定。
- 处置：在 ET Open 刷新脚本中删除
  `ET MALWARE Observed Coruna User-Agent` 家族。

### 3.2 Apache ActiveMQ M2（2 条，误报）

- 事件是内部应用的正常 API：
  - `10.1.18.252 -> 10.1.2.40`，`/api/message/todayList`
  - `10.2.16.13 -> 10.1.2.32`，`/api/message/listTwenty`
- ET 规则 `sid:2069476` 只匹配 `http.uri` 的 `/api/message/`，任何带这个
  路径的业务应用都会命中；M1 的 `/api/jolokia/` 更具体，保留。
- 处置：删除 `... CVE-2024-32114) M2` 这个前缀。

### 3.3 Google 广告 DNS（2 条，误报）

- `80ece911...safeframe.googlesyndication.com`，是 Google 广告 iframe 的
  随机子域；`dig` 返回正常地址。
- 处置：在 `LY-CS-003` 的排除列表加入 `googlesyndication.com`（rev 7）。

### 3.4 `sdk.myapp.com`（5 条，待确认）

- 查询名：`2f712c2b...sdk.myapp.com`，源 `10.100.0.252` 和 IPv6 客户端；
- `dig sdk.myapp.com` 返回腾讯云 CNAME（`*.tencent-cloud.net`），
  随机子域返回 `127.0.0.1`（通配 DNS）；
- 形态更像某个 App SDK 的设备/会话 ID，而不是典型 C2，但不能仅凭 DNS
  排除。建议向业务确认是否使用 `sdk.myapp.com`；确认前保留告警。

### 3.5 Bare IP 下载（3 条，需确认）

- `10.64.178.250 -> 10.1.2.41` 下载 `/ChromeSetup.exe`，UA 为 Chrome/QuarkPC；
- `10.1.2.13 -> 121.40.54.194` 下载 `/sdmanager/2026/11/03/dist_...zip`，UA 为 Hutool；
- 看起来是内网软件分发/应用更新，不是攻击；建议核对文件哈希和发布来源，
  若确认合法可把对应的内网分发源加入例外。

### 3.6 privilege-use（27 条，自身噪声）

- `raw_event.metadata.log_line` 是：
  `CRON[...]: pam_unix(cron:session): session opened for user root`；
- 这是 Agent 的 `runtime.auth.privilege` 规则匹配了
  `session opened for user root`，把每小时 root cron 当成提权；
- 建议在 `agent/cmd/main.go` 的规则里去掉这个泛化 token，保留
  `sudo:`、`su: pam_unix`、`sudo su`、`sudo -i`，并补一条 CRON 反例测试。
  该修复需要更新 Agent 二进制，单独排期。

## 4. 已做的源码改动

- `deploy/suricata/et-open-refresh.sh`：新增 Coruna UA、ActiveMQ M2 两个
  drop 前缀。
- `rules/ly-custom/c2.rules`：`LY-CS-003` 排除 `googlesyndication.com`，rev 7。
- 反代 XFF 真实客户端归因：见 `docs/dev/XFF-ATTRIBUTION-2026-11-04.md`。

## 5. 建议下一步

1. 在 `.125` 上执行 ET Open 刷新，使 Coruna/ActiveMQ M2 立即生效；
   重新导出/重启 Suricata 使 `LY-CS-003` rev 7 生效。
2. 确认 `10.1.1.181` 是否为授权扫描器；确认 `10.1.2.52` 的 SSH 任务。
3. 确认 `sdk.myapp.com` 的业务归属；确认后再决定是否排除。
4. 处理 Redis `transport_reliability:*` 无界增长（保留期/裁剪），
   这是当前最需要排期的系统风险。
5. 反代 XFF 代码已提交，待构建 `ly-flow/server` 镜像后部署；
   部署后事件列表显示真实客户端，`proxy_ip` 保留在详情中。
