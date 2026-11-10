# 流影镜像检测实例（10.1.18.125）

> 最近核实：2026-11-10 13:40–14:00 UTC，在实例内只读采集。
> 文中数字均来自当次命令输出；无法从实例内确认的项标注「待核实」。

## 1. 宿主与网络

- 宿主：ESXi，`10.1.18.123`（ICMP 可达，HTTPS 返回 200）
  - 原文档记为 ESXi 8.0.3；本次未在实例内核实，**待核实**
- 新 VM：`lyflow-mirror`（guest hostname；ESXi 清单中的显示名待核实）
- 规格（实测）：**8 vCPU / 9.71 GiB 内存 / 991 GB 单盘**
  - CPU：`nproc` = 8；`lscpu` 显示 Intel Xeon Bronze 3204 @ 1.90GHz，8 socket × 1 core
  - 内存：`MemTotal: 10182480 kB`（约 9.71 GiB，`free -h` 显示 9.7Gi）
  - 磁盘：`/dev/sda1` 991G，已用 43G，可用 949G（5%）
  - 后端存储是否为精简置备：待核实（guest 内不可见）
- 系统：Ubuntu 24.04.5 LTS，内核 `6.8.0-147-generic`，VMware 全虚拟化
- 管理口：`mgmt0` → `Management Network`，`10.1.18.125/24`，网关 `10.1.18.1`
- 镜像口：`mirror0` → `mirror port`（vmnic4，VLAN 4095，Promiscuous=true），无 IPv4 地址
- 镜像口累计收包（自开机）：`rx_packets=698,133,630`，`rx_bytes=528,426,166,751`（约 492 GiB），
  `rx_dropped=10,808`，`rx_errors=0`

## 2. 平台

- 入口：`https://10.1.18.125/`（自签证书，浏览器需手动信任）
- 账号：`admin / Lyflow@2026`
- 版本（`docker ps` 实测，2026-11-10）：

  | 服务 | 镜像 |
  |---|---|
  | ly-server | `ly-flow/server:v85` |
  | agent-center | `ly-flow/server:v84` |
  | ly-vis | `ly-flow/frontend:v53` |
  | ly-security-engine | `ly-flow/security-engine:v67` |
  | ly-suricata-sensor | `ly-flow/suricata-profile:v67` |
  | ly-local-mirror | `ly-flow/local-mirror:v69` |
  | clickhouse | `ly-flow/vendor/clickhouse:24.8-alpine-amd64` |
  | postgres | `ly-flow/vendor/postgres:16-alpine-amd64` |
  | redis | `ly-flow/vendor/redis:7-alpine-amd64` |

- 服务：postgres、redis、clickhouse、ly-server、agent-center、ly-vis、ly-security-engine、
  ly-suricata-sensor、ly-local-mirror，9/9 running healthy
- 部署目录：`/opt/ly-flow-platform`（compose 文件 + `.env` 覆盖镜像 tag）

## 3. 流量链路

```text
mirror port（vmnic4）
  → mirror0
    ├─ Suricata 8.0.7：37,965 条规则，4 threads，af-packet
    └─ ly-local-mirror：af_packet，sessions/flows 写入本地平台
```

- Suricata 日志确认（当前镜像启动一次即输出）：
  - `Info: detect: 2 rule files processed. 37965 rules successfully loaded, 0 rules failed, 0 rules skipped`
  - `Info: runmodes: mirror0: creating 4 threads`
  - `Notice: threads: Threads created -> W: 4 FM: 1 FR: 1   Engine started.`
- 规则分布（`grep -c '^alert'`）：
  - `server-zone/suricata.rules`：57 条（其中 55 条为 `LY-` 前缀自建规则，2 条为 ET MALWARE）
  - `et-open/et-open.rules`：37,908 条
  - 合计 37,965 条，与加载日志一致
- 规则来源：ET Open（每日刷新）+ LyFlow 自建规则（server-zone profile）；无商业情报源
- local-mirror 持续输出：
  - `sensor=local iface=mirror0 engine=af_packet`
  - `raw=flows:raw semantic=flows:semantic session=sessions:semantic`
- 告警现状（2026-11-10 核实）：
  - `eve.json` 与 `eve.json.1` 中 alert 均为 0 条；每小时观测多数为 0，仅 05:00 UTC 那小时 6 条
- 历史观测（2026-10-29 ～ 10-30，当时数据，非当前状态）：
  - 首次观测：EVE 约 8.2 万条、82 条 alert、8.2 万 flow
    - 主要告警：`[LY-FSCAN-003] Fscan UDP Scan Pattern` 77 条
    - 次要告警：`ET TROJAN High DNS Query Count Possible Tunnel` 5 条
  - **发现并修复误报**：`LY-FSCAN-003` 原来只有 30 包/60 秒阈值，没有内容条件，
    正常 DNS 客户端（10.254.251.x → 202.101.224.68:53）被误判为 Fscan UDP 扫描，
    短时间内产生 757 条告警。已加 `dsize:0;`，只匹配空载荷 UDP 探测。
    - 修复后 90 秒：EVE 14,889 行，alert 仅 3 条（2 条 DNS tunnel、1 条其他），Fscan 误报消失
  - 2026-10-30 已完成一轮基于真实告警的规则降噪，详见
    `docs/dev/ALERT-TUNING-2026-10-30.md`：
    - SID 1000050 / 9002003 收紧为“24+ 位、纯字母数字、含数字”标签；
    - SID 9001005 重写为 FRP 默认控制端口 7000 的 TLS 建连检测；
    - SID 9001009 / 9007022 增加 `flow:to_server`，修掉响应方向误报；
    - SID 9004301 / 9004601 只匹配脚本后缀响应中的 WebShell 特征；
    - 优化后新窗口 30,206 行 EVE、0 条告警。

## 4. 每小时观测

systemd（`systemctl list-timers 'lyflow-*'`）：

- `lyflow-hourly-observe.timer`：`OnCalendar=hourly`（`Persistent=true`，`RandomizedDelaySec=60`），
  跑 `/usr/local/bin/lyflow-hourly-observe.py`
- `lyflow-eve-rotate.timer`：`OnCalendar=hourly`，执行 `logrotate -f /etc/logrotate.d/lyflow-suricata-eve`
- `lyflow-et-open-refresh.timer`：每日 `03:30 Asia/Shanghai`（±20 分钟随机延迟）刷新 ET Open；
  最近一次 2026-11-09 19:33 UTC，退出码 0
- `lyflow-redis-prune.timer`：每日 `04:10 Asia/Shanghai` 清理 `transport_reliability` 哈希

输出：

```text
/var/log/lyflow/hourly/YYYYMMDD-HH.json
/var/log/lyflow/hourly/summary.log
/var/log/lyflow/hourly/latest.md
```

检查项：

- 9 个 compose 服务状态/health
- Docker CPU/内存
- `mirror0` rx bytes/packets/errors/dropped，和上一小时增量
- Suricata / local-mirror 最近 90 分钟错误
- API 登录、health、components、engine-health、defense、RASP、traffic sessions
- 组件非 ok 项

最近一次（2026-11-10 13:00 UTC）：

```text
warnings: 1  (traffic_sessions http=-1)
services: 9/9 running healthy
mirror0: rx_packets=694,662,857, rx_dropped=10,754, 较上次 +4,137,394
suricata_eve: 4,053 lines, 0 alerts
```

## 5. 已知问题

1. ~~`ops.backup` 未挂载~~ 已修复：`/opt/lyflow-backup` 挂到容器 `/backup`，
   `components` 返回 `backup directory ready, no backups yet`（count=0，status=ok）。
   注意目录里确实还没有任何备份文件，备份策略本身尚未验证。
2. ~~`ly-local-mirror` 使用 `release-amd64` 旧镜像~~ 已升级到 `ly-flow/local-mirror:v69`。
3. ~~`engine-health` 为空~~ 已修复：`/api/v1/engine-health` 现返回 3 条，
   其中 `suricata` 引擎以 `agent_id=local-mirror-sensor`、`hostname=流量镜像分析` 出现，state=running。
4. ~~Suricata 57 条规则来自 `.241` 的 server-zone profile~~ 现状：每日 ET Open 刷新已生效，
   `et-open.rules` 与 `server-zone/suricata.rules` 的 mtime 均为 2026-11-10 06:58；
   加载 37,965 条。server-zone 自建部分仍是 57 条（55 条 `LY-` 自建 + 2 条 ET MALWARE）；
   该目录内 `profile-manifest.json` 的 `generated_at` 为 2026-10-30。
   是否仍由 `.241` 同步而来，本次未在 `.125` 内核实，**待核实**。
5. 浏览器访问需信任自签证书；443 已监听并返回 200。
6. **`/api/v1/traffic/sessions` 超时**：每小时观测稳定报 `traffic_sessions http=-1`
   （curl 30 秒超时）。流量事件仍在入库，但该查询接口在镜像实例上不可用，需要单独定位。
7. **采集可见性为 degraded**：`components.capture` 报
   `state=degraded, reason=loss_unknown`（agent `47e3c1b5-…`，10.1.18.8）。
   丢包率分母不可信时不发布比率，属预期口径，但状态需要有人跟进。
8. EVE 落盘由 `logrotate` 管理（`rotate 48`、`compress`、`delaycompress`、`copytruncate`），
   当前 `/var/log/suricata` 50 个文件、约 2.2 GB。仓库里的 `deploy/suricata/eve-retention.sh`
   在该实例上未部署（`/etc/lyflow/eve-rotate.conf` 不存在）。

## 6. 下一步观察

- 每小时看 `latest.md` / `summary.log`，重点：
  - 9/9 服务是否持续 healthy
  - `mirror0` 是否有持续增量、`rx_dropped` 是否增长（累计 10,808 / 6.9 亿包，比例约 0.0015%）
  - Suricata EVE alert 是否出现新的高置信 C2/挖矿/隧道
  - local-mirror 是否出现 spool/502/corrupt
  - `/api/v1/traffic/sessions` 超时是否与数据量增长相关
- 磁盘：总 991G、已用 43G、可用 949G，**容量不是当前瓶颈**。占用大头是
  postgres 卷 17G（其中 `traffic_sessions` 表 15G）、clickhouse 卷 11G、redis 卷 3.6G；
  EVE 已被 logrotate 限制在约 2.2G。后续观察重点应是 `traffic_sessions` 与 clickhouse 的增长速率，
  以及 EVE 保留窗口是否够复盘；原文档按 40G 磁盘推断容量风险，与实际规格不符，已作废。
- 运行至少 24 小时后再判断误报基线和是否需要调规则。
