# 流影镜像检测实例（10.1.18.125）

## 1. 宿主与网络

- 宿主：ESXi 8.0.3，`10.1.18.123`
- 新 VM：`lyflow-mirror`
- 规格：4 vCPU / 8 GB / 40 GB 精简磁盘
- 管理口：`mgmt0` → `Management Network`，`10.1.18.125/24`，网关 `10.1.18.1`
- 镜像口：`mirror0` → `mirror port`（vmnic4，VLAN 4095，Promiscuous=true）
- 镜像口已实测收包：约 15 万包 / 26 MB（首次观测窗口）

## 2. 平台

- 入口：`https://10.1.18.125/`（自签证书，浏览器需手动信任）
- 账号：`admin / Lyflow@2026`
- 版本：`server:v60` / `frontend:v46`
- 服务：postgres、redis、clickhouse、ly-server、agent-center、ly-vis、ly-security-engine、ly-suricata-sensor、ly-local-mirror，全部 healthy

## 3. 流量链路

```text
mirror port（vmnic4）
  → mirror0
    ├─ Suricata 8.0.7：57 条规则，4 threads，af-packet
    └─ ly-local-mirror：af_packet，sessions/flows 写入本地平台
```

- Suricata 日志确认：
  - `rule files processed. 57 rules successfully loaded, 0 failed`
  - `mirror0: creating 4 threads`
- local-mirror 持续输出：
  - `sensor=local iface=mirror0 engine=af_packet`
  - `raw=flows:raw semantic=flows:semantic session=sessions:semantic`
- 首次观测：EVE 约 8.2 万条、82 条 alert、8.2 万 flow。
  - 主要告警：`[LY-FSCAN-003] Fscan UDP Scan Pattern` 77 条
  - 次要告警：`ET TROJAN High DNS Query Count Possible Tunnel` 5 条
- **发现并修复误报**：`LY-FSCAN-003` 原来只有 30 包/60 秒阈值，没有内容条件，
  正常 DNS 客户端（10.254.251.x → 202.101.224.68:53）被误判为 Fscan UDP 扫描，
  短时间内产生 757 条告警。已加 `dsize:0;`，只匹配空载荷 UDP 探测。
  - 修复后 90 秒：EVE 14,889 行，alert 仅 3 条（2 条 DNS tunnel、1 条其他），
    Fscan 误报消失。
- 当前剩余告警：`ET TROJAN High DNS Query Count Possible Tunnel`
  （10.1.0.4 → 114.114.114.114:53），需继续观察是否为正常 DNS 客户端。
- 2026-10-30 已完成一轮基于真实告警的规则降噪，详见
  `docs/dev/ALERT-TUNING-2026-10-30.md`：
  - SID 1000050 / 9002003 收紧为“24+ 位、纯字母数字、含数字”标签；
  - SID 9001005 重写为 FRP 默认控制端口 7000 的 TLS 建连检测；
  - SID 9001009 / 9007022 增加 `flow:to_server`，修掉响应方向误报；
  - SID 9004301 / 9004601 只匹配脚本后缀响应中的 WebShell 特征；
  - 优化后新窗口 30,206 行 EVE、0 条告警。

## 4. 每小时观测

systemd：

- `lyflow-hourly-observe.timer`：`OnCalendar=hourly`，`Persistent=true`
- `lyflow-hourly-observe.service`：运行 `/usr/local/bin/lyflow-hourly-observe.py`

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

手动首跑结果：9/9 healthy，`mirror0` 有收包；唯一告警是 `ops.backup` 目录未挂载（新实例预期）。

自动首跑（18:00 UTC）：

```text
warnings: 0
services: 9/9 running healthy
mirror0: rx_packets=305,268, rx_dropped=24, 较上次 +7,739
suricata_eve: 14,889 lines, 3 alerts
traffic_sessions: API 200
```

`ops.backup` 无备份文件时按“空备份目录”忽略，不再每小时报噪声。

## 5. 已知问题

1. `ops.backup` 已在 `server:v61` 修复：空目录判为 `ok`（no backups yet），
   不再作为组件未就绪。
2. `ly-local-mirror` 使用 `release-amd64` 旧镜像；检测主链可用，但后续应升级到当前 agent 构建。
3. `engine-health` 为空，因为 local-mirror 不是注册 Agent；流量页有数据，但引擎健康页不显示这个 sensor。
4. Suricata 57 条规则来自 `.241` 的 server-zone profile；规则源更新后需要重新同步到 `.125`。
5. 浏览器访问需信任自签证书；之前的“连接拒绝”是安装未完成/端口未监听，现在 443 已监听并返回 200。

## 6. 下一步观察

- 每小时看 `latest.md` / `summary.log`，重点：
  - 9/9 服务是否持续 healthy
  - `mirror0` 是否有持续增量、`rx_dropped` 是否增长
  - Suricata EVE alert 是否出现新的高置信 C2/挖矿/隧道
  - local-mirror 是否出现 spool/502/corrupt
  - 磁盘 40G 是否足够长期 EVE 增长
- 运行至少 24 小时后再判断误报基线和是否需要调规则。
