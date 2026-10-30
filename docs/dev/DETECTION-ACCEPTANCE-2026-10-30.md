# 检测能力与主动防御验收（2026-10-30）

实例：

- `10.1.18.125`：镜像口检测实例（`mirror0`，Suricata 58 条规则）
- `10.1.18.241`：主平台
- `10.1.18.8`：RASP / Agent 测试机

## 1. 规则转换保真与降噪

### 1.1 审计范围

5 个外部签名源、52,453 条原始 Suricata 规则：

```text
ET Open / PT Security / Snort Community / Stamus / OISF traffic-id
```

### 1.2 发现

活动流量规则 531 条，其中 335 条存在端口/方向/偏移等约束丢失。

| 原规则 | 丢失的约束 | 转换后 | 风险 |
|---|---|---|---|
| ET IRC PRIVMSG | `!6661:6668` | `PRIVMSG` 任意端口 | 任意协议误报 |
| ET IRC USERHOST | `!6661:6668` | `USERHOST` 任意端口 | 同上 |
| ET SIP REGISTER/INVITE | `5060` | `REGISTER` / `INVITE` 任意端口 | HTTP 注册/邀请误报 |
| ET Gnutella | `1024:` + depth | `GNUTELLA` | 低 |
| ET BitTorrent | `6881:6889` | `BitTorrent protocol` | 低 |
| ET FTP Banner | `21` + flow | banner 字符串 | 低 |
| ET 邮件上报 | `25` + within | 邮件头字符串 | 中 |
| GPL NETBIOS SMB | `445` + offset | `^.{27}` / 二进制字面量 | 泛匹配 |
| OISF traffic-id | TLS/HTTP | `debian.org`、`google.com` | 正常流量刷屏 |

另外 471 条二进制规则转换后变成字面量 `|xx|`，永远不可能命中，属于假覆盖。

### 1.3 修复

`server/cmd/rule_platform.go` / `rule_platform_suricata.go`：

- 保留原始元数据：`source_dest_port`、`source_flow`、`source_match_options`；
- 以下情况标记 `unsupported`：
  - 丢失端口/响应方向/offset/depth/within/byte_test/isdataat/urilen/threshold
    且特征 <12 位 → `lost_match_constraints`
  - 裸域名 → `bare_domain`
  - 常见词 → `common_token`
  - `contains` 含 `|` → `unrepresentable_binary_content`
  - 特征 <6 位 → `pattern_too_generic`
- 解析器版本 `2026-10-30.4`，同步时强制重建 bundle。

### 1.4 结果

`.125`：

```text
活动流量规则        531 -> 185
detection_rules     unsupported 1,097
  unrepresentable_binary_content  471
  pattern_too_generic             394
  lost_match_constraints          195
  missing_condition_field          18
  bare_domain                      14
  common_token                      3
  invalid_regex                     2
```

活动 bundle 中已无 <6 位特征、裸域名或二进制 `contains` 规则。

## 2. 默认规则降噪

### 2.1 下线

| 规则 | 原因 |
|---|---|
| `dpi-admin-access-default` | 内部用户访问 `/admin`、`/manager` 即告警 |
| `log-collector-heartbeat-default` | 心跳不是威胁事件 |

- 从 `default-bundle.json` 移除；
- `retiredDefaultDetectionRuleIDs` 在启动/同步时禁用旧库同名规则；
- loader 再次跳过。

### 2.2 收紧

```text
dpi-c2-domain-default:
  (?i)(^|\.)(malware|miner|ransom|stealer|botnet|c2)(\.|$)

log-privilege-escalation-default:
  (?i)(useradd|usermod|groupadd|groupmod|visudo|setcap|passwd\s+\S+|
       chmod\s+[0-7]*7[0-7][0-7]|chown\s+root|
       sudo:.*COMMAND=.*(useradd|usermod|passwd|visudo|chmod\s+777|chown\s+root|setcap))

runtime-suspicious-download-default:
  (?i)((curl|wget)[^|;]*https?://[^|;]*(\|\s*(sh|bash|python|perl)\b|
       -O\s+/(tmp|dev/shm|var/tmp)/))|
       (python[0-9.]*\s+-c\s+.*(urlopen|requests\.get))
```

验证：

- 普通 `pam_unix(sudo:session)`、`apt update` 不命中；
- `useradd`、`visudo`、`passwd root`、`chmod 777` 命中；
- 普通 `curl https://...` 不命中；
- `curl ... | bash`、`wget ... -O /tmp/...`、`python -c urlopen` 命中。

### 2.3 事件清理

```text
.125  dpi-admin-access-default         5 -> 0
.241  log-collector-heartbeat-default  155 -> 0
```

## 3. Suricata 检测

```text
.125 / .241  58 rules loaded, 0 failed, overlap_count=0
```

合成流量验证：

| 场景 | 结果 |
|---|---|
| SMB1 Negotiate 到 8080 | SID 9003024 命中 |
| 30 位随机标签 DNS 查询 ×6 | SID 1000050、9002003 命中 |
| `shell.php` 响应体含 `WScript.Shell` | SID 9004301 命中 |
| 正常 CDN 域名 / 普通 HTML | 不命中 |
| Fscan UDP 规则 | `dsize:0` 后只匹配空载荷探测 |

## 4. 安全引擎

```text
.125  active bundle 460 条，traffic 185
.241  active bundle 139 条，traffic 81
```

- 已无 retired 规则；
- 已无泛匹配转换规则；
- `.125` `threat_events = 0`；
- `.241` `threat_events = 637`（runtime / YARA / RASP / Sigma，非转换误报）。

## 5. RASP 主动防御

### 5.1 会话

```text
ds-799ff1e387adcd64ec655591
scope=agent  agent=.8
mode=block  dry_run=10s  duration=180s
dry_run -> active -> stopped
最终平台 mode=monitor, monitoring=true
```

### 5.2 请求结果（active 后）

| 请求 | HTTP |
|---|---|
| benign `/hello` | 200 |
| SQLi `UNION SELECT ... FROM` | **403** |
| XSS `<script>alert(1)</script>` | **403** |
| 路径穿越 `../../../../etc/passwd` | **403** |

RASP 事件：

```text
request-sqli-owasp-crs-942270        blocked=true
request-xss-owasp-crs-941110         blocked=true
request-path_traversal-owasp-crs-930110 blocked=true
```

### 5.3 停止回滚

```text
stop -> bridge block_on_hit=false 用时 2.2s
agent 请求侧立即恢复：SQLi 200
```

### 5.4 本次修复的探针缺陷

测试发现：策略变更后，第一个请求仍使用旧配置。

- 原因：探针只在“命中事件上报”时刷新 `/config`，且 reporter 延迟初始化；
- 修复：
  - `request_hook.inspect_request` 在判定模式前刷新配置；
  - 新增 `_ensure_reporter()`，首次请求即初始化；
  - `config_refresh_seconds` 默认 30s -> 5s。
- 复测：SQLi 首个请求即 403，停止后 2 次 SQLi 均为 200。

### 5.5 策略生效与回滚时延（已优化）

优化前：

```text
创建会话 -> block_on_hit=true  57.5s
stop     -> block_on_hit=false 24.7s
```

根因：

- Agent 配置轮询固定 30s；
- 防御调度器 tick 固定 30s；
- 探针 30s 才刷新一次配置。

修复：

- Agent 新增 `ConfigPollInterval`：
  - 默认 5s；
  - 支持 `AGENT_CONFIG_POLL_INTERVAL` / `agent.config_poll_interval`；
  - 测试实例设为 2s。
- 防御运行时 tick 改为 2s：
  - `DEFENSE_TICK_INTERVAL_SECONDS` 可调。
- 探针：
  - 请求判定前刷新 `/config`；
  - `config_refresh_seconds` 默认 2s。

优化后：

```text
创建会话 -> block_on_hit=true  8.3s（dry_run=5s）
创建会话 -> block_on_hit=true 约 13s（dry_run=10s）
stop     -> block_on_hit=false 2.2s
stop     -> SQLi 恢复 200      2.2s
```

其中 dry-run 是人工设置的安全观察窗口；策略实际下发约 3s。

## 6. 运行时进程终止

在 `.8` 开启：

```text
RESPONSE_ENABLE_PROCESS_KILL=true
```

验证：

```text
测试进程 PID 793543（sleep 600）
response action: process_kill / L3
requested_by=user:1 -> pending_approval
approver=user:2 -> approved
dispatched_at 03:03:31
executed_at   03:03:32
result: verified=true, backend=signal, pid dead
```

L3 强制双人审批生效；测试用临时审批账号已删除。

## 7. 验收结果

```text
acceptance.py                 38/38
Go 规则转换/默认规则测试       通过
RASP request_hook/bridge 测试  31 passed
```

## 8. 风险与后续

1. 手动阻断与停止回滚已优化到秒级（见 5.5）：Agent 配置轮询默认 5s、
   防御调度 tick 2s、探针刷新 2s，均可通过环境变量调整。
2. 大规模 Agent 场景需要评估 5s 配置轮询的服务端压力；可按环境调大，
   或后续改为服务端推送。
3. `process_kill` 需要显式环境变量，且 L3 双人审批；部署文档需注明。
4. `.241` 交通会话接口曾出现一次 33s 超时（Redis 100% CPU），重试恢复；需要跟踪 Redis 负载。
5. 强特征但丢失方向的规则仍保留（如 `ActiveXObject`），需继续观察误报。

## 9. 拓扑与 Agent 视图清理（2026-10-30）

### 9.1 拓扑

- `10.1.18.241`：管理/分析平台，不安装 Agent，不启用本地抓包。
- `10.1.18.125`：抓包镜像环境，`mirror0` 接真实镜像流量；检测升级在本机验证。

### 9.2 清理 sensor-241

历史遗留的本地探针记录被当成 Agent：

```text
agents             1 条 (sensor-241 / lyprobe-1.0.0)
hosts              1 条 (10.1.18.241)
agent_identities   3 条 (含旧的 0cf8... / 05126...)
threat_events      3 条 CRUD 事件
```

处理：

- 先备份到：
  - `agents_removed_backup_20261030`
  - `hosts_removed_backup_20261030`
  - `agent_identities_removed_backup_20261030`
  - `threat_events_fp_backup_20261030`
- 删除上述记录；
- `.241` 停止 `ly-local-mirror`，并在 compose override 中设置
  `profiles: ["capture"]`，默认不再启动；
- 不再把 `.241` 作为受害资产或 Agent 展示。

### 9.3 Agent / Sensor 分离

- `agents` 表新增 `kind`：
  - `agent`：真实受管终端；
  - `sensor`：本地抓包/探针。
- 启动时把历史 `lyprobe%` 记录迁移为 `sensor`；
- `/api/v1/agents` 默认只返回 `kind='agent'`；
- `include_sensors=1` 仅用于诊断。

### 9.4 验证

```text
.241 agents: 只有 ubuntu / 10.1.18.8 / online
.241 hosts:  只有 ubuntu
.241 10.1.18.241 相关 threat_events: 0
.125 无 agent；ly-local-mirror 抓 mirror0 正常
acceptance.py: 38/38
```

## 10. 10.1.18.125 升级为生产测试环境

### 10.1 定位

- `10.1.18.241`：管理/分析平台，不做抓包、不跑检测测试。
- `10.1.18.125`：抓包镜像环境，后续所有检测、规则、RASP 控制面测试都在这里。

### 10.2 升级内容

- `server:v67`
- `frontend:v46`（当前最新前端构建）
- 同步完整规则源：
  - `rules/scenarios/server-zone.yaml`
  - `rules/suricata/*.rules`
  - `rules/ly-custom/*.rules`
  - `rules/security-engine/default-bundle.json`
- 在 `.125` 重新导出流量规则：
  - Suricata 58 条
  - lyprobe 9 条
  - `overlap_count=0`
- Suricata 已重启并加载 58/58 条规则。

### 10.3 抓包

```text
mirror0: 28,430,974 包，持续增长
ly-local-mirror: healthy, iface=mirror0, engine=af_packet
```

### 10.4 验收

在 `.125` 上执行：

```text
acceptance.py: 38/38
/api/v1/traffic/rule-profile: 200
agents: 0（纯抓包环境，无受管 Agent）
```

后续检测升级、降噪验证、主动防御控制面测试统一使用
`https://10.1.18.125/`，不再使用 `.241` 做抓包测试。

## 11. 传感器基础镜像重建（10.1.18.125）

### 11.1 重建内容

```text
ly-flow/security-engine:v67
ly-flow/local-mirror:v68
ly-flow/suricata-profile:v67
```

- `security-engine`：用当前源码重新编译并替换 `/app/ly-security-engine`；
- `local-mirror`：用当前 Agent 源码重新编译并替换 `/app/ly-agent`；
- `suricata-profile`：打入当前 Suricata profile 和 58 条 server-zone 规则。

### 11.2 运行状态

```text
ly-server            ly-flow/server:v67
ly-security-engine   ly-flow/security-engine:v67
ly-local-mirror      ly-flow/local-mirror:v68
ly-suricata-sensor   ly-flow/suricata-profile:v67
```

- 9/9 服务 healthy；
- Suricata 58/58 规则加载；
- local-mirror 抓 `mirror0`，af_packet；
- `mirror0` 31,333,019 包，持续增长；
- `threat_events = 0`；
- `.125` `acceptance.py`：38/38。

### 11.3 Agent 签名与密钥更新

已生成新的 Ed25519 release key，并完成签名：

```text
/opt/lyflow/keys/agent-release.key        # 构建机，权限 600
agent-integrity-root.pem                  # 公钥 root
agent-binary.digest.json                  # 新 Agent 二进制签名
agent-config.digest.json                  # agent.yaml 签名
```

已更新：

- `10.1.18.8`：新 Agent 二进制 + 新 root + binary/config digest；
  - `AGENT_REQUIRE_BINARY_INTEGRITY=true`
  - `AGENT_REQUIRE_CONFIG_INTEGRITY=true`
  - 服务 active，RASP bridge 200。
- `10.1.18.125`：`local-mirror:v68` 内置同一套签名文件，
  完整性校验开启，不再使用 `AGENT_REQUIRE_BINARY_INTEGRITY=false`。

注意：私钥只保存在构建机 `/opt/lyflow/keys/`，需要纳入离线备份与权限管理，
不得进入仓库或镜像。

## 12. 抓包运行观测（2026-10-30 04:30 UTC）

### 12.1 采集

```text
mirror0 速率     约 956 pps / 690 KB/s（3.45 MB / 5s）
累计收包         32,025,044
累计丢包         652（约 0.002%）
```

服务：

```text
9/9 healthy
ly-local-mirror:v68
ly-suricata-sensor:v67
58/58 规则加载
```

### 12.2 平台数据

```text
traffic_sessions 总量      605,497
最近 15 分钟会话           13,017
协议                       TCP 11,376 / UDP 1,622 / ICMP 19
Top 目的端口               80(2810)、27074(1328)、53(954)、443(908)
Top 源 IP                  10.1.0.192、10.1.18.252、202.205.184.10、10.5.10.17
threat_events              0
incidents                  0
```

EVE 窗口（约 26 分钟）：

```text
230,951 行
DNS 123,874 / flow 104,791 / TLS 1,348 / HTTP 929 / alert 9
app_proto: dns 82,106、unknown 17,053、ntp 2,326、tls 1,391、http 566
```

### 12.3 发现并修复的误报

1. 华为云 WAF 域名：

```text
b5b249a2d117470a9e68f2cb0f8c9fec.vip1.huaweicloudwaf.com
8f3e92242907409283b227f30df72257.vip1.huaweicloudwaf.com
```

被 `1000050` / `9002003` 判为 DNS 隧道。已在两条规则的 `dns.query`
中增加 `content:!"huaweicloudwaf.com"`。

2. 瑞星升级包：

```text
10.3.10.69 -> download.rising.com.cn
GET /rsnetverdl/.../vlstd_cfg.zip
```

被 `1000041 ET MALWARE Suspicious Download` 命中。原规则只匹配
`http.host` 包含 `download` 且 URI 以 `.zip` 结尾，所有软件更新都会触发。
已改为只匹配“目标是裸 IP 的 exe/zip 下载”：

```text
http.host; pcre:"/^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?$/"
```

### 12.4 修复后

```text
90 秒窗口：EVE 8,886 行，alert 0
huaweicloudwaf DNS 事件 4 条，alert 0
```

### 12.5 容量观察

```text
load average: 10.52 / 7.29 / 6.64（4 vCPU）
磁盘: 21G/38G (54%)
内存: 3.4G used / 7.9G
```

抓包链路正常，但 CPU 负载偏高，后续需要关注 ClickHouse / Redis 与 EVE 轮转。

## 13. Suricata EVE 入库与小时轮转

### 13.1 为什么 UI 之前看不到

`local-mirror` 只负责抓包和写 flows/sessions，不运行 Agent 的 Suricata EVE
适配器。因此 Suricata 告警只存在 `eve.json`，没有进入 `threat_events`，
UI 上自然看不到。之前那 9 条告警就是在入库前被规则修复清掉的，不是 UI
延迟。

### 13.2 新增 EVE 入库

`server/cmd/suricata_eve_ingest.go`：

- 后台 tail `eve.json`；
- 只处理 `event_type=alert`；
- 生成稳定 `event_uid`（`suricata-<hash>`）；
- 写入 `threat_events`：
  - category=`traffic`
  - source_engine=`suricata`
  - 严重级别按 Suricata 1/2/3 映射 high/medium/low
  - 保留 DNS/HTTP/flow 原始字段
- 支持文件轮转和 truncate：inode 变化或文件变短时从 0 重新读取。

服务端已升级为 `server:v68`。

### 13.3 小时轮转

`/etc/logrotate.d/lyflow-suricata-eve`：

```text
hourly
rotate 48
compress
delaycompress
missingok
notifempty
copytruncate
```

systemd：

```text
lyflow-eve-rotate.timer  OnCalendar=hourly
lyflow-eve-rotate.service
```

保留 48 个小时文件，压缩后单文件约 20–30MB。

### 13.4 查询

- 告警：统一查 `threat_events` / UI，轮转不影响；
- 原始日志：

```bash
lyflow-eve-search 'pattern'
```

会同时搜索 `eve.json` 和 `eve.json.*.gz`。

### 13.5 验证

```text
synthetic alert -> threat_events 出现 suricata-<hash>
轮转后 eve.json=2.9M, eve.json.1=29M
轮转后 synthetic alert 仍可入库
lyflow-eve-search 可搜索 gz 历史
旧调试 EVE 已压缩，释放约 2GB，磁盘 47%
```

测试事件已删除，`threat_events` 恢复为 0。

## 14. 全面检修与生产测试就绪度

### 14.1 本轮发现并修复

1. `traffic_sessions` 没有保留策略：
   - 630,634 行 / 1.47GB，按当前速率约 4–5GB/天；
   - 新增 `TRAFFIC_SESSION_RETENTION_DAYS`，默认 7，`.125` 设为 3；
   - 已验证 10 天前的测试行会被删除。

2. EVE 入库在服务重启后从文件末尾开始，会漏掉停机期间的告警：
   - 新增 ingest state 文件，记录 path/inode/offset；
   - 重启后从上次 offset 继续；
   - 已验证重启前告警 A、重启后告警 B 各入库一次，无重复。

3. `.125` 之前没有把 `LYFLOW_RASP_ALLOW_BLOCK` 传入容器：
   - 已补 compose override；
   - `/api/v1/defense/status` 现在 `allow_production_block=true`。

4. `.125` 日志保留仍按 180 天：
   - 已设置 `LOG_RETENTION_DAYS=30`、`TRAFFIC_SESSION_RETENTION_DAYS=3`；
   - 服务端日志确认 `retention_days=30`、`traffic session retention days=3`。

### 14.2 已确认的正常项

```text
9/9 服务 healthy
components 非 ok = 0
Suricata 58/58
traffic_sessions 最新数据持续写入
traffic/threats API 200，Suricata 告警可查
Redis 流保留 2 小时，consumer lag 0
EVE 小时轮转 + gzip + 48 份
threat_events 0（当前无真实告警）
```

### 14.3 仍存在的限制

1. `capture` / `engine-health` 为空：
   - `local-mirror` 不是注册 Agent，不上报 sensor 健康；
   - 流量页、`mirror0` 收包、local-mirror 日志均正常，但“引擎健康”页看不到这个本地传感器。
2. `.8` Agent 仍注册在 `.241`：
   - RASP / defense 控制面测试目前走 `.241`；
   - 若要在 `.125` 做 RASP 测试，需要把 `.8` 迁移注册到 `.125`。
3. EVE 轮转使用 `copytruncate`：
   - 轮转瞬间可能丢少量原始 EVE 行；
   - 告警已先入 `threat_events`，不影响 UI 查询。
4. 保留窗口：
   - 原始 EVE 48 小时；
   - traffic_sessions 3 天；
   - threat_events 30 天。

### 14.4 结论

抓包、检测、告警入库、轮转、保留、UI 查询链路已经闭环，
可以进行生产测试。上述 14.3 属于可见性/测试拓扑限制，不是数据链路故障。
