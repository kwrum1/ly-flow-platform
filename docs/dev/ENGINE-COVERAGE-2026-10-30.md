# 引擎覆盖与健康审计报告（2026-10-30）

> 审计对象：平台 `https://10.1.18.241`（server v60）+ Agent `10.1.18.8`
> 审计方式：只读 API、PostgreSQL、ClickHouse、Redis、Agent `/proc` / journal / 本地扫描结果。
> 审计时间：平台 UTC `2026-10-29T17:13:08Z`（Agent 本地 CST `2026-10-30 01:13`）。
> 24h 窗口：`2026-10-28T17:13Z` ~ `2026-10-29T17:13Z`。
> 约束：未修改策略、配置、代码，未部署，未重启任何服务，未执行 git commit；报告中的凭据均已省略。

---

## 0. 结论摘要

| 引擎 | 当前状态 | 24h 真实事件 | 覆盖结论 | 主要风险 |
|---|---|---:|---|---|
| RASP | monitor，Python 探针 | 2 条 `rasp.sql`（其中 1 条是 `test`） | 基本只有心跳，语言仅 Python | 统计失真、告警未产出、多语言未验证 |
| Runtime | procfs delta（非 eBPF/auditd） | 464 条，全部 `component.alert` | 已实际停摆（最后 11:22Z） | 98.5% 噪声、0 条规则命中、健康页缺失 |
| YARA | 4.5.5，周期扫描 | Agent 侧 1046 次命中 | 大量规则源码自匹配 | 自匹配误报、命中未进入平台事件 |
| 日志审计 | auth.log + nginx | 2016 条（后降至 297 条） | 采集面可用，但链路不稳 | 重复采集、SSH 成功登录不可见、heartbeat 断流 |
| Traffic | sensor-241（离线） | 66 条告警 | 依赖离线 Agent | 在线 Agent 未开 traffic，归属不一致 |
| Artifact | 规则存在，事件为 0 | 0 | YARA 结果未落地 | 检测结果不可用 |

**总体判断：引擎“在线”不等于“有效覆盖”。** 当前最严重的问题不是引擎没启动，而是日志采集器重复启动导致重复事件与 FD 泄漏、Runtime 实际停摆且全是噪声、RASP/YARA 的检测结果没有进入统一事件链路。

---

## 1. 健康 API 快照

所有请求均返回 HTTP 200（登录后 Bearer Token 调用，凭据未落盘/未打印）。

| API | 关键结果 |
|---|---|
| `/api/v1/engine-health` | 仅 6 条：`suricata` / `yara` / `rasp` × 2 个 Agent；**无 runtime、log_audit、artifact** |
| `/api/v1/debug/components` | PostgreSQL/Redis/备份正常；`alerts:rasp=0`、`alerts:runtime=0`；capture `degraded/loss_unknown` |
| `/api/v1/rasp/stats` | `allowed=124`、`blocked=0`、`by_attack_type={}`、`by_language={}` |
| `/api/v1/rasp/events?limit=200&include_heartbeat=1` | `total=124`：122 条 heartbeat + 2 条 `rasp.sql` |
| `/api/v1/rasp/protection/status` | `mode=monitor`、`enforced=false`、`policy_signed=false`、`state=detecting`、`language=""` |
| `/api/v1/rules/stats` | 676 条规则：traffic 585、rasp 16、log_audit 9、runtime 6、artifact 2、xdr 58 |
| `/api/v1/rule-platform/yara` | 17,691 条内置规则、2,226 个文件、`imported=false`、`imported_rules=0`、更新于 2026-10-21 |
| `/api/v1/agents?limit=500` | `.8` online（rasp=true，hids=false，traffic=false）；`sensor-241` offline（traffic=true） |

`/api/v1/engine-health` 的实际返回（节选）：

- `.8 / suricata`：`state=disabled`、`installed=false`、`last_event_at=null`
- `.8 / yara`：`state=installed`、`running=false`、`last_event_at=2026-10-29T16:49:38Z`
- `.8 / rasp`：`state=running`、`running=true`、**`last_event_at=null`**（但 RASP 实际有 124 条事件）
- `sensor-241`：三个引擎均 `not_installed`，最后心跳 `2026-10-29T14:24:19Z`

---

## 2. 最近 24h 各引擎事件量

> 说明：平台事件表 `threat_events` 在审计期间发生过一次明显的行数变化（见 §7、B6），下表给出两个时点快照。Redis Stream 长度为累计深度，不是严格 24h 计数，仅用于判断链路是否有流量。

### 2.1 总量

| 类别 | PG 快照 A（16:57Z） | PG 快照 B（17:15Z） | Redis telemetry / alerts | 备注 |
|---|---:|---:|---|---|
| log_audit | 2,016 | 297 | 17,323 / 160 | 快照间减少 1,719 行 |
| runtime | 464 | 464 | 792 / 0 | alerts:runtime 为空 |
| rasp | 0 | 0 | 118 / 0 | 真实事件只在 telemetry，未进威胁表 |
| traffic | 66 | 66 | 16,172 / 2,596（alerts:dpi） | 流量会话 128,112 |
| artifact | 0 | 0 | 无独立流 | 仅 1 条 legacy YARA 事件 |
| **合计** | **2,546** | **827** | — | 审计期间减少 1,719 行 |

ClickHouse 事件存储（17:10Z 查询）：

| 表 | 行数 |
|---|---:|
| `lyflow.lyflow_events_v2` | 0 |
| `lyflow.lyflow_security_events` | 0 |
| `lyflow.lyflow_events_1m` | 0 |
| `lyflow.lyflow_events_1h` | 0 |
| `lyflow.lyflow_traffic_sessions` | 128,112 |

即：统一事件/安全事件的 ClickHouse 主存储为空，当前 24h 统计实际依赖 PG `threat_events` + Redis Stream，缺少可审计的 1m/1h 汇总。

### 2.2 log_audit（按 event_type / rule）

快照 A（2,016 行）：

| event_type | rule | 数量 | 说明 |
|---|---|---:|---|
| `log.auth` | `<none>`（未打规则） | 1,336 | 绝大多数是重复采集的 `Accepted password` |
| `SSH Root Login Log` | `log-ssh-root-login-default`（旧链路） | 383 | 最后一条 08:48:37Z |
| `Log Collector Heartbeat` | `log-collector-heartbeat-default` | 153 | 最后一条 16:49:43Z |
| `log.auth` | `log-privilege-escalation-default` | 48 | sudo/systemd-run 等 |
| 5 个 Sigma 规则 | `sigma-*` | 96 | 各 19~20 条，集中在 07:58Z |

快照 B（297 行，重复行被清理后）：

| event_type | rule | 数量 |
|---|---|---:|
| `Log Collector Heartbeat` | `log-collector-heartbeat-default` | 153 |
| `log.auth` | `log-privilege-escalation-default` | 48 |
| 5 个 Sigma 规则 | `sigma-*` | 96 |

### 2.3 runtime（按 event_type / 进程）

| 维度 | 结果 |
|---|---|
| event_type | `component.alert` 464 条（唯一分组） |
| `rule_id` | 空（464/464） |
| 进程 Top | `kworker/*` 211、`agetty` 113、`ps` 99、空名称 34、`systemd` 3、`(sd-pam)` 2、`python3` 1、`yara` 1 |
| 噪声占比 | `kworker + agetty + ps + 空名称 = 457/464 = 98.5%` |
| 时间范围 | 07:53:19Z ~ 11:22:27Z（此后无新 runtime 事件） |

### 2.4 rasp（按 event_type / rule）

| event_type | rule_id | 数量 | 语言 | 严重度 |
|---|---|---|---:|---|
| `rasp.protection.heartbeat` | — | 122 | 无 | — |
| `rasp.sql` | `request-sqli-owasp-crs-942270` | 1 | python | critical |
| `rasp.sql` | `test` | 1 | python | high |

心跳时间范围：`15:01:24Z ~ 17:12:34Z`（约 1 条/分钟）。两条真实事件均在 `16:51Z`，其中第二条的 `rule_id` 字面值就是 `test`，属于自测/演示数据。

### 2.5 traffic（按 rule）

| rule | 数量 |
|---|---:|
| `et-open-2002952` (ET P2P TOR) | 21 |
| `et-open-2008021` (Turkojan C&C) | 9 |
| `et-open-2011487` | 8 |
| `et-open-2010642` | 8 |
| `et-open-2101412` (GPL SNMP public) | 5 |
| `et-open-2101990` (GPL CHAT MSN) | 4 |
| `et-open-2010495` (Adobe) | 4 |
| `CRUD` | 3 |
| `et-open-2008027` | 2 |
| `et-open-2011485` | 2 |

注意：这些告警归属 `sensor-241`，而该 Agent 当前 `offline` 且 `suricata=not_installed`；在线 Agent `.8` 的 `traffic_enabled=false`。

### 2.6 artifact

- `threat_events`：0 条。
- `lyflow_event_storage_events`：仅 1 条 `adapter.yara` 的 legacy `component.alert`（08:53:51Z，`/opt/ly-agent/yara/scan/selftest-marker.txt`）。
- 对比 Agent 侧 1,046 次 YARA 命中：**检测结果基本没有进入平台统一事件链路**。

---

## 3. RASP 审计

### 3.1 是否只有 heartbeat？

不是“只有”，但真实检测极少：

- 124 条事件中 **122 条是心跳**，只有 2 条 `rasp.sql`。
- 2 条真实事件都在 `2026-10-29T16:51Z`，且第 2 条 `rule_id=test`、`evidence=test`，是测试注入。
- 因此可认为：**过去 24h 没有可复现的真实业务攻击样本**，只有 1 条 CRS SQLi 演示事件 + 1 条 test。

### 3.2 覆盖语言

| 探针 | 已安装 | 观察到的事件 |
|---|---|---|
| Python | 是（`/opt/ly-agent/rasp/python/`） | `rasp.sql`，`language=python` |
| PHP | 是（`ly_rasp_prepend.php`） | 0 |
| Java | 是（`ly-rasp-agent.jar`） | 0 |
| Node.js | 是（`ly_rasp.js`） | 0 |
| .NET | 是（`LyRaspProfiler.dll`） | 0 |

Agent 上实际只有 `networkd-dispatcher` / `unattended-upgrade` 等 Python 系统进程，没有 Java/Node/PHP/.NET 业务进程；RASP 心跳中的 `applications` 只有 `generic-local-bridge`。结论：**当前仅验证了 Python 桥接，其他语言只是“文件已安装”，没有真实应用覆盖**。

### 3.3 统计接口失真（真实 bug）

`/api/v1/rasp/stats` 返回：

```json
{"allowed":124,"blocked":0,"by_attack_type":{},"by_language":{},"today_events":124,"total_events":124}
```

但同一时刻 `/rasp/events` 明确有 `language=python` 和 `severity=critical` 的 `rasp.sql`。原因是 `server/cmd/main.go:8895-8908` 用 `xdrPickString(e,"language")` / `xdrPickString(e,"attack_type")` 读取顶层字段，而真实事件把 `language`、`rule_id`、`severity` 放在 `fields` 下；同时循环没有排除 `rasp.protection.heartbeat`，导致 122 条心跳全部计入 `allowed`。

### 3.4 告警链路缺失

- Redis：`telemetry:rasp` 118 条，`alerts:rasp` **0** 条。
- 安全引擎已消费（`lag=0`），但没有任何 RASP 告警输出。
- 1 条 `critical` 的 `UNION SELECT password FROM`（`request-sqli-owasp-crs-942270`）没有进入 `threat_events`，`/api/v1/threats/rasp` 返回 `total=0`。

### 3.5 保护状态与控制健康

`/api/v1/rasp/protection/status`：

- `mode=monitor`、`enforced=false`、`policy_signed=false`、`fail_safe_on_unknown=true`
- `state=detecting`、`state_reason=monitor_only`、`status=protected`
- `language=""`

122 条心跳的 `control_health.status`：

- `degraded` 115 条，`healthy` 仅 7 条
- 原因：`health_store_unavailable` 76、`observation_delivery_unavailable` 20、`authorization_failed` 19
- 最新心跳（17:12:34Z）仍为 `degraded / observation_delivery_unavailable`

即：RASP 对外显示 `protected`，但控制健康长期降级；`engine-health` 的 `last_event_at=null` 也与 124 条实际事件矛盾。另有 `output_path=/opt/ly-agent/rasp/events.jsonl`，但该文件在 Agent 上不存在。

---

## 4. Runtime 审计

### 4.1 采集机制：procfs，不是 eBPF / auditd

`threat_events.raw_event.metadata` 明确：

```json
{"collector":"procfs-process-delta","source":"agent-runtime-monitor",
 "signal":"new-process","source_evidence":"procfs-process-delta",
 "capability_status":"active"}
```

Agent 配置：`runtime.backend=auto`、`centos7_fallback=auditd`，内核为 `7.2.4-x64v3-xanmod1`。代码在 eBPF 不可用时回退：

- `agent/cmd/main.go:2932`：`newEBPFProcessCollector()` 返回 nil 时尝试 auditd；
- 再失败则 `newProcessDeltaCollector()`（procfs）；
- 代码中已有 `full_ebpf_program_loader_not_implemented`、`auditd_backend_not_available_or_not_configured` 的回退原因。

结论：**当前是 procfs `ps` 轮询差分，不是 eBPF，也不是 auditd。**

### 4.2 噪声是否仍在

仍在，而且占绝大多数：

| 进程 | 数量 | 占比 |
|---|---:|---:|
| `kworker/*` | 211 | 45.5% |
| `agetty` | 113 | 24.4% |
| `ps` | 99 | 21.3% |
| 空名称 | 34 | 7.3% |
| `systemd` / `(sd-pam)` / `python3` / `yara` | 7 | 1.5% |

`agetty` 的 cmdline 是 `--noreset --noclear ... vt220`，`ps` 的 cmdline 是 `ps -eo pid,user,comm,args`，`kworker` 是内核线程；这些都不应作为安全告警。464 条事件 `rule_id` 全为空，说明 Runtime 的 6 条规则没有命中任何一条。

### 4.3 当前是否还在跑

- 最后一条 runtime 事件：`2026-10-29T11:22:27Z`；审计时平台时间 `17:13Z`，已停约 5 小时 50 分钟。
- `telemetry:runtime` 仍有 792 条，但最近一条是 `control.health`（17:01:40Z），`reason=observation_delivery_unavailable`、`status=degraded`。
- Agent `.8` 的 `agents.hids_enabled=false`（`/api/v1/agents`），Runtime 实际被策略关闭。
- `engine-health` 根本没有 runtime 这一项，无法从健康页看出“已停摆”。

---

## 5. YARA 审计

### 5.1 平台侧规则

`/api/v1/rule-platform/yara`：

- `builtin_rules=17691`
- `files=2226`
- `size_bytes=20,988,216`
- `imported=false`、`imported_rules=0`
- `updated_at=2026-10-21T08:52:34Z`
- Agent 侧 `/opt/ly-agent/yara/rules.yar` 5.7MB，YARA 4.5.5

### 5.2 最近扫描与命中

Agent `last-scan.json`（JSONL，1,046 行，全部 `scan_status=matched`）：

- 时间范围：`2026-10-29T05:03Z ~ 16:49:38Z`
- 唯一文件 266 个，唯一 hash 261 个
- 最近一次扫描：`2026-10-29T16:49:38Z`，28 条命中
- 单次最大扫描：`2026-10-29T16:02Z`，1,000 条命中
- **1,026/1,046 条命中位于 `/tmp` 下**
- **1,017/1,046 条命中的文件是 `.yar/.yara` 规则源码**

命中最多的文件：

| 文件 | 命中数 |
|---|---:|
| `/tmp/yara-src/rules/yara/thor-webshells.yar` | 291 |
| `/tmp/yara-src/rules/yara/thor-hacktools.yar` | 101 |
| `/tmp/yara-src/rules/yara/apt_eqgrp_apr17.yar` | 33 |
| `/opt/ly-agent/yara/scan/selftest-marker.txt` | 20 |
| `/tmp/yara-src/rules/yara/apt_fvey_shadowbroker_dec16.yar` | 20 |
| `/tmp/yara-src/rules/yara/gen_empire.yar` | 18 |

### 5.3 规则源码自匹配：确认存在

Agent 配置：

```text
YARA_SCAN_PATHS=/opt/ly-agent/yara/scan,/tmp,/var/tmp,/dev/shm,/var/www,/usr/local/bin,/root,/home
```

最近一次扫描的命中样本：

```json
{"file_path":"/tmp/yara-file-2r2brw7g/one.yar","rule":"WEBSHELL_ASP_Generic"}
{"file_path":"/tmp/yara-src/rules/yara/thor-webshells.yar","rule":"WEBSHELL_PHP_Generic_Callback"}
{"file_path":"/tmp/build_yara.py","rule":"LyFlow_YARA_Selftest_2026"}
{"file_path":"/tmp/yara-check-x5k2noma/one.yar","rule":"WEBSHELL_ASP_Nano"}
```

即 YARA 在扫描 `/tmp` 时命中了自己（以及其他构建缓存）的规则源码/构建脚本。`/tmp/yara-src` 当前已不存在，但 `/tmp/yara-file-*`、`/tmp/yara-check-*`、`/tmp/build_yara*.py` 仍在，最近扫描仍持续自匹配。此前 `docs/dev/ENGINE-HEALTH-2026-10-30.md` 声称“已删除构建缓存”，但当前环境仍复现，属于回归或清理不彻底。

### 5.4 命中没有进入平台事件

- Agent 侧 1,046 次命中；
- 平台 `artifact` 威胁 0 条；
- `lyflow_event_storage_events` 只有 1 条 YARA legacy 事件（selftest marker，08:53Z）；
- `alerts` / `threat_events` 中没有对应 YARA 命中。

因此 YARA 目前更像“本地扫描器”，而不是“平台检测引擎”。

---

## 6. 日志审计

### 6.1 采集哪些文件

Agent 进程环境（已脱敏）：

```text
LOG_SOURCES=nginx-access:/var/log/nginx/access.log,nginx-error:/var/log/nginx/error.log,auth:/var/log/auth.log
```

实际文件：

| 文件 | 大小 | 状态 |
|---|---:|---|
| `/var/log/auth.log` | 8.7 MB / 86k 行 | 主要数据源 |
| `/var/log/nginx/access.log` | 845 B | 很少 |
| `/var/log/nginx/error.log` | 80 B | 很少 |
| `/var/log/secure` | 不存在 | Runtime auth collector 配置了但为空 |
| `/var/log/messages` | 不存在 | Runtime auth collector 配置了但为空 |

结论：日志审计实际以 `auth.log` 为主，nginx 日志几乎没有流量；没有采集 syslog、应用日志、容器日志。

### 6.2 Heartbeat 是否正常

- `Log Collector Heartbeat` 共 153 条，最后一条 `2026-10-29T16:49:43Z`。
- Agent 在 `16:49:34Z` 重启；重启后至今（17:13Z）**没有新的 log collector heartbeat**，已断流约 23 分钟。
- Agent 自身 heartbeat 正常（`last_heartbeat=17:13:01Z`），说明不是 Agent 整体掉线，而是日志采集/心跳子链路问题。

### 6.3 SSH 成功登录是否还有新事件

- `auth.log` 中持续有成功登录：
  - `2026-10-30T00:53:12+08:00`（16:53Z）
  - `2026-10-30T01:06~01:12+08:00`（17:06~17:12Z）
- 平台 `threat_events` 中 `log.auth` 最后一条是 `16:42:43Z`；`SSH Root Login Log` 最后一条是 `08:48:37Z`。
- 当前 active bundle 的 9 条 `log_audit` 规则中**没有 `log-ssh-root-login-default`**，只有 `log-ssh-failure-default`、`log-privilege-escalation-default`、5 条 nginx、heartbeat、1 条 Sigma。

结论：**SSH 成功登录在平台侧没有新事件**。这是此前“降噪”主动移除成功登录规则的结果；但如果仍需要“谁在何时登录成功”的审计能力，目前是覆盖缺口，而不是单纯降噪。

### 6.4 重复 message_id / 重复事件

严格按 `message_id`：

- 快照 A：`threat_events` 2,546 行，`count(distinct raw_event->>'message_id')=2546`，**没有重复 message_id**。
- 快照 B：827 行，827 个唯一 message_id。

但语义重复非常严重：

- 快照 A 的 2,016 条 `log_audit` 只有 **36 个不同的 `details.message`**，重复行 1,980 条。
- 其中 `Accepted password` 1,336 条，同一条日志被反复写入；一条消息最多出现 **127 次**，且对应 127 个不同 message_id。
- 样例（同一条 auth.log）：

```text
created_at=13:53:01Z  mid=1793281981018-0  ...Accepted password for root from 10.18.3.67 port 10612
created_at=13:59:16Z  mid=1793282356448-0  同一行
created_at=14:00:18Z  mid=1793282418125-0  同一行
created_at=14:01:17Z  mid=1793282476611-0  同一行
created_at=15:10:44Z  mid=1793286640955-0  同一行
created_at=15:11:16Z  mid=1793286665314-0  同一行
```

根因在 Agent：

- `agent/cmd/log_sources.go:206` 用 `now.UnixNano()` 生成事件 ID，不带文件 inode/offset/行 hash；
- 每次重读同一行都会得到新 ID，服务端无法去重；
- `agent/cmd/main.go:497` 的 `go a.runLogSources()` 没有 “已启动” 保护，而 `startManagedCollectors()` 会在每次配置应用时被调用（`main.go:920`、`rasp_policy.go:156`）。

### 6.5 采集器重复启动与 FD 泄漏（Critical）

证据：

- journalctl 中 `[log] native collectors active: 3 source(s)` **每 30 秒出现两次**（正常应只在启动时出现一次）。
- Agent 进程对同一个 `/var/log/auth.log` 保持 **93~95 个 fd**，16 秒内从 93 增到 95；进程总 fd 约 678~715。
- 同一行 auth.log 被多次发布（上文 127 次）。
- `startManagedCollectors()` 中 traffic/hids/rasp 都有 `started` 标志，唯独 `go a.runLogSources()` 没有。

这三点组合可以解释“重复事件 + FD 缓慢增长”：每次配置循环都会再启动一个 log collector goroutine，每个 goroutine 各自维护 offset，反复读取同一批日志并发布不同 ID。

### 6.6 日志告警链路停摆

- `telemetry:log_audit`：17,323 条，`lag=0`，最新 17:08:53Z。
- `alerts:log_audit`：160 条，最后一条 `2026-10-29T16:49:34Z`（heartbeat）。
- 新 `Accepted` 行在 telemetry 中存在（最近 600 条中有 14 条），但没有新 alert。
- 安全引擎在 15:16:21Z、16:08:51Z、16:38:30Z 三次因 `security-engine runtime CPU budget exceeded` 停止并重启；容器 `RestartCount=3`，最近启动 16:39:16Z。
- 引擎 `/health` 显示 `received=5154, alerts=466, dead_letters=0`，20 秒内 `received` 增加、`alerts` 只增加 4 条且没有进入 `alerts:log_audit`。

结论：日志 telemetry 正常，但 alert 输出自 16:49Z 起停摆，且与安全引擎的 CPU budget 重启时间线相关。

---

## 7. 真实 Bug / 覆盖缺口清单

> 严重级别：Critical > High > Medium > Low。以下均为审计发现，未做任何修复。

### B1 [Critical] Agent 日志采集器重复启动：重复事件 + FD 泄漏

**证据**

- `journalctl -u ly-agent`：`[log] native collectors active: 3 source(s)` 每 30s 出现两次。
- `/proc/<ly-agent>/fd`：`/var/log/auth.log` 93~95 个 fd，16s 内 +2；总 fd ~700。
- PG：2,016 条 log_audit / 36 个不同 message / 1,980 条重复；单行最多 127 次。
- 代码：`agent/cmd/main.go:497` 无保护地 `go a.runLogSources()`；`startManagedCollectors()` 在 `main.go:920` 和 `rasp_policy.go:156` 被反复调用；traffic/hids/rasp 都有 `started` 标志，log 没有。

**影响**：重复告警/重复入库、日志时间线失真、FD 与 goroutine 无界增长，长期可能触发 EMFILE 导致采集停止。

**建议修复点（不要直接改）**

1. 给 log collector 增加 `logStarted`/`sync.Once`，只在首次启动；配置变更只更新 offset/路径，不新建 goroutine。
2. 事件 ID 改为 `hash(path + inode + offset + raw_line)`，或在服务端按 `(agent_id, log_path, raw_message, source_timestamp)` 去重。
3. offset 持久化（inode + offset），处理 logrotate/truncate。
4. 增加 `ly_agent_log_collector_goroutines` / `open_fds` 指标和阈值告警。

### B2 [High] Runtime 实际停摆，且 98.5% 是噪声、0 条规则命中

**证据**

- `collector=procfs-process-delta`，不是 eBPF/auditd。
- 464 条全部 `component.alert`，`rule_id` 全空；`kworker 211 + agetty 113 + ps 99 + 空 34 = 457/464`。
- 最后事件 11:22:27Z；`agents.hids_enabled=false`。
- `/engine-health` 没有 runtime 项；`alerts:runtime=0`。
- `telemetry:runtime` 最新只有 `control.health degraded / observation_delivery_unavailable`。

**影响**：Runtime 既没有有效检测，也没有可见的健康状态；真实进程/提权/反弹 Shell 事件会被噪声淹没或被关闭。

**建议修复点**

1. `/engine-health` 增加 runtime（backend、enabled、last_event、rule_hits、noise_ratio）。
2. 硬排除 `kworker/*`、`ksoftirqd/*`、`rcu_*`、`agetty`、`ps`、空 comm；低危 new-process 不入告警，只入 telemetry 采样。
3. 明确 `hids_enabled=false` 的 UI 状态，避免“runtime 正常”的误解。
4. 修复 eBPF loader 或至少诚实标注 `full_ebpf_program_loader_not_implemented`。

### B3 [High] RASP 统计失真、告警不产出、语言覆盖不足

**证据**

- `/rasp/stats`：`allowed=124`、`by_attack_type={}`、`by_language={}`；实际 124 条中 122 条是心跳。
- 真实 `rasp.sql`（critical，CRS 942270）存在，但 `alerts:rasp=0`、`/threats/rasp total=0`。
- 仅 Python 有事件；PHP/Java/Node/.NET 只有探针文件，没有业务进程。
- 115/122 心跳 `control_health=degraded`（health_store_unavailable 76、observation_delivery_unavailable 20、authorization_failed 19）。
- `engine-health` 的 `rasp.last_event_at=null`；`output_path=/opt/ly-agent/rasp/events.jsonl` 不存在。

**建议修复点**

1. `raspStatsHandler` 从 `fields.language` / `fields.rule_id` / `fields.severity` 取值，并排除 heartbeat。
2. 将 RASP `rasp.sql` / `rasp.xss` / `rasp.command` 等接入 `alerts:rasp` → `threat_events`；至少 critical 必须产出。
3. 排除 `rule_id=test` 等自测数据，或在 UI 标注 demo。
4. 明确 `protected` 只在 `enforced=true` 时展示；monitor 显示 “检测中/未阻断”。
5. 为 PHP/Java/Node/.NET 接真实应用做 E2E，否则不要宣称全语言覆盖。

### B4 [High] YARA 规则源码自匹配 + 命中未进入平台

**证据**

- 1,046 条命中中 1,026 条在 `/tmp`，1,017 条是 `.yar/.yara`。
- `16:02Z` 单次扫描 1,000 条命中，主要来自 `/tmp/yara-src/rules/yara/*.yar`。
- 最近 `16:49:38Z` 仍命中 `/tmp/yara-file-*/one.yar`、`/tmp/yara-check-*/one.yar`、`/tmp/build_yara*.py`。
- `YARA_SCAN_PATHS` 包含 `/tmp,/root,/home`，没有排除规则目录/源码后缀。
- 平台 `artifact` = 0；只有 1 条 legacy selftest YARA 事件。

**影响**：误报洪水、扫描预算浪费；真正的恶意文件命中也无法在平台检索/告警。

**建议修复点**

1. 扫描排除 `*.yar`、`*.yara`、`/tmp/yara-src`、`/tmp/yara-check-*`、`/opt/ly-agent/yara`、构建缓存和 Agent 自身目录。
2. 将 Agent `last-scan.json` 的命中接入 `artifact` 事件/告警，增加 YARA→平台新鲜度指标。
3. 对 `LyFlow_YARA_Selftest_2026` 只允许在显式自测目录生效，禁止在 `/tmp`/`/root` 下命中。
4. 每次扫描输出“扫描文件数/跳过数/命中数/耗时”，便于发现自匹配。

### B5 [Medium] ClickHouse 统一事件存储为空，24h 汇总不可审计

**证据**

- `lyflow_events_v2=0`、`lyflow_security_events=0`、`lyflow_events_1m=0`、`lyflow_events_1h=0`。
- 只有 `lyflow_traffic_sessions=128,112`。
- 当前 24h 统计只能查 PG `threat_events`（且行数在审计中变化）和 Redis Stream。

**影响**：没有稳定的 1m/1h 聚合与历史检索；引擎覆盖率无法用统一事件表复算。

**建议修复点**：确认 v2/security_events 写入链路是否被关闭；补 migration/回填与写入健康检查；在 `/debug/components` 暴露各表行数与最新时间。

### B6 [Medium] `threat_events` 在审计期间从 2,546 行降到 827 行

**证据**

- 16:57Z：log_audit 2,016、runtime 464、traffic 66，合计 2,546。
- 17:15Z：log_audit 297、runtime 464、traffic 66，合计 827。
- 消失的 1,719 行主要是未打规则的 `log.auth` / `SSH Root Login Log` 重复行。
- `threatCategoryHTTPHandler` 每次 GET 都会调用 `scheduleThreatBackfill(cfg)`（`server/cmd/main.go:6976`），读请求可能触发后台重建。

**影响**：同一时间窗的“24h 事件量”不可重复；若无审计日志，无法判断是保留策略、去重还是数据丢失。

**建议修复点**：将 backfill/retention/dedupe 改为显式任务并记录审计；GET 不做写副作用；增加 `threat_events` 行数/删除量监控。

### B7 [Medium] 日志告警链路 16:49Z 后停摆，安全引擎反复因 CPU budget 重启

**证据**

- `alerts:log_audit` 最后 16:49:34Z；`telemetry:log_audit` 最新 17:08:53Z，`lag=0`。
- 新 `Accepted` 在 telemetry 中存在，但没有新 alert。
- 安全引擎 15:16:21Z、16:08:51Z、16:38:30Z 三次 `runtime CPU budget exceeded`；`RestartCount=3`。
- `/health` 显示 `received=5154, alerts=466`，20s 内 alerts 仅 +4，且未进入 log 流。

**影响**：日志审计“看起来有数据”，但告警不再产生；CPU budget 重启会丢事件/重置计数。

**建议修复点**：定位触发 CPU budget 的规则/大消息；提高或按规则配置预算；增加“telemetry 有增量但 alerts 长期无增量”的 freshness 告警；保存重启前后 offset/计数。

### B8 [Medium] SSH 成功登录在平台侧不可见（降噪后未补审计面）

**证据**

- active bundle 9 条 log 规则中没有 `log-ssh-root-login-default`。
- auth.log 在 16:53Z、17:06~17:12Z 有成功登录；平台 `log.auth` 最后 16:42Z，`SSH Root Login Log` 最后 08:48Z。
- `threats/log_audit` 当前只剩 heartbeat、privilege escalation、Sigma。

**影响**：安全团队无法在平台回答“谁在何时成功登录”。这是主动降噪的副作用，应明确为产品取舍。

**建议修复点**：保留一条低危、可节流的 “SSH session established” telemetry/审计事件（不升级为 incident），或提供登录成功查询视图；不要简单恢复高频告警。

### B9 [Medium] 引擎健康页只覆盖 3 个引擎，且状态与事实不一致

**证据**

- `engine-health` 仅 suricata/yara/rasp；无 runtime/log_audit/artifact。
- `rasp.last_event_at=null` 但实际 124 条事件。
- `yara.running=false` 但每小时扫描（一次性进程语义）。
- `sensor-241` offline/not_installed，却仍有 traffic 告警归属它。
- `.8` suricata disabled，但 traffic 引擎能力仍存在。

**建议修复点**：`engine-health` 统一覆盖 6 类引擎；`last_event_at` 从 telemetry 聚合而不是只读 agent capability；把“周期任务”和“常驻进程”区分展示；统一 sensor 身份。

### B10 [Low] 语义/文案问题

- RASP `status=protected` 但 `mode=monitor`、`policy_signed=false`、`enforced=false`。
- `output_path` 指向不存在的 `events.jsonl`。
- 心跳 reasons 中 `authorization_failed` 与 `health_store_unavailable` 长期存在。
- `Log Collector Heartbeat` 断流 23 分钟但无告警。

---

## 8. 建议优先级

| 优先级 | 项目 | 理由 |
|---|---|---|
| **P0** | B1 日志采集器重复启动 / FD 泄漏 | 正在产生重复数据，且资源无界增长；修复成本低、收益最大 |
| **P1** | B2 Runtime 停摆与噪声 | 引擎实际无效，健康页还看不到 |
| **P1** | B3 RASP 统计/告警/语言覆盖 | critical 事件不产告警，统计不可信 |
| **P1** | B4 YARA 自匹配与结果未落地 | 误报洪水，真实命中不可检索 |
| **P1** | B7 日志告警链路停摆 | 有 telemetry 无 alert，等于审计失效 |
| **P1** | B6 threat_events 行数骤降 | 数据可重复性/完整性风险，需先查清 |
| **P2** | B5 ClickHouse 事件表为空 | 影响长期检索与 24h 复算 |
| **P2** | B8 SSH 成功登录可见性 | 产品取舍，需明确 |
| **P2** | B9 引擎健康页覆盖 | 可观测性补齐 |
| **P3** | B10 文案/心跳告警 | 降低误判与运维困惑 |

---

## 9. 关键证据索引

### API

```text
GET /api/v1/engine-health                              200  6 items（仅 3 引擎）
GET /api/v1/debug/components                           200  alerts:rasp=0, alerts:runtime=0
GET /api/v1/rasp/stats                                 200  allowed=124, by_*={}
GET /api/v1/rasp/events?limit=200&include_heartbeat=1  200  124 = 122 heartbeat + 2 rasp.sql
GET /api/v1/rasp/protection/status                     200  monitor/enforced=false
GET /api/v1/rules/stats                                200  676 rules
GET /api/v1/rule-platform/yara                         200  17691 rules / 2226 files
```

### PostgreSQL

```sql
-- 24h 快照 A（16:57Z）
SELECT category, count(*) FROM threat_events GROUP BY 1;
-- log_audit 2016 | runtime 464 | traffic 66

-- 24h 快照 B（17:15Z）
-- log_audit 297 | runtime 464 | traffic 66

-- 重复内容（快照 A）
SELECT count(*), count(DISTINCT raw_event->'details'->>'message')
FROM threat_events WHERE category='log_audit';
-- 2016 | 36

-- 精确 message_id 唯一性
SELECT count(*), count(DISTINCT raw_event->>'message_id') FROM threat_events;
-- 2546 | 2546（快照 A）；827 | 827（快照 B）

-- Runtime 噪声
SELECT raw_event->'metadata'->>'name', count(*)
FROM threat_events WHERE category='runtime' GROUP BY 1 ORDER BY 2 DESC;
-- kworker* 211 | agetty 113 | ps 99 | <empty> 34 | systemd 3
```

### ClickHouse

```text
lyflow_events_v2        0
lyflow_security_events  0
lyflow_events_1m        0
lyflow_events_1h        0
lyflow_traffic_sessions 128112
```

### Redis

```text
telemetry:log_audit  17323   alerts:log_audit  160（最后 16:49:34Z）
telemetry:runtime      792   alerts:runtime      0
telemetry:rasp         118   alerts:rasp         0
telemetry:traffic    16172   alerts:dpi       2596
flows:raw           112904   events:xdr       2761
```

### Agent .8

```text
YARA last-scan 1046 条；1026 条在 /tmp；1017 条是 .yar/.yara
YARA 最近扫描 2026-10-29T16:49:38Z
RASP 122 条心跳：degraded 115 / healthy 7
日志采集器 fd：/var/log/auth.log 93~95 个
journalctl：[log] native collectors active: 3 source(s) 每 30s 两次
```

### 安全引擎

```text
15:16:21Z stopped: runtime CPU budget exceeded
16:08:51Z stopped: runtime CPU budget exceeded
16:38:30Z stopped: runtime CPU budget exceeded
RestartCount=3, StartedAt=16:39:16Z
/health: received=5154, alerts=466, dead_letters=0, bundle=db-active-20261029154745
```

---

## 10. 审计边界与未决事项

- 本次未修改 `.241` / `.8` 的任何配置、策略、规则、服务；未执行写操作，未提交代码。
- 审计期间观察到 `threat_events` 行数变化（2,546 → 827），可能与其他会话/后台 backfill/retention 有关；本报告保留两个快照，具体原因需结合服务端审计日志进一步确认。
- `docs/dev/ENGINE-HEALTH-2026-10-30.md` 中部分“已修复”结论与当前实测不一致（YARA 自匹配仍存在、RASP control health 仍 degraded），建议以本报告的实时证据为准并复核。
- RASP `rasp.sql` / `rasp.xss` 之外的攻击类型（命令执行、文件、HTTP）当前没有真实样本，覆盖率无法从现有数据证明。
