# 引擎健康与误报审计（2026-10-30）

测试对象：`.241` 平台 + `.8` Agent。

## 1. RASP

- 策略：active v1 `monitor`，`enforcing=false`，fail-safe 开启。
- 保护状态：`detecting/monitor_only`，Agent RASP engine `running=true`。
- 统计：当天 102 allowed，0 blocked，`by_attack_type` 为空（只有心跳/放行，没有真实攻击事件）。
- 请求级能力：`ly_rasp` 单元测试与真实 WSGI 验证通过：
  - monitor 放行；
  - dry-run `would_block=true`；
  - block 抛 `RASPRequestBlocked`，真实 HTTP 403。
- 平台事件链路已打通：
  - `telemetry:rasp` 收到 `rasp.sql` 事件，`rule_id=request-sqli-owasp-crs-942270`；
  - `/api/v1/rasp/events` 默认已过滤 heartbeat，可直接看到真实攻击事件；
  - 自动 reporter 在只有 middleware、没有 `enable()` 的应用中也会懒初始化。
- 缺口：
  - PHP/Java/Node/.NET 探针未接真实业务应用，覆盖不全面。
  - Agent `RASP_ENABLED=false` 启动，由签名策略激活；文案上容易误解，建议后续显式打开。

## 2. Runtime

- 24h 事件：464 条，全部是 `component.alert`。
- 主要噪声：
  - `new process observed: kworker/...`、`agetty`、`ps` 等；
  - `authentication signal detected: root-login` 来自管理员 SSH 登录。
- 已修复：
  - `processDeltaCollector` 默认丢弃 `low/new-process`，只保留 medium/high 可疑进程。
  - `authLogCollector` 不再把“成功 root 登录”作为 runtime 告警；失败/异常登录仍保留。
- 仍建议：
  - 如果 eBPF backend 可用，优先 eBPF，procfs delta 只做兜底。
  - 对 `kworker`/`ksoftirqd`/`rcu_*` 做硬编码排除，即使未来恢复 low 事件。

## 3. YARA

- 引擎：YARA 4.5.5，已安装；内置 17,691 条规则。
- 原问题：
  - 只扫描 `/opt/ly-agent/yara/scan` 自测目录；
  - `engine-health` 显示 `running=false`；
  - 最近事件只有自测标记。
- 已修复：
  - `YARA_SCAN_PATHS` 扩展为
    `/opt/ly-agent/yara/scan,/tmp,/var/tmp,/dev/shm,/var/www,/usr/local/bin,/root,/home`；
  - 扫描周期 3600s，超时 300s；
  - 扫描启动日志显示新路径；
  - 已实测扫描到 `/tmp` 文件。
- 噪声处理：
  - 扫描 `/tmp` 时命中了自己的 YARA 规则源码（`/tmp/yara-src`），已删除该构建缓存；
  - 建议增加“跳过 `*.yar/*.yara`”或规则仓库目录，避免规则文件自匹配。
- 缺口：`running=false` 仍表示“没有独立 YARA 进程”，实际按周期在 Agent 内执行；前端文案需要区分“已安装/周期扫描中”。

## 4. 日志审计

- 采集：auth.log、nginx access/error（`LOG_SOURCES`），24h 约 1,962 条 log_audit 事件。
- 主要噪声：`SSH Root Login Log`，24h 1,707 条，其中 1,325 条来自管理员 IP `10.18.3.67`。
- 已修复：
  - 从默认 bundle 移除“成功 root 登录”规则；
  - DB 中 `log-ssh-root-login-default` 置为 disabled；
  - 重新编译并激活 bundle（619 → 618 条，log_audit 10 → 9）；
  - 实测成功 SSH 登录不再产生新事件。
- 保留：`log-ssh-failure-default`，覆盖 failed password / invalid user / auth failure。
- 仍发现：同一行 auth.log 曾产生多次不同 message_id 的重复事件，建议按源日志时间戳+行哈希去重。

## 5. XDR

- 24h：1000 alerts，8 条 active chain，posture high/76。
- 来源：`ly-security-engine` 997，`dpi_engine` 3。
- 主要噪声来自 SSH root login 和 runtime process delta；两项已收敛。
- 规则同步审计 bug：`rule.source.discover.attempt` 的 resource 为空，导致
  `controlaudit: incomplete audit entry`。已修复服务端 version 回填（server v59）。
- 仍需观察：修复后 24h 的 incident 数量、重复 chain、证据链完整性。

## 6. 规则库同步

实测（2026-10-30）：

| 源 | 结果 | 内容 hash |
|---|---|---|
| ET Open | 200 unchanged | `c6234647c8c9...` |
| Falco | 200 unchanged | `30a1a60263ab...` |
| Sigma | 200 unchanged | `8e0302ef07ea...` |

说明：

- 上游可达，fetch/hash/compare 链路正常；
- 内容未变时正确返回 `unchanged`，不会重复激活 bundle；
- 同步失败时原因为审计条目缺少 `resource`，已修复；
- 下一次上游内容变化时需要再验证一次真实 `activated=true`。

## 7. 结论

| 引擎 | 工作 | 全面性 | 结论 |
|---|---|---|---|
| RASP | 是（monitor） | 部分 | 请求级能力已验证，业务应用/多语言覆盖不足 |
| Runtime | 是 | 噪声已降 | 仍有 eBPF 回退和系统进程噪声风险 |
| YARA | 是（周期扫描） | 已扩展 | 扫描路径已扩展到高风险目录 |
| 日志审计 | 是 | 较好 | SSH 成功登录噪声已移除，仍有重复事件 |
| 规则同步 | 是 | 较好 | 上游 fetch/hash/unchanged 正常，待真实变更激活 |

## 8. 待办

1. ~~解决 `.8` 到 `.241:6379` 的 Redis 可达性~~：已加 `socat` 代理
   `10.1.18.241:16379 -> 127.0.0.1:6379`，iptables 仅放行 `10.1.18.8`；
   Agent 已配置 `REDIS_SERVER/REDIS_PASSWORD`，RASP health store 不再报错。
2. 用真实业务应用验证 PHP/Java/Node/.NET RASP 探针。
3. 为 YARA 增加规则源码/二进制自匹配排除。
4. 日志事件按源时间戳去重。
5. 等上游规则变更时验证一次 `activated=true`。
6. 清理旧的 `v2.corrupt.*` spool 备份（已保留，未删除）。
