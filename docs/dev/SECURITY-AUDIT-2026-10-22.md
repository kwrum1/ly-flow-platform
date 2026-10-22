# 安全运营审计与修复记录

- 日期：2026-10-22
- 范围：资产命名、内网横向流量闭环、告警白名单、规则 ID 可读性、引擎健康降级、页面数据一致性

## 1. Agent / 资产重命名

- 资产详情抽屉新增“重命名”入口，可直接修改 Agent 显示名称。
- 名称限制 64 字符并校验重复、非法字符；保存后同步数据库和 Agent 名称映射。
- 目的：研判受害服务器时使用业务名称，而不是 `ubuntu`、`test8-final3` 这类主机名或 UUID。

## 2. 内网横向流量进入 Incident

- 单条中/高危内网流量告警不再因为“缺少第二阶段遥测”被丢弃。
- 对源/目的均为私网、包含 exploit/XSS/SMB/RDP/SSH/lateral 等特征的流量，生成“内网横向可疑流量”Incident。
- 证据来自持久化 `threat_events`，不再依赖瞬时 Redis 流。
- 修复规则 ID 为 `0` 的问题：优先使用 `component_rule_id`、`native_rule.id`，再回退到规则 ID；显示为真实 SID。
- 实际验证：`ET WEB_SPECIFIC_APPS ClarkConnect Linux proxy.php XSS Attempt`（`et-open-2010602`）已进入活动 Incident。

## 3. 告警白名单

- 规则中心新增“告警白名单”管理面板。
- 支持按规则、来源 IP、资产/实体添加 7/30/90 天抑制，必须填写原因。
- 支持查看生效条目和移除；移除后立即恢复检测。
- 与流量详情页的“标记误报并抑制”共用同一套 `xdr-response-policy`。

## 4. 引擎健康稳定性

- `engine-runtime/status` 在安全引擎健康接口短暂超时时不再返回 503。
- 返回部分引擎状态并标记 `degraded/errors`，避免规则中心、总览和引擎健康页因为一次健康超时出现接口错误。
- 总览和引擎健康页统一为 6 个引擎口径（安全引擎、Suricata、LyProbe、Wazuh、YARA、OpenRASP）。

## 5. 页面一致性

- 攻击链处置默认“未闭环”筛选修复：服务端返回 `active` 后，前端不再错误地按 `status=active` 二次过滤掉 `open` 记录。
- 总览 Incident 查询使用实时同步，活动 Incident 数量与攻击链页面一致。
- Agent 重命名、白名单操作均从当前页面即时刷新。

## 5.1 LyFlow 安全引擎 / LyFlow 探针异常

根因有两个：

- Redis 的 `flows:semantic` 和 `telemetry:traffic` 长期未清理，占用约 5.4 GB；Redis 达到 8 GB `maxmemory/noeviction` 后，安全引擎无法创建 `telemetry:traffic` consumer group，持续重启并显示异常。
- LyFlow 探针的活跃判断优先使用 payload 内的时间戳；镜像流的 payload 时间可能落后于 Redis 投递时间，导致探针被误判为未运行。

修复：

- Redis 流保留与业务历史解耦，默认 `REDIS_STREAM_RETENTION_HOURS=2`；历史审计仍由 PostgreSQL/ClickHouse 保存。
- 清理列表补齐 `flows:semantic`、`telemetry:traffic`、`telemetry:runtime`、`telemetry:rasp`、`telemetry:log_audit`、`logs:raw`、`events:dead-letter`。
- 探针活跃判断使用 payload 时间与 Redis message ID 中较新的时间。
- 验证：Redis 从约 5.2 GB 降至约 1 GB；安全引擎 `healthy/running`，`degraded=false`；LyFlow 探针 `running=true`。

## 6. 验证

- `server/cmd`、`server/incidentlifecycle` 测试通过。
- 前端 117 项测试、typecheck、build 通过。
- 生产验证：Agent 重命名可保存并恢复；白名单可添加/移除；活动 Incident 显示 4 条内网横向候选；引擎运行时接口无 503；页面无 console/API 错误。
