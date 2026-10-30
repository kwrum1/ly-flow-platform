# 流量 UI 移除确认 + SSH/XDR 历史噪声清理（2026-10-30）

测试对象：`.241` 平台（`https://10.1.18.241`）、Agent `10.1.18.8`。
数据库：容器 `ly-flow-platform-postgres-1`，库 `lyflow`，用户 `lyflow`。
时间基准：服务器时区 UTC，本文同时给出 UTC 与 `+08` 本地时间。

本任务只读验证 + 一次可回滚的数据清理，未改代码、未改规则、未部署、未重启容器、未动 systemd、未 commit。

## 1. 前端 UI：流量规则面板已移除

### 1.1 首页缓存策略

| 请求 | 状态 | Cache-Control | Last-Modified |
|---|---|---|---|
| `GET /` | 200 | `no-cache, no-store, must-revalidate` | Thu, 29 Oct 2026 15:51:13 GMT |
| `GET /index.html` | 200 | `no-cache, no-store, must-revalidate` | Thu, 29 Oct 2026 15:51:13 GMT |

结论：`/index.html` 已返回 no-cache，前端发版后不会因浏览器缓存继续使用旧 chunk。

### 1.2 Rules chunk 内容

| 项 | 值 |
|---|---|
| 入口 chunk | `index-BQGqflog.js`（200，1,235,944 bytes） |
| Rules chunk | `Rules-CU5Lshp2.js`（200，14,512 bytes，`application/javascript`） |
| Rules chunk ETag | `"6ae36b71-38b0"`（缓存 `max-age=31536000`，内容寻址） |
| `流量引擎规则集` | 未命中（-1） |
| `traffic-rule-profile` | 未命中（-1） |
| `loadTrafficProfile` | 未命中（-1） |
| `四类引擎规则源` | 命中（offset 9033，正常保留） |

补充：对入口 chunk 引用的全部 **18 个 JS asset** 做了全量扫描，两个禁用字符串命中数均为 **0**。

结论：线上 Rules 路由已不含「流量引擎规则集」面板与 `traffic-rule-profile` 锚点，`四类引擎规则源` 仍在，符合预期。

## 2. `SSH Root Login Log` 历史统计

查询条件：`threat_events.message = 'SSH Root Login Log'`（清理前）。

| 指标 | 值 |
|---|---|
| 事件数 | 1,719 |
| 去重 `event_uid` | 1,719（无重复主键） |
| 时间范围（UTC） | 2026-10-29 08:21:57.217 → 2026-10-29 15:44:24.789 |
| 时间范围（+08） | 2026-10-29 16:21:57 → 2026-10-29 23:44:24 |
| 规则 | `log-ssh-root-login-default`（category `log_audit`） |
| Agent | `f2c67caf-5990-4ad3-8757-623c7a5213bf`（host `ubuntu`，即 `.8`） |
| 目标 IP | `10.1.18.8` |

来源 IP（从 `raw_event.details.message` 解析，`src_ip` 列本身为空）：

| 来源 IP | 条数 |
|---|---|
| 10.18.3.67（管理员出口） | 1,336 |
| 无 IP（旧事件无 `details`，383 条） | 383 |

按小时分布（UTC）：08 时 444、12 时 26、13 时 314、14 时 813、15 时 122，合计 1,719。

## 3. 新规则不再产生新事件

| 证据 | 结果 |
|---|---|
| `detection_rules.log-ssh-root-login-default.enabled` | `false`（updated_at 2026-10-29 15:47:44 UTC） |
| 当前激活 bundle | `59 / db-active-20261029154745 / active`（2026-10-29 15:47:46 UTC） |
| 激活 bundle 文件内 `log-ssh-root-login-default` | `grep -c` = **0** |
| 激活 bundle 文件内 `log-ssh-failure-default` | `grep -c` = **1**（失败登录规则保留） |
| 规则停用后新增事件（`observed_at > 15:47:44+00`） | **0** |
| 最后一条 SSH 事件 | 15:44:24 UTC（规则停用前 3 分 20 秒） |
| 日志采集是否仍在工作 | `log_audit` 最后写入 16:49:34 UTC，清理前共 2,016 条 |

结论：观察窗口 15:47:44 → 17:10 UTC（约 1 小时 22 分）内，日志管道持续产出 `log_audit` 事件，但该规则零新增，确认新规则集不再产生成功 root 登录噪声。

## 4. 可回滚清理

### 4.1 备份

```sql
CREATE TABLE IF NOT EXISTS threat_events_ssh_root_backup AS
SELECT * FROM threat_events WHERE message='SSH Root Login Log';
```

| 项 | 值 |
|---|---|
| 备份表 | `public.threat_events_ssh_root_backup`（13 列，与源表一致） |
| 备份行数 | **1,719** |
| 待删行数 | **1,719** |
| 一致 | 是 |
| 内容校验（`md5(string_agg(event_uid ... order by event_uid))`） | 备份 `d6ea8b4d5767840f0c6ecfe07ff8bf1e` = 待删 `d6ea8b4d5767840f0c6ecfe07ff8bf1e` |
| 表大小 | 2,568 kB |

行数与校验和均一致后才执行删除；脚本在不等时直接中止，不进入 DELETE。

### 4.2 删除

```sql
WITH deleted AS (
  DELETE FROM threat_events WHERE message='SSH Root Login Log' RETURNING 1
) SELECT count(*) FROM deleted;
```

| 指标 | 清理前 | 清理后 |
|---|---|---|
| `DELETE` 返回行数 | — | **1,719** |
| `threat_events` 总行数 | 2,546 | **827** |
| `SSH Root Login Log` 行数 | 1,719 | **0** |
| `log_audit` 行数 | 2,016 | **297** |
| 备份表行数 | 1,719 | **1,719**（保持不动） |
| `incidents` 行数 | 17 | **17**（未动） |
| 减少量核对 | 2546 − 827 = 1,719 = 删除行数 | 一致 |

清理后分类分布：`runtime 464`、`log_audit 297`、`traffic 66`。

清理起止：17:08:43 UTC → 17:08:57 UTC。

### 4.3 回滚方式

```sql
BEGIN;
INSERT INTO threat_events SELECT * FROM threat_events_ssh_root_backup;
COMMIT;
-- 校验：期望 1719
SELECT count(*) FROM threat_events WHERE message='SSH Root Login Log';
-- 全部回滚成功后再考虑清理备份表（本任务未删备份）
```

说明：本次未执行 `VACUUM`，`threat_events` 物理大小仍为 7,728 kB，死元组由 autovacuum 后续回收。若不需要长期保留备份，另行评审后再 `DROP TABLE threat_events_ssh_root_backup`。

## 5. `incidents` 重复情况（只报告，未删除）

共 **17** 条 incident，全部与本轮清理的 SSH 噪声同源，但来源不是被删的 `log-ssh-root-login-default`，而是历史 Wazuh 管道：

| 指标 | 值 |
|---|---|
| incident 总数 | 17（open 15 / closed 1 / processing 1） |
| 含 root-login 证据的 incident | 17（即全部） |
| 证据来源规则 | Wazuh `5715 / Wazuh SSHD root login` |
| 证据时间范围 | 2026-10-29 04:54:39 → 05:03:39 UTC（+08 12:54–13:03，仅 9 分钟） |
| 证据行数 / 去重事件 | 34 行 / 22 个 `event_uid` |
| 被 2 条 incident 共用的 `event_uid` | **12** |
| `dedup_key` 唯一性 | 17 个全部唯一（未触发去重合并） |
| 创建时间 | 全部同一批 2026-10-29 07:59:20 UTC |

判定：

- 同一批 9 分钟的登录事件被展开成 17 条「2 事件 / 2 阶段」链，证据链首尾重叠，属**过度拆分/重复 incident**，不是误报内容错误。
- `dedup_key` 未重复，说明重复发生在链切分（滑动窗口）而非入库去重；仅靠 `dedup_key` 查重发现不了。
- 这些 incident 的证据 `event_uid` 均不在当前 `threat_events` 中（`evt-*` 与 `alert-*` 命名空间不同，Wazuh 历史事件已不在表内），因此**本次 DB 清理不会消除这 17 条 incident**。
- 按任务要求未删除任何 incident；如需收敛，建议单独评审：按 `source_chain_id`/时间窗合并，或对同源 root-login 链设置抑制。

## 6. XDR stats 前后对比

`GET /api/v1/xdr/stats`：

| 字段 | 清理前 17:08:43 | 清理后 17:08:57 | 复测 17:10:16 |
|---|---|---|---|
| `total_events` / `total_alerts` | 1000 / 1000 | 1000 / 1000 | 1000 / 1000 |
| `events_today` / `alerts_today` | 1000 / 1000 | 1000 / 1000 | 1000 / 1000 |
| `critical_alerts` | 0 | 0 | 0 |
| `high_alerts` | 48 | 48 | 48 |
| `medium_alerts` | 478 | 478 | 478 |
| `low_alerts` | 474 | 474 | 474 |
| `active_chains` | 8 | 8 | 8 |
| `posture_level` / `posture_score` | high / 76 | high / 76 | high / 76 |
| `sources` | `ly-security-engine` | 同 | 同 |

结论：**前后完全一致，无变化**。

原因（已核对代码与运行时）：

- `xdrStatsHandler` 走 `loadXDREvents`，优先读 Redis 流 `events:xdr`（当前 `XLEN = 2761`），PG 只是兜底；删除 `threat_events` 行不影响该流。
- `total_events` 上限为 1000（`loadXDREvents(cfg, 1000, 0)`），是"最近 1000 条"口径，不是全量计数。
- 因此本次清理**不会**让 XDR 首页数字下降；XDR 历史里仍含 root-login 噪声。

## 7. 未处理项与风险

1. **XDR 历史未清理**：Redis `events:xdr`（2,761 条）仍包含历史 root-login 告警，XDR stats 仍为 1000 alerts / 8 chains / posture 76。本次范围仅限 PG `threat_events`。
2. **17 条重复 incident 未处理**：来自 Wazuh 5715 历史链，12 个证据事件被两条 incident 共用；按约束只报告不删除，需要单独的合并/抑制方案。
3. **383 条旧事件无来源 IP**：这批 SSH 事件无 `details` 字段（旧采集格式），无法补出源 IP；`threat_events.src_ip` 列对全部 1,719 条均为空，`log_audit` 的源 IP 仍只存在于 `raw_event.details.message` 文本里，属数据质量缺口。
4. **磁盘空间未立即释放**：未执行 `VACUUM`，`threat_events` 仍占 7,728 kB；备份表额外占 2,568 kB，需按保留策略决定何时归档/删除。
5. **备份表保留**：`threat_events_ssh_root_backup` 仍在库中，可作为回滚依据；未设置过期时间。
6. **前端缓存**：`index.html` 已 no-cache，但 `Rules-*.js` 为 `max-age=31536000` 强缓存；由于文件名带 hash，正常发版不受影响，回滚到同名旧 chunk 时才需注意浏览器缓存。

## 8. 交付核对

| 要求 | 结果 |
|---|---|
| Rules chunk 不含「流量引擎规则集」/`traffic-rule-profile` | 通过（`Rules-CU5Lshp2.js`，200，18 个 asset 全量扫描 0 命中） |
| `/index.html` 返回 no-cache | 通过（`no-cache, no-store, must-revalidate`） |
| SSH 历史数量/时间范围/来源 IP | 1,719 条；08:21:57–15:44:24 UTC；10.18.3.67 共 1,336 条，383 条无 IP |
| 新规则不再产生事件 | 通过（停用后 0 条，bundle 59 不含该规则，日志管道仍在产出） |
| 备份行数 = 待删行数 | 通过（1,719 = 1,719，校验和一致） |
| 删除计数 | 删除 1,719；总行数 2,546 → 827；剩余 0 |
| incident 重复检查 | 完成，只报告：17 条，12 个证据事件跨 incident 复用 |
| XDR stats 前后 | 完全一致（1000/8/76），原因已定位为 Redis 流口径 |
| 未改代码/未部署/未重启/未 commit | 是 |
