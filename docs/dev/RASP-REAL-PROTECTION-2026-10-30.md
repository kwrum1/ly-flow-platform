# RASP 真实检测 + 真实防护验证（2026-10-30）

- 任务：在 Agent 测试机 `10.1.18.8` 上用真实 `ly_rasp` 中间件验证请求级 RASP 能否真实返回 403，并通过平台 `/defense` 会话把策略真正提升到 block / enforcing。
- 平台：`https://10.1.18.241`
- Agent：`10.1.18.8`，agent_id `f2c67caf-5990-4ad3-8757-623c7a5213bf`
- 探针：`/opt/ly-agent/rasp/python/ly_rasp`（与仓库 `repo/agent/rasp/python/ly_rasp` 校验一致）
- 请求规则：`/etc/lyflow/rasp/request_rules.json`（`owasp-crs 4.31.0-dev`，24 条，PL2，digest `fa50ae33ba…`）
- 结论：**拦截真实生效（HTTP 403），平台事件 `blocked=true` 落库；rollback 后探针存在“陈旧 block / 静默 off”缺陷，已只改探针修复。**

---

## 1. 临时 WSGI 应用

仅在 `.8` 的 `/tmp/rasp-real-check/` 下创建，测试后已删除：

- `app.py`：`wsgiref` + `RASPWSGIMiddleware`，监听 `127.0.0.1:18120`，多线程；`/__rasp_status` 返回进程内 `RASPConfig` 与 `request_hook_status()`。
- `start.sh`：从 `/opt/ly-agent/etc/agent.env` 读取 `AGENT_ID` / `LY_RASP_TOKEN`（不落盘、不回显），并设置：

```sh
RASP_MODE=block
RASP_BLOCK_ON_HIT=true
RASP_POLICY_VERSION=1
RASP_AGENT_ID=$AGENT_ID
RASP_APP=rasp-real-check
LY_RASP_REQUEST_RULES=/etc/lyflow/rasp/request_rules.json
LY_RASP_BRIDGE_URL=http://127.0.0.1:17891
```

应用内自检（启动时）：

```json
{"config":{"mode":"block","block_on_hit":true,"policy_version":1,"policy_id":"","agent_id":"f2c67caf-…","app":"rasp-real-check"},
 "hook":{"enabled":true,"pack_path":"/etc/lyflow/rasp/request_rules.json","schema_version":"lyflow.rasp.request_rules.v1",
         "source":"owasp-crs","source_version":"4.31.0-dev","rule_count":24,"skipped_rules":0,
         "digest":"fa50ae33ba875a98a9c3aa0b494becb7c0b5b176fd59b92dcd18c0873631e27b","paranoia_level":2}}
```

> `RASP_MODE=block` 只是冷启动兜底；进程第一次上报事件时会从 bridge 拉取签名配置，之后完全以平台策略为准（已实测 `policy_version` 从 1 变为 12/13）。

---

## 2. 逐请求 HTTP 结果

### 2.1 第 1 轮：真实 block 会话（policy v12，`active`）

会话 `ds-10bafaca6b00c76bdea0c085`，`dry_run_seconds=120`，`duration=600`，17:12 提升为 `active`，bridge 返回 `policy_mode=block`、`block_on_hit=true`。

| # | 请求 | HTTP | `X-Ly-RASP-Blocked` | 响应 |
|---|---|---|---|---|
| 1 | `GET /hello?name=alice&page=2` | **200** | – | 正常 200 |
| 2 | `GET /healthz` | **200** | – | 正常 200 |
| 3 | `GET /items?id=1' UNION SELECT password FROM users--` | **403** | `1` | `{"error":"rasp_blocked","attack_type":"sqli","rule_id":"owasp-crs-942270"}` |
| 4 | `GET /items?id=1' AND SLEEP(5)--` | **403** | `1` | `rasp_blocked` / `owasp-crs-942160` |
| 5 | `GET /search?q=<script>alert(1)</script>` | **403** | `1` | `rasp_blocked` / `attack_type=xss` / `941110` |
| 6 | `GET /search?q=abc" onerror=alert(1) x="` | **403** | `1` | `rasp_blocked` / `xss` / `941390` |
| 7 | `GET /download?file=../../../../etc/passwd` | **403** | `1` | `rasp_blocked` / `path_traversal` / `930110` |
| 8 | `GET /static/../../../../etc/passwd`（curl 默认） | 200 | – | 见下方说明 |
| 9 | `GET /static/../../../../etc/passwd`（`--path-as-is`） | **403** | `1` | `path_traversal` / `930110` |
| 10 | `GET /static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` | **403** | `1` | `path_traversal` / `930110` |
| 11 | `POST /items` body `id=1' UNION SELECT password FROM users--` | **403** | `1` | `sqli` / `942270`（body 检测生效） |
| 12 | `POST /items` body `name=alice&note=hello` | **200** | – | 正常 200 |
| 13 | `GET /hello?name=alice&page=2` | **200** | – | 正常 200 |

第 8 行不是绕过：curl 在发送前做了客户端路径规范化，实际请求行变成 `GET /etc/passwd`；服务端 `PATH_INFO=/etc/passwd`，不包含 `../`。第 9/10 行证明服务端收到真实穿越路径时会被 403。

### 2.2 第 2 轮：修复后回归（policy v13，`active`）

会话 `ds-6f983b38e546c3bf0f9b3fef`，`dry_run_seconds=60`，17:29:58 提升为 `active`。

| # | 请求 | HTTP | `X-Ly-RASP-Blocked` | 规则 |
|---|---|---|---|---|
| 1 | benign `GET /hello` | **200** | – | – |
| 2 | benign `GET /healthz` | **200** | – | – |
| 3 | sqli union (query) | **403** | `1` | `owasp-crs-942270` |
| 4 | sqli time-based (query) | **403** | `1` | `owasp-crs-942160` |
| 5 | xss `<script>` | **403** | `1` | `owasp-crs-941110` |
| 6 | xss `alert(` | **403** | `1` | `owasp-crs-941390` |
| 7 | traversal (query) | **403** | `1` | `owasp-crs-930110` |
| 8 | traversal (`--path-as-is`) | **403** | `1` | `owasp-crs-930110` |
| 9 | traversal (encoded `%2e%2e%2f`) | **403** | `1` | `owasp-crs-930110` |
| 10 | sqli (POST body) | **403** | `1` | `owasp-crs-942270` |
| 11 | benign POST | **200** | – | – |
| 12 | benign GET | **200** | – | – |

请求后进程内配置：

```json
{"mode":"block","block_on_hit":true,"policy_version":13,
 "policy_id":"rasp-defense-ds-6f983b38e546c3bf0f9b3fef"}
```

即：拦截不是 env 兜底造成的，运行中已切换到平台签发的 v13 block 策略。

---

## 3. defense 会话状态

### 3.1 第 1 轮（手动停止）

| 时间 (UTC) | 事件 | 状态 |
|---|---|---|
| 17:10:12 | `POST /defense/sessions` scope=agent mode=block dry_run=120s duration=600s | `dry_run`，policy=`12` |
| 17:12:1x | scheduler promote | **`active`** |
| 17:12:30 | bridge `/v1/rasp/config` | `v12 block block_on_hit=true` |
| 17:12:30 | `/api/v1/rasp/policy` | `enforcing=true`，`active=12/active` |
| 17:19:19 | `POST /defense/sessions/<id>/stop` | HTTP 200 → `stopped` |
| 17:19:24 | `/defense/status` | **`mode=monitor`**，`monitoring=true`，无 live session |
| 17:19:24 | `/api/v1/rasp/policy` | `enforcing=false`，`active=1/monitor` |

### 3.2 第 2 轮（到时自动结束）

| 时间 (UTC) | 事件 | 状态 |
|---|---|---|
| 17:28:41 | 创建 scope=agent mode=block dry_run=60s duration=300s | `dry_run`，policy=`13` |
| 17:29:58 | scheduler promote | **`active`** |
| 17:30:10 | bridge | `v13 block block_on_hit=true` |
| 17:33:50 | 到时过期（`ends_at=17:33:41`） | `expired`，rollback 到 v1 |
| 17:33:5x | `/defense/status` | **`mode=monitor`**，`enforcing=false`，`active=1/monitor` |

> 第 2 轮本计划手动 stop，但 300s 窗口在停止调用前已到期，返回 409 `defense: conflict: session is expired`；手动 stop 的完整验证由第 1 轮覆盖。两轮结束后均无 live session。

---

## 4. RASP 事件证据

`GET /api/v1/rasp/events?limit=200`，过滤 `entities.application=rasp-real-check`：

### 4.1 v12 会话（8 条 `blocked=true`）

| observed_at | event_type | blocked | action | policy_version | rule_id |
|---|---|---|---|---|---|
| 17:13:11 | `rasp.sql` | **true** | block | 12 | request-sqli-owasp-crs-942270 |
| 17:13:11 | `rasp.sql` | **true** | block | 12 | request-sqli-owasp-crs-942160 |
| 17:13:11 | `rasp.http` | **true** | block | 12 | request-xss-owasp-crs-941110 |
| 17:13:11 | `rasp.http` | **true** | block | 12 | request-xss-owasp-crs-941390 |
| 17:13:11 | `rasp.file` | **true** | block | 12 | request-path_traversal-owasp-crs-930110 |
| 17:13:20 | `rasp.file` | **true** | block | 12 | request-path_traversal-owasp-crs-930110 |
| 17:13:20 | `rasp.file` | **true** | block | 12 | request-path_traversal-owasp-crs-930110 |
| 17:13:20 | `rasp.sql` | **true** | block | 12 | request-sqli-owasp-crs-942270 |

### 4.2 v13 会话（7 条 `blocked=true`）

| observed_at | event_type | blocked | action | policy_version | rule_id |
|---|---|---|---|---|---|
| 17:30:17 | `rasp.sql` | **true** | block | 13 | request-sqli-owasp-crs-942270 |
| 17:30:17 | `rasp.sql` | **true** | block | 13 | request-sqli-owasp-crs-942160 |
| 17:30:17 | `rasp.http` | **true** | block | 13 | request-xss-owasp-crs-941110 |
| 17:30:17 | `rasp.http` | **true** | block | 13 | request-xss-owasp-crs-941390 |
| 17:30:17 | `rasp.file` | **true** | block | 13 | request-path_traversal-owasp-crs-930110 |
| 17:30:17 | `rasp.file` | **true** | block | 13 | request-path_traversal-owasp-crs-930110 |
| 17:30:17 | `rasp.file` | **true** | block | 13 | request-path_traversal-owasp-crs-930110 |

字段位置：`fields.blocked=true`、`fields.action=block`、`fields.policy_version=12/13`、`fields.would_block=false`、`fields.rule_id=request-<category>-…`。

事件类型映射（bridge 规范只有 5 类）：`xss → rasp.http`，`path_traversal → rasp.file`，`sqli → rasp.sql`；精确分类保留在 `rule_id`（`request-xss-…` / `request-path_traversal-…`）。因此任务里提到的 `rasp.xss` / `path_traversal` 在本平台表现为 `rasp.http` / `rasp.file` + 对应 rule_id，属于“平台字段等价”。

反面对照：17:28:29/31 两条同规则事件 `blocked=false`、`action=log`、`policy_version=1`，即 rollback 后的 monitor 语义正确。

### 4.3 注意事项

- 平台 `/rasp/events` 返回的顶层 `mode` 字段对以上所有行都显示 `monitor`（包括 `blocked=true` 的历史事件），因为它是在**读取时**按当前策略标注的，不是事件发生时的快照。判断“当时是否拦截”请用 `fields.blocked` / `fields.action` / `fields.policy_version`。
- 事件入库存在延迟：本轮观察到 `observed_at` 与出现在列表中的时间相差约 3–5 分钟（agent spool 串行 flush + 服务端写入）。日志中曾出现 `[spool] encrypted flush paused: … status 502`（17:01 UTC），说明 spool 会因上游 502 暂停并按序重放，但未丢事件（最终全部到达）。

---

## 5. 发现的问题与修复

### 5.1 现象

第 1 轮 stop 后，**平台**已回到 monitor（策略 `active=1/monitor`、`enforcing=false`），但 `.8` 上的探针继续对 SQLi 返回 403 长达约 7 分钟；17:26:34 之后又变成全部 200 且**不再产生事件**（探针 `mode` 变为 `off`）。

定位结果（按任务要求逐项排除）：

| 检查项 | 结论 |
|---|---|
| middleware 模式 | 正常：`RASPWSGIMiddleware` 在 `mode=block && block_on_hit` 时抛 `RASPRequestBlocked`，返回 403 |
| 规则包 | 正常：24 条规则加载成功，`request_rules.json` 命中正确 |
| agent binding | 正常：`X-Lyflow-Agent-ID` 与 bridge 绑定一致，事件 `202` 接受 |
| 事件链路 | 正常但有延迟：`telemetry:rasp` 最终写入，`blocked=true` |
| **policy 刷新 / token** | **缺陷**：`bridge._refresh_config()` 用**上一次响应里的轮换 token** 去读 `/v1/rasp/config`；bridge 每次策略激活都会 `RotateToken()`，旧 token 只在 2 分钟内有效。token 过期后 `/config` 返回 401，`report()` 把 `config.mode` 置为 `off`，探针从此**静默停止检测**，且无法自行恢复（没有稳定引导凭据）。 |
| **策略过期** | **缺陷**：bridge 下发的签名配置包含 `expires_at`，但 `_refresh_config()` 从未写回 `config.expires_at`；`effective_mode()` 的过期逻辑形同虚设，block 策略在控制面不可达/rollback 抖动时会**无限期保持**。 |
| rollback 传播 | 平台侧存在短暂 `503 RASP policy inactive` / `/api/v1/agent/config` 503 窗口（17:20–17:26 观察到），agent 需重新 ACK 才能回到 monitor，探针在此期间只能依赖本地过期时间兜底。 |

### 5.2 修复（只改探针 `bridge.py`）

文件：`/opt/ly-agent/rasp/python/ly_rasp/bridge.py`

- 原：`6b31f84d5879db0b35467cba66ffddfd9f9bdc60f78f6b9fac69f5ef98cf9de4`
- 新：`cf973d232f490a1f8c88c86a9011fb0689d479dabfc475049fba16506c90237c`

改动点：

1. **分离引导凭据与事件凭据**
   - 构造时保存 `self._bootstrap_token = config.bridge_token`（即 `agent.env` 的 `LY_RASP_TOKEN`，bridge 的 `AuthenticateConfig()` 永远接受它）。
   - `/v1/rasp/config` 固定用 bootstrap token 请求，并用**实际发送的 token** 校验 HMAC（bridge 用请求头 token 签名）。
   - 事件 POST 继续使用轮换后的 `config.bridge_token`。
2. **token 轮换自愈**
   - 事件 POST 返回 401/403 时，`_refresh_config(force=True)` 用 bootstrap token 重新拉取签名配置，重试一次；仍失败才进入 `mode=off` 的授权失败分支。
3. **执行签名策略的过期时间**
   - 新增 `parse_config_expiry()`，兼容 Go `RFC3339Nano`（9 位小数）与 `Z`/`+08:00`。
   - `_refresh_config()` 写回 `config.expires_at`，并在有签名策略（`policy_version>0`）时设置 `config.fail_behavior="monitor"`：策略到期后降级为 monitor（继续检测、不再拦截），不会无限期 block，也不会直接静默关闭。

关键 diff（相对仓库版本）：

```diff
+_EXPIRY_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$")
+
+def parse_config_expiry(value: Any) -> Any:
+    ...
+    return datetime.fromisoformat(stamp)
@@ class BridgeClient.__init__
+        self._bootstrap_token = config.bridge_token
@@ def report
-            request = Request(..., headers=self._headers(), ...)
-            with self._opener.open(request, timeout=2.0) as response:
+            try:
+                delivered = self._post_event(strict_event)
+            except HTTPError as error:
+                if error.code not in {401, 403}:
+                    raise
+                self._refresh_config(force=True)
+                strict_event = self.build_event(event)
+                delivered = self._post_event(strict_event)
@@ def _refresh_config(force=False)
+        credential = self._bootstrap_token or self.config.bridge_token
+        request = Request(..., headers=self._headers(credential), ...)
-        expected = hmac.new(self.config.bridge_token.encode(...), ...)
+        expected = hmac.new(credential.encode(...), ...)
+        expires_at = parse_config_expiry(body.get("expires_at"))
@@
+        self.config.expires_at = expires_at
+        self.config.fail_behavior = "monitor" if policy_version > 0 else "disable"
@@ def _headers(credential=None)
```

### 5.3 修复验证（`.8` 实测）

```
bootstrap present: True
after refresh: policy=rasp-monitor-default v1 mode=monitor block_on_hit=False expires=2027-10-28 19:10:35.947291+00:00
event token replaced: True
expired: effective_mode=monitor should_block=False
live:    effective_mode=block   should_block=True
report delivered: True
```

- 人为把 `config.bridge_token` 改成失效值，仍能用 bootstrap token 拉到配置并换回新 token。
- 到期策略 `should_block=false`，未到期策略 `should_block=true`。
- 修复后 WSGI 应用在 rollback 场景：`mode=monitor`，SQLi 200；在 v13 active 场景：SQLi/XSS/穿越 403（见第 2.2 节）。

---

## 6. 清理结果

- 临时 WSGI 应用：已 `fuser -k 18120/tcp`，`ss -ltnp` 无 `18120`，无残留 `python3 app.py` 进程。
- 临时目录 `/tmp/rasp-real-check`：已删除（含 app、脚本、原 `bridge.py` 备份、测试输出）。
- defense 会话：无 live session；`ds-10baf…` = `stopped`，`ds-6f98…` = `expired`。
- 平台最终状态：`/defense/status` → `mode=monitor, monitoring=true, live_session=false, remaining=0`；`/rasp/policy` → `enforcing=false, active=1/monitor`。
- `.8`：`ly-agent` active，`ssh` active，bridge `/v1/rasp/config` HTTP 200（`rasp-monitor-default v1 monitor block_on_hit=false`）。
- `/etc/lyflow/rasp/request_rules.json`、`agent.env`、`agent.yaml` 未改动。
- 未删除：`/var/lib/lyflow/rasp/fallback.jsonl`（探针完整性哈希链的 fallback，含 rollback 窗口内被 bridge 409/401 拒绝的事件与控制健康记录；属探针运行时数据，不属于本次临时文件）。
- 服务器/前端/仓库其他文件均未改动，未部署、未 commit；`docs/dev/RASP-REAL-PROTECTION-2026-10-30.md` 为新增报告。

---

## 7. 风险与后续

1. **探针改动只落在 `.8`，尚未回源到仓库**。`repo/agent/rasp/python/ly_rasp/bridge.py` 仍是旧版本；升级/重装 agent 会覆盖本次修复。需要另开任务同步（本任务明确不允许改仓库其他文件）。
2. **rollback 传播仍依赖 agent 心跳（30s）和探针的事件上报**。修复把最坏情况限制为“策略到期即降级 monitor”，但探针在没有匹配流量时不会主动刷新配置；控制面 rollback 后、下一次命中前，仍可能多拦一段时间（受 `expires_at` 上限约束）。
3. **平台读取时的 `mode` 字段会误导**：历史 `blocked=true` 事件在 rollback 后仍显示 `mode=monitor`。看板若以此字段判断“是否拦截过”会得出错误结论，应使用 `fields.action` / `fields.blocked`。
4. **telemetry 入库延迟 3–5 分钟**，且 spool 在上游 502 时会暂停重放。安全运营视角下“拦截实时、事件滞后”，需要评估 SLA。
5. **生产 block 开关已打开**：`allow_production_block=true`。任何有权限的账号都能创建真实 block 会话，建议在生产环境显式关闭或在 UI 增加二次确认。
6. **路径穿越依赖服务端是否收到未规范化路径**。经 curl 默认规范化后的 `/static/../../etc/passwd` 会变成 `/etc/passwd`，不属于绕过；但若上游代理先规范化，RASP 请求侧规则同样看不到穿越特征，需要结合 sink 侧 `file` hook（本次未覆盖）评估。
7. **fallback 文件会持续增长**：本轮 rollback 窗口内有被拒事件写入 `/var/lib/lyflow/rasp/fallback.jsonl`，需要纳入容量/清理策略。

---

## 8. 复现命令（不含凭据）

```sh
# .8
mkdir -p /tmp/rasp-real-check && cd /tmp/rasp-real-check
# 写入 app.py / start.sh（见第 1 节），start.sh 自行 source /opt/ly-agent/etc/agent.env
setsid nohup ./start.sh > app.log 2>&1 < /dev/null &

curl -sS http://127.0.0.1:18120/__rasp_status
curl -sS --path-as-is -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:18120/items?id=1%27%20UNION%20SELECT%20password%20FROM%20users--'

# 平台
curl -sS -X POST https://10.1.18.241/api/v1/defense/sessions \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"scope":"agent","scope_value":"f2c67caf-5990-4ad3-8757-623c7a5213bf","mode":"block","duration_seconds":300,"dry_run_seconds":60,"reason":"rasp real check"}'

curl -sS https://10.1.18.241/api/v1/defense/status -H "Authorization: Bearer $TOKEN"
curl -sS https://10.1.18.241/api/v1/rasp/policy -H "Authorization: Bearer $TOKEN"
curl -sS 'https://10.1.18.241/api/v1/rasp/events?limit=200' -H "Authorization: Bearer $TOKEN"

# 结束
curl -sS -X POST https://10.1.18.241/api/v1/defense/sessions/<id>/stop \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"test finished"}'
```
