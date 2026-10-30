# 规则库上游同步实测报告（2026-10-30）

- 平台：`https://10.1.18.241`（admin，凭据取自现有私有脚本，本报告不记录任何口令/Token）
- 服务器时间：UTC。实测窗口 `2026-10-29T17:05Z ~ 17:15Z`（本地 CST `2026-10-30 01:05 ~ 01:15`）
- 测试方式：只调用只读接口 + 逐源 `POST /api/v1/rule-platform/sync`；**未**调用空 body 的“全量同步”（该入口会异步同步全部可更新源，内容变化时会直接激活新 bundle）
- 安全约束执行情况：未改代码、未部署、未动 .241/.8 的 systemd/容器、未 git commit、未打印密钥；仓库内只新增本文件
- 判定“不会激活”的方法：先在本机独立拉取上游原始字节计算 SHA256，与平台 `content_hash` 比对；只有完全一致（命中 unchanged 快速路径）才发起该源的 POST。脚本同时设置了熔断：任一源返回 `activated=true` 或 active bundle 版本/hash 变化即停止后续同步

## 1. 基线：`GET /api/v1/rule-platform/sources`

`HTTP 200`，共 11 个 source（`data.freshness = ok`）。基线采集时平台正好有一个后台全量同步任务在跑（见第 5 节），因此 `et-open-connector` 的 `last_sync_at` 已是本轮任务刷新的 `17:03:58Z`。

| source_id | category | connector | updatable | sync_status | current_version | content_hash (sha256) | last_sync_at |
|---|---|---|---|---|---|---|---|
| custom-rasp-rules | rasp | false | false | synced | catalog-20261029 | aab11481f77154376a9842ee2264a34ba1b04b1345103ec31a715556dcd3202a | 2026-10-29T02:06:45Z |
| et-open-connector | traffic | true | true | synced | sync-20261029T082326Z | c6234647c8c92681533a643896d6c35a559c35d327a9de02a730de9a00def13b | 2026-10-29T16:17:17Z |
| falco-connector | runtime | true | true | synced | sync-20261029T033721Z | 30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b | 2026-10-29T16:17:17Z |
| lyflow-compiled-local | all | false | false | synced | catalog-20261029 | 0da9ff52f1fefcd3f307e8d6ed528414a5c334ad77c76a6067d50945d2054e66 | 2026-10-29T02:06:45Z |
| lyflow-default | all | false | false | synced | catalog-20261029 | aa5f086b07470da52c9cda9a1406f0b6dae386781f2c435ab0b06f8aed0c45f3 | 2026-10-29T02:06:45Z |
| oisf-trafficid | traffic | true | true | synced | sync-20261029T033721Z | 9e0569d15a8ca53b526e2ca784d8a98870d008eaf163bc188c0deb33ddc9464e | 2026-10-29T16:17:18Z |
| owasp-crs-connector | rasp | true | true | synced | sync-20261029T033721Z | f63d62bdadfb8a7e63e348ca7135fed7c83c58cf65c62841ba8ba11632020fc2 | 2026-10-29T16:17:19Z |
| openrasp-derived | rasp | true | **false** | synced | catalog-20261029 | d25ef6fc22f0ed63c65bf5a40036b8ec8f91fa37e5c39547f600c3aeb7bf51d9 | 2026-10-29T02:06:45Z |
| sigma-connector | log_audit | true | true | synced | sync-20261029T033721Z | 8e0302ef07eabcb04ee3d63ffcedce173270ca20e6b6213c83a3d7db8630ce9e | 2026-10-29T16:17:19Z |
| sigma-full | log_audit | true | true | synced | sync-20261029T061828Z | 7ab70e31cabd604fa698c796dab0c1789f82e6f5c8447e806fb9ee7ec440ffbc | 2026-10-29T16:17:22Z |
| stamus-lateral | traffic | true | true | synced | sync-20261029T034720Z | eacc6867f4f910d4464551da0008d62348fe27030ea0a35e23840d417c66ab68 | 2026-10-29T16:17:24Z |

补充：

- 11 个 source 全部 `restricted=false`、`sync_status=synced`，无 `staged`/`failed` 残留。
- `custom-rasp-rules` 不可更新、无 URL；按代码路径（`server/cmd/rule_platform.go` 的 `custom-rasp-rules` 分支）只能带 pin 的 inline rules/content，否则返回 `custom rule sync requires pinned inline rules or content`，故未对它发 POST。
- `openrasp-derived` 虽 `connector=true`，但 `updatable=false`，不属于全量同步范围。
- 可更新 connector 实际有 **7 个**（含 `sigma-full`、`stamus-lateral`），任务点名的 4 个均在列。

## 2. 逐源同步实测

共同结果：`HTTP 200`、`status=unchanged`、`activated=false`、返回的 `content_hash` 与基线一致、active bundle 无任何变化。

| # | source_id | endpoint | HTTP | 耗时 | status | activated | 返回 version（本次 run 标签） | 返回 content_hash | 同步后 current_version |
|---|---|---|---|---|---|---|---|---|---|
| 1 | et-open-connector | `https://rules.emergingthreats.net/open/suricata/emerging-all.rules` | 200 | 18.2s | unchanged | false | sync-20261029T170758Z | c6234647c8c92681533a643896d6c35a559c35d327a9de02a730de9a00def13b | sync-20261029T082326Z（不变） |
| 2 | falco-connector | `https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml` | 200 | 0.8s | unchanged | false | sync-20261029T170813Z | 30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b | sync-20261029T033721Z（不变） |
| 3 | sigma-connector | `https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml` | 200 | 0.5s | unchanged | false | sync-20261029T170814Z | 8e0302ef07eabcb04ee3d63ffcedce173270ca20e6b6213c83a3d7db8630ce9e | sync-20261029T033721Z（不变） |
| 4 | owasp-crs-connector | `https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 200 | 0.5s | unchanged | false | sync-20261029T170814Z | f63d62bdadfb8a7e63e348ca7135fed7c83c58cf65c62841ba8ba11632020fc2 | sync-20261029T033721Z（不变） |
| 5 | oisf-trafficid（附加） | `https://openinfosecfoundation.org/rules/trafficid/trafficid.rules` | 200 | 0.6s | unchanged | false | sync-20261029T170815Z | 9e0569d15a8ca53b526e2ca784d8a98870d008eaf163bc188c0deb33ddc9464e | sync-20261029T033721Z（不变） |

说明：

- 第 5 项为附加覆盖（同属可更新 connector，且上游哈希已预检一致）。
- “返回 version”只是本次 run 的唯一标签；unchanged 路径**不会**把它持久化为 `current_version`，因此 source 的 `current_version` 保持上次真正应用时的版本。这是正常语义，不应误判为“同步没生效”。
- `sigma-full`、`stamus-lateral` 未由本任务直接 POST（见第 3 节）；但在同一窗口内被平台的后台全量同步任务覆盖，结果同为 `unchanged`（见第 5 节）。
- 独立预检（本机拉取原始字节并算 SHA256）结果：7 个可更新源全部与平台 `content_hash` 完全一致，包括：
  - et-open 46,697,580 B → `c623…13b`
  - falco 64,538 B → `30a1…65b`（本地 raw.githubusercontent.com 被重置，改用 jsdelivr 取得同字节）
  - sigma 1,187 B → `8e03…9e`
  - owasp-crs 99,229 B → `f63d…fc2`
  - oisf 9,855 B → `9e05…64e`
  - sigma-full 9,516,403 B → `7ab7…fbc`（经 gh-proxy）
  - stamus 31,209 B → `eacc…b68`
- 熔断未触发（`stopped=None`）。

## 3. 未直接 POST 的可更新源及原因

| source_id | 原因 | 已有证据 |
|---|---|---|
| sigma-full | 内容为 GitHub master tarball，天然高频变化；一旦变化，POST 会走 `applied+activated` 直接切 active bundle，违反本次“不主动激活变化内容”的约束 | 预检哈希 `7ab70e31cabd…` 与平台一致；后台任务结果为 `unchanged` |
| stamus-lateral | 同上（第三方 tarball） | 预检哈希 `eacc6867f4f9…` 与平台一致；后台任务结果为 `unchanged` |

结论：本次窗口内所有 7 个可更新源的上游内容均未变化，所以“全量同步”本身也是安全的；但这是时间点巧合，不能作为常规操作方式。真正的变更演练必须单独隔离（见第 7 节）。

## 4. active bundle 与计数一致性

同步前、同步后（含后台任务结束后）完全一致：

| 字段 | 同步前 | 同步后 |
|---|---|---|
| version | db-active-20261029154745 | db-active-20261029154745 |
| status | active | active |
| bundle_hash | cbc8cae2f7fbd6336c92c2294df9809ebdf1cad35e6ba567daaf8703576b41e1 | 同左 |
| activated_at | 2026-10-29T15:47:46Z | 同左 |
| rule_count | 618 | 618 |
| rule_counts | traffic 585 / log_audit 9 / rasp 16 / runtime 6 / artifact 2 | 同左 |

一致性校验：

1. `rule_counts` 求和 = 585 + 9 + 16 + 6 + 2 = **618** = `rule_count` ✅
2. `GET /api/v1/rules/stats`（同步前后一致）：
   - `categories = {traffic:585, log_audit:9, runtime:6, rasp:16, artifact:2, xdr:58}`
   - traffic/log_audit 与 active-bundle 完全一致 ✅
   - `totalRules = enabledRules = 676 = 618 + 58(xdr)`；xdr 是独立关联规则，不计入安全引擎 bundle
   - `count_semantics.traffic = {signature_count:585, rule_file_count:2, source:"signed_active_lifecycle", ledger_digest:"cbc8cae2…41e1"}`，**ledger_digest 与 bundle_hash 相同** ✅
3. `GET /api/v1/rule-platform/bundles`：最新一条仍是 `db-active-20261029154745`（15:47:46Z），17:03–17:10 的多次 unchanged 同步**没有创建任何新 bundle** ✅
4. 不要用 `GET /api/v1/engine-rules` 的 `counts` 做 bundle 口径对比：它来自文件扫描 + `detection_rules` 全表（含 disabled/unsupported），实测为 `log_audit 128 / runtime 106 / rasp 1378 / suricata 585 / yara 6335`；其中只有 suricata 585 与 bundle 的 traffic 585 恰好一致。bundle 口径应以 `/rule-platform/active-bundle` 或 `/rules/stats` 为准。

结论：unchanged 同步没有改动 active bundle，计数、哈希、签名账本摘要三者自洽，且与同步结果一致。

## 5. 失败项与根因

实测期间捕获到 **1 个真实失败**，但不在本任务的逐源调用里，而是平台自身的后台全量同步任务：

`GET /api/v1/rule-platform/sync` 显示：

- started_at `2026-10-29T17:03:51Z`，finished_at `2026-10-29T17:10:36Z`，version `sync-20261029T170351Z`
- total 7 / unchanged 6 / **failed 1** / applied 0 / skipped 0
- 失败项：
  - `falco-connector`
  - error：`all endpoints failed (last: fetch raw.githubusercontent.com: Get "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml": EOF)`
- 其余 6 源：et-open / oisf / owasp-crs / sigma / sigma-full / stamus 全部 `unchanged`

根因判定：**上游/网络瞬时不可达（GitHub raw 连接被重置/EOF），不是权限、不是解析、不是审计、不是平台故障。**

证据链：

| 可能原因 | 是否成立 | 证据 |
|---|---|---|
| 上游不可达 | **成立（瞬时）** | 错误为 HTTP 传输层 `EOF`；同一 URL 在本任务 17:08:13Z 的独立逐源同步中返回 200/unchanged，哈希与基线一致；同批次其他 GitHub 源在 17:10 成功 |
| 权限问题 | 不成立 | 无 401/403；其余源正常；`restricted=false` |
| 解析问题 | 不成立 | 未出现 `rule source produced no ... parseable rules`；到达 fetch 阶段即失败 |
| 审计问题 | 不成立 | 未出现 audit/incomplete audit entry 类错误；同批次其他源审计路径正常 |
| 平台/DB 故障 | 不成立 | 其余 6 源成功，active bundle/rules-stats 正常 |

无法从 API 确认该任务由谁触发：时间点与 `release-v60` 产物时间（本地 01:02 ≈ UTC 17:02）吻合，**疑似后端重启后自动同步调度器在 2 分钟后触发**（`startRuleSyncScheduler` 的首个 timer 为 2 分钟），也不排除并行会话手动触发。它和本任务的逐源测试在 17:08 前后重叠，这是本次隔离性上的一个瑕疵，但未造成 bundle 变更。

> 注意：该失败只体现在内存中的 job 状态里；`rule_source_versions` 没有失败行，`/sources` 也不会显示失败。要发现这类失败必须主动查 `GET /rule-platform/sync`。

## 6. 其他实测观察（验证时容易踩的坑）

1. **`/sources` 有 5 分钟缓存，且同步成功后不失效**（`server/cmd/response_cache.go`，`sourceCatalogCacheTTL = 5m`；`rule_platform.go` 的 POST 分支只清 upsert 的缓存）。实测：17:08 同步成功后 `/sources` 仍返回 16:17/17:03 的旧 `last_sync_at`；等待缓存过期后重新拉取才变成 17:08–17:10。验证同步结果请用 `GET /rule-platform/versions?source_id=...`（不走该缓存）或等 >5 分钟再查 `/sources`。
2. **unchanged 路径的审计与 DB 更新是 best-effort**：`rule_platform.go` 中 unchanged 分支里 `_, _ = cfg.DBPool.Exec(...)` 和 `_ = cfg.RuleLifecycle.RecordOutcome(...)` 都忽略错误。也就是说 unchanged 同步即使审计写入失败也会返回 200。本次 `rule_source_versions.synced_at` 确实从 16:17 推进到 17:08:12–17:08:15，说明 DB 更新成功；但审计账本未通过 API 暴露，无法从外部证明本次 unchanged 的审计条目已落盘。若审计是硬要求，需要在容器内校验 control audit ledger（本次按约束未操作容器）。
3. **unchanged 仍会完整下载并解析上游**：ET Open 46.7 MB 的 unchanged 同步耗时 18.2s；其余小文件 0.5–0.8s。每日全量同步的主要成本就在大流量规则集的 fetch+parse。
4. **`POST /sync`（空 body）是高危入口**：它异步同步全部 7 个可更新源，任一源内容变化都会走 `applied + activated`，直接替换 active bundle。日常“验证同步”不要用它；必须逐源并预检哈希。
5. **unchanged 不新增 version 行**：只更新既有同 hash 行的 `synced_at`，`current_version` 保持不变；不要据此认为同步未执行。

## 7. 下一次“真实变更”时需要验证什么

前置（变更前 30 分钟内）：

1. `GET /rule-platform/sync` 确认 `running=false`，避免与自动同步/他人任务并发（本次就发生了重叠）。
2. 记录基线四件套：`active-bundle`（version/hash/rule_count/rule_counts）、`bundles` 前 5 条、`rules/stats`（含 `ledger_digest`）、目标源 `versions?source_id=`。
3. 预留回滚版本：确认上一个可用 bundle 版本（本次为 `db-active-20261029154745` / `cbc8cae2…41e1`）在 `bundles` 列表中且为 inactive。
4. 独立计算目标上游 SHA256，确认**确实与当前 `content_hash` 不同**；记录预期新增/删除的规则数与 category。

执行（单源，人工在场）：

5. 只对一个源 `POST /rule-platform/sync`，body 仅 `{"source_id":"<id>"}`；不要空 body，不要并行多源。
6. 断言响应：HTTP 200、`status=applied`、`activated=true`、`content_hash` = 预检哈希、`converted_count`/`inserted_count`/`unsupported_count`/`disabled_count` 合理、`bundle_hash` 为新值。
7. 立即 `GET /active-bundle`：version 应变为 `<source>-<sync 版本>`（slug 化），bundle_hash 应等于响应的 `bundle_hash`，`rule_count` 变化 = 新增 − 移除。
8. 校验 `rule_counts`：变化应只落在目标 category（如 traffic 585→新值），其余 category 不变；求和仍等于 `rule_count`。
9. 校验 `/rules/stats`：对应 category 数值同步变化，`count_semantics.traffic.ledger_digest` 等于新 bundle_hash，`totalRules = rule_count + xdr`。
10. 校验引擎确实换包：确认 hot reload 成功（`bundles`/引擎状态无 error；如可用，查 `rule_hot_reload_events` 或引擎侧 served revision）。
11. 校验审计：`rule.source.parse`、`rule.source.persist`、`rule.source.sync` 三类 succeeded 条目齐全，`MarkSynced` 把新 version 行从 `staged` 置为 `synced`；确认没有 `staged` 残留。
12. 校验“控制台禁用不被复活”：若该源存在 `disabled=true` 规则，确认 `disabled_count>0` 且同步后仍为禁用；必要时抽查一条被禁用规则 ID 不在新 bundle 中。
13. 等待 >5 分钟（或直接用 `/versions`），确认 `/sources` 的 `current_version/content_hash/last_sync_at` 更新为新值。

异常与回滚：

14. 若 unchanged 预期却出现 `activated=true`：立即停止，保存响应与前后 bundle 快照，对比 `content_hash`，判断是否为镜像返回了不同字节（本次预检显示 ghproxy 对 sigma-full 曾返回 403 的 14 字节内容，镜像污染是真实风险）。
15. 回滚仅在人工确认后执行 `POST /rule-platform/rollback {"version":"db-active-20261029154745"}`，回滚后校验 bundle_hash 回到 `cbc8cae2…41e1`、rule_count=618、rule_counts 与第 4 节一致。
16. 校验失败/审计失败时，`rule_source_versions` 会留下 `staged` 行（集成测试已覆盖）；下次同步前清理或确认其不影响 active bundle。

## 附录：本次证据

- 采集脚本与原始 JSON 位于测试机临时目录（不在仓库）：`sources.json`、`active-bundle.json`、`bundles.json`、`versions.json`、`sync-runs.json`、`sources-after.json`、`upstream-precheck.json`、`upstream-precheck-extra.json`、`rules-stats*.json`
- 关键代码位置：
  - unchanged 快速路径与 activation：`server/cmd/rule_platform.go`（`syncRulePlatformSource`，unchanged 分支 ~L1110–1117，activation ~L1309）
  - source 目录缓存：`server/cmd/rule_platform.go` L71–88、`server/cmd/response_cache.go`
  - connector 目录/URL：`server/cmd/rule_platform.go` `ensureRuleSourceCatalog` L1381–1394
  - 自动同步调度器：`server/cmd/rule_platform.go` `startRuleSyncScheduler` L832–852
- 本次未执行：空 body 全量同步、`compile-preview`、`rollback`、任何 POST/PUT 修改 source 或规则开关。
