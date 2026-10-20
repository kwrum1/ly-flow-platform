# LyFlow 二次功能回归测试报告

- 日期：2026-10-20
- 测试角色：功能测试专家（二次回归）
- 被测版本：`feat/lyflow-v2`，测试时提交 `d83ca9b`
- 构建机：`10.1.18.100`
- 测试机：`10.1.18.126`
- 测试入口：`https://10.1.18.126/`
- 证据目录：`/opt/lyflow/reports/G5/regression-2026-10-20/ui/`

## 1. 结论

本轮二次回归覆盖 UI、认证/角色、Incident、响应处置、规则中心、流量观测、NetFlow/lyprobe、运行威胁/eBPF、事件深链和异常空态。

- 完整 UI 巡检：17 个页面/视口，全部 HTTP 200，横向溢出 0，console/page error 0，异常请求 0。
- 定向回归：`rc=0`，关键断言全部通过。
- 发现并已修复 6 个问题；保留 2 个中风险性能问题作为后续优化。
- 未执行破坏性响应动作；未修改生产数据卷。

## 2. 测试方法

### 2.1 自动化 UI 巡检

使用仓库内 `frontend/e2e/live-product-validation.js`，Playwright + Chromium，`ignoreHTTPSErrors=true`，桌面 1440×900 与移动 390×844。

覆盖页面：

`/login`、`/dashboard`、`/situation/global`、`/xdr`、`/incidents`、`/assets`、`/events`、`/runtime`、`/rules`、`/rule-updates`、`/control-center`、`/install-config`、`/traffic-threats`、`/rasp`，以及 dashboard/agents/login 移动端。

结果：

- 页面状态：全部 200
- `consoleErrors=0`
- `pageErrors=0`
- `unexpectedRequestFailures=0`
- `badResponses=0`
- 所有页面 `horizontalOverflow=0`
- 证据：`validation5.stdout.json`、`validation5.stderr.txt`、各页面 PNG

> 注：中间一次巡检出现浏览器 `ERR_NETWORK_CHANGED` 导致动态 chunk 加载失败，复跑 `validation4` 清零；判定为构建机网络瞬断，非产品缺陷。

### 2.2 定向回归

新增 `frontend/e2e/second-regression.js`，覆盖：

1. 规则中心在慢速规则源接口下仍能先显示引擎卡片。
2. 规则中心显示 lyprobe 实装引擎、6 条真实规则、ET Open 子集来源。
3. 流量观测页显示 lyprobe 探针和真实 bytes/packets。
4. 响应处置页不存在重复的“发起响应动作”表单。
5. 运行威胁页显示 `runtime.process.exec` 且检测引擎为 `eBPF`。
6. `/events/does-not-exist` 显示“未找到事件”，不静默回退列表。
7. Incident 详情只发起 1 次详情请求，且显示阶段时间线与证据包。
8. viewer 账号登录后进入 `/forbidden`，访问 `/xdr` 仍停留 `/forbidden`。

结果：`rc=0`，证据：`second9.stdout.json`、`second9.stderr.txt`、`second-regression.json`。

### 2.3 API/数据核验

- `/api/v1/engine-rules?engine=lyprobe`：200，6 条，约 0.37s。
- `/api/v1/engine-runtime/status`：`lyprobe.rule_count=6`，`transport=netflow-v9`。
- `/api/v1/traffic/flows?limit=200&agent_id=g5-real-agent`：200 条中 156 条 lyprobe，0 条 `0.0.0.0` 坏记录。
- `/api/v1/traffic/flows?limit=50&query=lyprobe`：50/50 条 lyprobe。
- `traffic_sessions`：lyprobe 记录 273 条，最新 `observed_at=12:26`。
- `/api/v1/component-alerts/runtime?limit=100`：51 条 `runtime.process.exec` 且 `backend=ebpf`。
- `traffic_sessions`/`flows` 的 lyprobe 记录包含真实 `bytes_in`、`packets`、`capture_source=lyprobe`。

## 3. 发现与修复

### F1（高，已修复）规则中心被慢速规则源阻塞

**现象**：登录后进入 `/rules`，9 秒后页面仍显示“正在读取实装引擎与上游…”，6 个引擎卡片不可见；规则清单本身已加载。

**原因**：`loadSourceData` 使用一个 `Promise.allSettled` 同时等待快速运行时状态和慢速规则源目录；`/rules/sources` 约 5.7s、`/rule-platform/sources` 约 4.8s，负载高时超过 9s。

**修复**：
- 拆分为两阶段：先加载 `/engine-runtime/status` + `/engine-health`，立即结束引擎卡片 loading。
- 上游目录单独使用 `upstreamLoading`，并为每个请求增加 8–12s 超时。
- 上游读取中显示“读取中”，不再显示误导性的 0。
- 证据：`rules-wait9s.png`、修复后 `second7` 中 `stillLoadingSources=false`。

### F2（高，已修复）流量观测页看不到 lyprobe 证据

**现象**：`/traffic-observe` 12 条会话全部为 `g5-real-agent`，lyprobe 数据不可见。

**修复**：
- 探针列优先显示 `lyprobe`，副标题显示归属主机。
- 详情增加“采集来源”。
- 后端 `/traffic/flows` 在带 query/agent/IP 过滤时将读取窗口扩大到 5000 条，关键词 `lyprobe` 可检索到证据。
- 验证：页面首屏已出现 `lyprobe / g5-real-agent`，流量含真实 bytes/packets。

### F3（中，已修复）运行威胁页 eBPF 来源显示为“-”

**现象**：`runtime.process.exec` 事件的“检测引擎”列为 `-`，无法区分 eBPF、auditd、procfs。

**修复**：运行时事件使用 `backend` 作为来源；映射 `eBPF`、`auditd`、`procfs`、`日志审计`。验证页面已显示 `eBPF`。

### F4（中，已修复）NetFlow 0.0.0.0 记录进入流量页

**现象**：流量页出现 `0.0.0.0:0 → 0.0.0.0:0 / 58`。

**修复**：NetFlow 解码阶段将 unspecified 地址视为无效；地址为空时丢弃记录。新增单测 `TestDecodeV9RejectsUnspecifiedAddresses`。验证最近 200 条 lyprobe 流中坏记录为 0。

> 说明：Agent 抓包中 `0.0.0.0:68 → 255.255.255.255:67` 属于真实 DHCP 广播，不是 NetFlow 坏记录，保留展示。

### F5（中，已修复）规则总数与清单总数不一致

**现象**：规则中心标题显示 `30,374 条原生规则`，规则清单显示 `共 29,906 条`，差 468 条。

**原因**：标题使用引擎 `counts` 求和（Suricata 使用生效 bundle 479），清单使用实际规则项（Suricata 本地 11 条）；两者语义不同。

**修复**：标题改用规则清单 `total`，与分页清单一致；引擎卡改为“生效规则”口径，避免把生效 bundle 与本地清单混为一谈。复测标题与清单均为 `29,906`，卡片显示“生效规则 479/22,214/...”。

### F6（通过）非管理员访问控制

- viewer 账号 `reg_viewer` 登录后进入 `/forbidden`。
- 直接访问 `/xdr` 仍停留 `/forbidden`，无重定向循环。
- 页面文案：“当前账号没有控制台权限”。

### F7（通过）Incident 详情性能与重复请求

- 点击 Incident 后仅 1 次 `/api/v1/incidents/{id}` 请求。
- 详情渲染耗时约 72ms（点击到读取页面文本）。
- 页面显示“攻击阶段”“阶段时间线”“证据包”，状态迁移控件正常。
- 截图：`incident-detail.png`。

### F8（通过）响应处置页

- 不存在“发起响应动作”表单。
- 保留自动处置策略、动作历史、审批/执行/回滚记录。
- 页面文案明确“具体处置动作统一从攻击链 Incident 发起”。

### F9（通过）事件深链

- `/events/does-not-exist` 显示“未找到事件 does-not-exist，链接可能已归档或失效。”
- 同时保留事件列表，不再静默显示普通列表。
- 请求返回 404 属预期，已从自动化 console 过滤中排除。

### F10（中，已修复）lyprobe 引擎卡显示“无心跳”

**现象**：lyprobe 有持续 NetFlow 流量，但 `/engine-runtime/status` 返回 `running=false`、`rules_loaded`。

**修复**：后端读取 `flows:raw` 最近 500 条，发现 5 分钟内的 `source=lyprobe` 记录即返回 `running=true`、`status=running` 和 `last_export`。验证返回 `running=true`，`last_export=13:29:53Z`，规则卡显示“运行中”。

## 4. 保留问题（未阻塞本轮）

### R1（中，已缓解）规则源目录接口冷启动仍偏慢

- 冷请求 `/api/v1/rules/sources`：约 8.4s
- 冷请求 `/api/v1/rule-platform/sources`：约 0.3–4.8s
- 已增加 30s 进程内响应缓存：第二次请求分别降至约 0.01s；来源更新时立即清缓存。
- 引擎卡片已不再被阻塞；冷启动期间上游表显示“读取上游…”。后续可考虑持久缓存或异步预热。

### R2（中）服务重启后 Incident 首次列表冷启动慢

- 服务重启后首次 `/api/v1/incidents?limit=3&live=0`：约 15.6s。
- 后续同一请求：约 14ms。
- 推测为 DB/Redis/规则缓存冷启动；建议启动预热或在健康检查中标记 warmup 状态，避免 UI 首屏误判超时。

## 5. 环境问题（非产品缺陷）

- 构建机缺少 `/dev/urandom`、`/dev/random`，导致 Chromium NSS 初始化失败（`nss_error=-8023`），Playwright 无法启动。已补建设备节点后恢复；测试机本身正常。
- 测试机 Docker 守护进程曾因容器重启循环卡住，已重启 Docker 恢复；容器与数据卷保留。
- 浏览器自动化未绕过真实证书信任：Playwright 测试上下文显式 `ignoreHTTPSErrors` 仅用于自签测试站。

## 6. 修复提交

- `8233ca8`：规则中心两阶段加载、eBPF/探针来源展示、流量过滤窗口。
- `459dab4`：NetFlow unspecified 地址过滤。
- `13b10f8`、`c1064b2`：NetFlow 单测与非 v9/空地址校验。
- `25c84f6`、`6c2125b`、`6a91519`：二次回归脚本与登录等待修正。
- `ff39e3b`：auditd fallback 单测。
- `82492d1`：规则总数与分页清单口径统一（30,374 → 29,906 一致）。
- `90b7518`：lyprobe 流量心跳 + 规则源目录 30s 缓存。
- `d152ee4`：6 列引擎卡、生效规则文案、探针/运行时来源与筛选优化。
- `d83ca9b`：流量观测 lyprobe 探针筛选与回归断言加固。

## 7. 测试结论

本轮二次回归通过。高优先级 UI 阻塞、lyprobe 证据可见性、eBPF 来源标识和 NetFlow 无效地址已修复并复测；剩余问题为中低风险的性能/心跳优化，不影响本轮功能验收。
