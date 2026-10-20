# LyFlow 生产级功能验收报告

- 日期：2026-10-20
- 验收角色：功能测试专家 + UI/开发联调
- 分支：`feat/lyflow-v2`
- 验收提交：`303ed35`（UI 合并与生产验收脚本）
- 构建机：`10.1.18.100`
- 测试机：`10.1.18.126`
- 入口：`https://10.1.18.126/`
- 证据目录：`/opt/lyflow/reports/G5/production-acceptance-2026-10-20/`

## 1. 验收结论

**功能与 UI 生产验收通过，发布级验收保留 2 项环境/容量例外。**

- 生产验收 Playwright：`rc=0`
- 全量 UI 巡检：17 个页面/视口，HTTP 200，横向溢出 0，console/page error 0，异常请求 0
- 定向生产验收：19 个页面、6 条 legacy 路由、重复 UI 检查、Incident/响应/证据/规则/流量/eBPF 全部通过
- API 烟测：29 个读接口 + 登录全部 200，`FAILURES=[]`
- Agent：`ly-agent` 运行中，eBPF 采集器 active，bpftrace 在运行
- lyprobe：最近 200 条流量中 158 条 lyprobe，`0.0.0.0` 坏记录 0；引擎状态 `running=true`，`last_export` 新鲜
- 运行威胁：68 条 `runtime.process.exec` 且 `backend=ebpf`
- 规则中心：lyprobe 6 条真实规则；清单与标题均为 29,906 条
- security-engine：`healthy`，`cpu_budget_ms=1000`，`restart_count=0`

## 2. 去重与遗留功能清理

以下 legacy 路由已改为 301/SPA 重定向到 canonical 页面，页面文件已删除：

| legacy 路由 | canonical 页面 |
|---|---|
| `/application-threats` | `/rasp` |
| `/system-security-audit` | `/runtime` |
| `/host-ops` | `/assets` |
| `/real-time-posture` | `/xdr` |
| `/rule-visibility` | `/rules` |
| `/rule-updates` | `/rules` |

同时：

- 删除 `ApplicationThreats.vue`、`SystemSecurityAudit.vue`、`HostOps.vue`、`RealTimePosture.vue`、`RuleVisibility.vue`、`RuleUpdates.vue` 六个重复页面。
- `/control-center` 移除重复的 Agent 列表与 Agent 统计，只保留抓包接口、设备地点、时间设置。
- 导航「控制中心」改名为「平台设置」，描述改为「采集接口、设备地点与时间」。
- 保留 `/timeline`、`/trace` 这两个产品契约中的 canonical 调查页，不再新增同类型入口。
- 后端旧 API 按“只增不删”原则保留，不在本轮删除。

## 3. 本轮发现并修复

### F1（高）security-engine watchdog 重启循环

**现象**：security-engine 约每 1–2 分钟因 `runtime CPU budget exceeded` 停止，`/engine-runtime/status` 503，规则中心/引擎健康不可用。

**修复**：
- `g5-host.yml` 与 `lean.yml` 增加 `SECURITY_ENGINE_CPU_BUDGET_MS=1000`。
- 重建 security-engine 容器。
- 验收：`cpu_budget_ms=1000`，`restart_count=0`，`/health` 200，控制健康 `healthy`。

### F2（高）lyprobe 心跳在流量洪峰下丢失

**现象**：lyprobe 有持续 NetFlow，但状态偶发 `rules_loaded / 无心跳`。

**修复**：心跳扫描从最近 500 条扩大到 5000 条 `flows:raw`；仍保持 5 分钟窗口和 2s Redis 超时。验收：`running=true`，`last_export` 新鲜。

### F3（中）规则源目录冷启动阻塞

**修复**：
- `/rule-platform/sources` 增加启动预热和 5 分钟 TTL 缓存。
- `/rules/sources` 保留 5 分钟 TTL 缓存。
- 引擎卡片先渲染，不再等待上游目录。

### F4（中）流量会话首次查询冷启动 20s

**修复**：服务启动后后台预热 `loadPersistentTrafficSessions`。验收：首次会话查询约 0.22s。

### F5（中）规则源数量与清单口径

**修复**：标题使用规则清单 total；引擎卡明确“生效规则”。验收标题与清单均为 `29,906`。

## 4. 生产验收矩阵

### 4.1 UI 页面

`/dashboard`、`/situation/global`、`/xdr`、`/incidents`、`/timeline`、`/assets`、`/events`、`/runtime`、`/rasp`、`/trace`、`/rules`、`/engines`、`/control-center`、`/install-config`、`/users`、`/traffic-observe`、`/traffic-threats`、`/response`、`/evidence`。

全部 200；移动端 dashboard/assets/login 无横向溢出。

### 4.2 功能断言

- 非管理员 viewer：登录后 `/forbidden`，访问 `/xdr` 仍 `/forbidden`。
- Incident：详情 1 次请求，约 58–72ms，阶段时间线、证据包正常。
- 响应处置：无重复“发起响应动作”，自动策略与动作历史正常。
- 事件深链：`/events/does-not-exist` 显示“未找到事件”。
- 流量观测：lyprobe 筛选可用，显示真实 bytes/packets。
- 运行威胁：eBPF 来源显示，process.exec 事件可见。
- 规则中心：lyprobe 规则卡、6 条规则、11 个真实上游、29,906 条清单。
- 证据库：证据包列表、生成/上传入口正常。

### 4.3 API 烟测

健康、认证、资产、Incident、Event v2、XDR、全球态势、流量、组件告警、规则、引擎、响应、证据、平台时间等 29 个接口全部 200，`FAILURES=[]`。

## 5. 保留例外

1. **Clean VM 安装/自检/回滚**：本轮未新建 VM，沿用现有测试机；ESXi 干净机验收仍未完成。
2. **容量目标**：20k EPS + 1Gbps 未在本轮重新压测；此前约 18.5k EPS。
3. **测试机 Docker 守护进程**：本轮出现容器状态不一致，已通过重启 Docker 恢复；属于测试环境稳定性问题。
4. **`/rules/sources` 冷启动**：首次约 5–8s，缓存后 0.01s；引擎卡不受阻塞，保留为后续优化。

## 6. 验收命令与证据

- `frontend/e2e/production-acceptance.js` → `acceptance5.stdout.json`，`rc=0`
- `frontend/e2e/live-product-validation.js` → `live-validation.stdout.json`，`rc=0`
- `frontend/e2e/second-regression.js` → `second-regression.json`，`rc=0`
- 截图、JSON：`/opt/lyflow/reports/G5/production-acceptance-2026-10-20/ui/`

## 7. 代码发布

- GitHub 仓库：`https://github.com/kwrum1/ly-flow-platform`
- 分支：`feat/lyflow-v2` 已通过 CI；本报告配套提交将同步到 `main`。
- CI：`.github/workflows/ci.yml` 使用受支持的 `actions/checkout@v4`、`actions/setup-go@v5`、`actions/setup-node@v4`。
- 云构建：`.github/workflows/release.yml` 继续构建 AMD64/ARM64 一键安装包，发布标签保持 `latest-server`。
- 代码清理：移除 6 个重复页面、6 条重复路由、控制中心重复 Agent 列表，以及仓库内过期编译二进制。
- 文档/截图：README 增加生产验收状态、界面预览与 GitHub Release 一键安装命令；截图位于 `docs/assets/screenshots/`。

## 8. 签署

- 功能测试：通过
- UI 验收：通过
- 开发联调：通过
- 发布级验收：`PASS_WITH_EXCEPTIONS`（clean VM、容量两项例外）


## 9. 发布修复与 GitHub 云构建最终状态（2026-10-20 晚）

- GitHub `main` 已包含生产验收代码、去重页面、截图与发布修复。
- 修复 Release 工作流 Windows Agent 编译失败：提交 `3ffa445` 误删了 6 个 Windows 平台文件，导致 `hiddenCommand`、`applyPlatformTrafficPolicy`、`runPCAPPacketCapture`、`readDiskUsage` 未定义。已从 `0ee2180` 恢复：
  - `agent/cmd/command_hidden_windows.go`
  - `agent/cmd/disk_windows.go`
  - `agent/cmd/pcap_windows.go`
  - `agent/cmd/tray_windows.go`
  - `agent/cmd/windows_defaults.go`
  - `agent/cmd/windows_install.go`
- 已在构建机验证 Windows amd64 Agent 与 Linux amd64 Agent 交叉编译，`agent` 全量单测通过。
- GitHub Actions：
  - Release run `39448186932`（提交 `fe221b0`）成功：AMD64/ARM64 镜像、服务端安装包和 `latest-server` 发布全部成功。
  - `latest-server` 资产：`lyflow-server-amd64.tar.gz`（588,918,057 字节）、`lyflow-server-arm64.tar.gz`（540,676,698 字节）。
  - CI run `39448186884` 暴露事件清单缺少恢复的 Windows 抓包流，已重新生成 `docs/generated/event-contract-inventory.json`（192 条扫描路径），随文档提交同步。
- 云构建与本地代理环境：
  - `.github/workflows/release.yml` 使用 `GOPROXY=direct`，不设置 HTTP/HTTPS 代理；规则、Go 依赖、npm 和 Docker 基础镜像直接访问上游。
  - 移除构建机/测试机 Docker systemd 的 `99-no-proxy.conf` 代理覆盖；仓库脚本不再读取 `TASK13_AUTHORIZED_PROXY`。
  - 本地构建/安装脚本不注入代理变量。
- 发布门禁结论：功能/UI/API/Agent/lyprobe/eBPF/规则/响应/证据通过；clean VM 安装/回滚与 20k EPS 容量复测仍为本报告保留例外。
