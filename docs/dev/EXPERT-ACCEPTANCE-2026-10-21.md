# LyFlow 真机专家测试与修复记录

- 日期：2026-10-21
- 生产环境：`https://10.1.18.198/`
- 测试机：`10.1.18.8`（Ubuntu 26.04，root SSH）
- 测试方式：生产 UI + 真实 Agent + API 烟测 + Playwright 页面巡检
- HTTPS：测试侧使用自签证书信任模拟（Playwright `ignoreHTTPSErrors`、Agent `insecure_skip_verify`）

## 1. 本轮修复

### 1.1 LyFlow 探针误报异常

**现象**：生产有持续镜像抓包和流量告警，但引擎健康与规则中心把 LyFlow 探针标为异常/无心跳。

**原因**：探针心跳只识别 `source=lyprobe`，而生产镜像采集写入的是 `source=local-mirror-capture`、`capture_source=mirror`。

**修复**：探针心跳同时接受 `local-mirror-capture`、`mirror` 和镜像探针名称；`last_export` 使用真实最近流量时间。

**验证**：`/api/v1/engine-runtime/status` 返回 `running=true`、`status=running`，引擎健康与规则中心均显示运行中。

### 1.2 YARA 误报正常

**现象**：测试机没有原生 YARA executable，但 Agent capability 仍显示 YARA 运行中。

**原因**：Agent 已明确上报 `installed=false`、`last_error=native yara executable is unavailable` 时，后端仍使用 capability fallback 覆盖为运行中。

**修复**：只有 Agent 未提供引擎状态时才使用 capability fallback；显式错误不再被覆盖。

**验证**：引擎健康显示 YARA「未安装」；规则中心显示 YARA「未安装」，不再显示虚假运行状态。

**补齐能力**：Agent 安装器新增 YARA CLI 自动安装（apt/dnf/yum/apk）和 `/api/v1/agent/yara/rules` 规则包下载；测试机已安装 YARA 4.5.5，规则包 6,996,814 字节，重启 Agent 后引擎健康显示 YARA `installed=true`、`running=true`。

### 1.3 规则源文案与更新逻辑

**现象**：所有规则源都显示「可更新」，无更新时按钮仍可点击且点击无变化；部分来源显示未上报/无心跳。

**修复**：

- 有可用更新 → `有新版本` + 更新按钮
- 当前版本等于上游版本 → `已是最新`，不显示更新按钮
- 没有版本记录 → `未上报`，显示同步按钮
- 最近同步无记录 → `未同步`（不再使用未上报）
- 引擎卡片「可更新」只统计真实有更新的来源
- 头部显示「上游规则源 / 可更新」两个数量

**验证**：Falco 有更新时成功同步 3 条规则并重新编译；同步后状态变为「已是最新」，按钮消失。其余 10 个来源均为已是最新。

### 1.4 平台设置布局

- 重做页面头部、设置卡片、字段间距、按钮和响应式布局。
- 三块设置内容完整展开，不再被旧 Agent 表格行高压缩。
- 时间设置改为两列，服务器时间/平台时间只读，修改时间与 NTP 对齐。

### 1.5 真实 Agent 安装与完整性

- 在 `10.1.18.8` 完成全新安装，服务 `active`。
- 验证 Agent 在线、心跳、资产入库、`flows:raw` 真实流量上报。
- 修复公开一键包缺少签名摘要文件导致 Agent 启动失败的问题：服务端使用平台 policy signer 为 `/app/agents/linux/<arch>/ly-agent` 动态签发 `lyflow.signed_digest.v1` 摘要，安装器下载摘要与 policy root 后启用 `AGENT_REQUIRE_BINARY_INTEGRITY=true`；配置摘要仍保持关闭（`AGENT_REQUIRE_CONFIG_INTEGRITY=false`），因为按主机生成的配置尚无稳定签名流程。
- 测试机使用新的摘要与 trust root 重启后仍在线，binary fail-closed 校验通过。

## 1.6 Java RASP probe 与 DPI 遗留设计

- 服务端镜像补齐 `probe/rasp/` 资产；Python/PHP/Java/Node.js/.NET 五个 probe 下载接口均返回 200，Java jar 为 13,074 字节。
- `DPI Engine` 是早期 legacy 设计，仅用于旧 `flows:raw` 迁移，不属于默认生产栈；已从源码和 UI 删除：
  - 删除 `dpi-engine/` 模块、legacy compose profile、构建/QA/覆盖脚本引用；
  - 删除旧 DPI 规则数据和编译预览；
  - 删除引擎健康、规则中心、事件筛选和态势中的 `DPI Engine` 卡片/入口；
  - 新 LyFlow 探针告警统一标记为 `lyprobe`，历史 `dpi_engine` 事件源仅保留契约兼容。

## 2. 测试结果

- 19 个生产页面巡检：全部 HTTP 200，`console/page error=0`，异常 API 响应 `0`，桌面横向溢出 `0`
- API 烟测：30 个接口全部 200，`FAILURES=[]`
- Agent：`test8-fresh` 在线，心跳正常，资产统计在线 1
- 流量：可按 Agent 查询真实 TLS/DNS/TCP 流
- 引擎健康：6 张卡片，LyFlow DPI / Suricata / LyFlow 探针 / Wazuh / OpenRASP / YARA；测试机 YARA 安装后运行中
- 规则中心：11 个上游，0 个可更新；Falco 更新实测成功
- 平台设置：抓包接口、设备地点保存接口均返回成功
- Agent 资产：`/api/v1/agent/rasp/probe/{python,php,java,nodejs,dotnet}` 全部 200
- Agent 完整性：签名摘要接口 200，policy root 200，测试机 binary integrity 开启并保持在线
- DPI 遗留：源码、legacy profile、旧规则和 UI 入口已删除
- Go：`pkg`、`server/cmd`、`server/cmd/netflow-collector`、`security-engine` 测试通过
- 前端：117 个测试通过，typecheck 通过，build 通过

## 3. 保留问题

1. Agent 配置摘要（`AGENT_REQUIRE_CONFIG_INTEGRITY`）仍关闭；当前只对 Agent 二进制做 fail-closed 签名校验，按主机生成的配置签名流程待补齐。
2. 生产镜像采集 PF_RING 内核模块不可用，当前自动回退 AF_PACKET。
3. 宿主机内存存在超配，需关注高并发时的内存压力。
