# AGENTS.md — LyFlow 开发规则（AI Agent 必读）

本文件是所有编码 Agent 在本仓库工作的第一入口。详细设计见 `docs/dev/DEVELOPMENT_GUIDE.md`。

## 0. 开始前必须阅读

1. `docs/dev/DEVELOPMENT_GUIDE.md`
2. `docs/dev/WORKQUEUE.md`
3. `docs/dev/PROGRESS.md`
4. `docs/dev/DECISIONS.md`
5. `/opt/lyflow/ENVIRONMENT.local.md`（私有环境文件，不在仓库中）

## 1. 硬边界

- **编译机**：只在 `BUILD_HOST`（见私有环境文件）上编译、构建镜像、打包产物。
  - 源码：`/opt/lyflow/src`
  - 产物：`/opt/lyflow/artifacts`
  - 日志：`/opt/lyflow/logs`
- **测试机**：只在 `TEST_HOST`（见私有环境文件）上做集成/E2E/压测/安装升级回滚。
  - 部署：`/opt/lyflow/deploy`
  - 数据：`/opt/lyflow/data`
  - 报告：`/opt/lyflow/reports`
- 不在测试机改代码后直接部署；不在本地绕过编译机构建产物。
- 不把任何密码、密钥、Token 写入仓库、脚本、Dockerfile、日志、镜像。
- 破坏性操作（删除数据卷、重装测试机、改网络）必须先快照并人工确认。

## 2. 工作方式

1. 一次只做一个 Task ID；从 `WORKQUEUE.md` 取下一个 `TODO`。
2. 先读相关代码和测试，再写一个失败测试，再实现。
3. 变更范围只限任务卡；不顺手重构无关模块。
4. 大改必须有 feature flag，默认关闭。
5. 数据库只加不删；API 只增不删；旧接口保留到新接口通过契约测试。
6. 每个任务结束更新 `PROGRESS.md` 和 `WORKQUEUE.md`。
7. 竣工前不停止：小决策按 `DECISIONS.md` 的默认规则选择并记录，继续下一个任务。
8. 只有以下情况允许停：里程碑 Gate 需要人类评审、机器不可达、凭据失效、磁盘满、破坏性操作无快照、需求与架构冲突。

## 3. 禁止事项

- 禁止修改 `third_party/`、Suricata、Wazuh、Elkeid、OpenRASP、`ly_probe` 的 vendored 源码。
- 禁止把 GPL 组件链接进自有二进制；一律独立进程/容器。
- 禁止把 `private/elkeid/`、Elkeid HUB/Console/HIDS-RASP 规则配置放进公开构建产物。
- 禁止重新引入 `ly_server` 的 MariaDB 查询层。
- 禁止伪造数据、假攻击线、假覆盖率。
- 禁止默认暗色主题；默认浅色，深色可切换。
- 禁止提交真实客户数据、真实 PCAP、密钥、证书。

## 4. 常用命令

```bash
cd /opt/lyflow/src

# Go 模块
(cd server && go test ./...)
(cd agent && go test ./...)
(cd pkg && go test ./...)
(cd security-engine && go test ./...)

# 前端
(cd frontend && npm ci && npm run typecheck && npm run lint && npm test)

# 部署配置
docker compose -f deploy/compose/lean.yml config
```

> 仓库 `go.work` 要求 Go 1.26.5；如果本机 Go 版本较低，使用 `GOTOOLCHAIN=auto` 或安装匹配版本。不要随意改 `go.work` 的版本。

## 5. 完成标准（Definition of Done）

- [ ] 代码符合任务卡范围
- [ ] 新增/修改测试通过
- [ ] Go/前端测试、typecheck、lint 通过
- [ ] 构建在 `BUILD_HOST` 完成，关键集成/E2E 在 `TEST_HOST` 通过
- [ ] API/契约变更已更新 `contracts/` 或 `pkg/contracts/`
- [ ] 数据库变更附带可回滚 migration
- [ ] 有日志、错误处理、超时、取消
- [ ] 有 feature flag（如涉及行为变更）
- [ ] 更新 `docs/dev/PROGRESS.md`、`docs/dev/WORKQUEUE.md`
- [ ] 无新增 secret、GPL 污染、未授权依赖
- [ ] 输出变更摘要、测试结果、风险、回滚方式

## 6. 任务模板

```text
Task: T{x.y} {名称}
Context: 读取 AGENTS.md、docs/dev/DEVELOPMENT_GUIDE.md、WORKQUEUE、PROGRESS、相关包与测试。
Environment: BUILD_HOST=/opt/lyflow/src；TEST_HOST=/opt/lyflow/deploy。
Constraints: 只改任务范围；不改 third_party/GPL；不删旧 API；默认 feature flag 关闭。
Plan: ...
Tests: ...
Implementation: ...
Result: 变更文件 / 测试结果 / 风险 / 回滚方式 / 未决事项
```
