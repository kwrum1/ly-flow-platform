# 文档索引与维护规则

本文档规定项目文档的权威关系。功能是否存在，以可运行代码、机器可读契约、测试和目标环境验收为准，不能仅凭页面、目录名或历史说明判断。

## 当前权威文档

| 文档 | 责任 |
|---|---|
| [`../README.md`](../README.md) | 项目入口、安装和默认拓扑 |
| [`RELEASE-1.0.md`](RELEASE-1.0.md) | 1.0 正式版发布说明 |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | 当前生产架构、数据流和部署边界 |
| [`API.md`](API.md) | 人工阅读的 API 摘要；机器契约优先级更高 |
| [`zh/当前功能盘点与能力边界.md`](zh/当前功能盘点与能力边界.md) | 已实现能力、限制和未承诺能力 |
| [`zh/后续工作计划.md`](zh/后续工作计划.md) | 接盘后的唯一执行计划 |
| [`dev/DETECTION-ACCEPTANCE-2026-10-30.md`](dev/DETECTION-ACCEPTANCE-2026-10-30.md) | 检测能力、主动防御和抓包链路验收 |
| [`dev/ALERT-TUNING-2026-10-30.md`](dev/ALERT-TUNING-2026-10-30.md) | 规则降噪、转换器保真和误报处理 |
| [`dev/MIRROR-SENSOR-125.md`](dev/MIRROR-SENSOR-125.md) | 镜像抓包环境部署与观测 |
| [`CLICKHOUSE_EVENT_MIGRATION.md`](CLICKHOUSE_EVENT_MIGRATION.md) | 事件存储迁移和读切换约束 |
| [`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md) | 当前服务端包来源、构建校验和交付边界 |
| [`GITHUB-CI.md`](GITHUB-CI.md) | 当前正式服务端构建、周期、产物与历史清理 |
| [`../DESIGN.md`](../DESIGN.md) | 当前前端视觉设计系统，不是产品功能计划 |

机器可读权威包括：

- `contracts/product-acceptance/v1/route-api-contract.json`：服务端路由、认证、角色和持久化预期。
- `contracts/product-acceptance/v1/frontend-routes.json`：前端路由保留、合并和删除决策。
- `security-coverage.yaml`：安全信号到分析器、输出流和 XDR 的覆盖关系。
- `scripts/qa/expected-tests.txt` 与各 QA manifest：验收测试入口。

## 历史资料

`docs/archive/` 仅保存历史版本对比和审计记录。历史文档中的提交、release、现场验证和限制只对其记录时点有效，不得用作当前功能承诺或新工作计划。

## 维护规则

1. 新功能必须同时更新代码、机器契约、测试和当前功能盘点。
2. 计划只维护在 `zh/后续工作计划.md`；完成项转入功能盘点，不继续保留多个 TODO 清单。
3. 实验、QA、兼容和生产能力必须显式标注，不使用“支持”一词混合表达。
4. 运行时内存状态、测试夹具和页面占位不算持久化能力。
5. 未完成目标写退出标准和证据，不以提交数量或目录数量代替完成度。
6. 文档不得包含口令、token、私钥或真实环境凭据。
7. 当前安装、架构和发布说明必须与正式 Compose、安装脚本和 GitHub 工作流同步；历史脚本只能在归档或 QA 边界中说明。
