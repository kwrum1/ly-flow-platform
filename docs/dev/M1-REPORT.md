# M1 验收报告（数据主链与 UI shell）

- 日期：2026-10-19
- 分支：`feat/lyflow-v2`
- 基线：`gitea/main`（`f02f000`）→ 当前 `50addf8`（+ M1 文档提交）
- 环境：编译机 Ubuntu 25.10 / 40C / 62G；测试 VM 尚未就绪

## 1. 范围

M1 包含 T1.1–T1.7：

- Ingest v2：`POST /api/v2/ingest/events`
- Query v2：`GET /api/v2/events`、`GET /api/v2/events/{id}`
- 新 UI shell：ly_vis 风格顶部导航 + 二级页签
- 总览页：KPI、阶段分布、来源覆盖、最近事件
- 事件中心：筛选、游标分页、详情抽屉、证据面板
- 统一搜索：`q` 关键词
- 契约/路由：119 条路由，digest 更新

## 2. 已通过的验证

| 验证 | 命令 | 结果 |
|---|---|---|
| Go 契约 | `cd pkg && go test ./contracts -count=1` | ok |
| Go 数据库 schema | `cd server && go test ./analytics -count=1` | ok |
| Ingest | `cd server && go test ./ingestv2 -count=1` | ok |
| Query | `cd server && go test ./queryv2 -count=1` | ok |
| 路由契约 | `cd server && go test ./cmd -run TestRouteAPIContract -count=1` | ok |
| 前端类型 | `cd frontend && npm run typecheck` | ok |
| 前端构建 | `cd frontend && npm run build` | ok |
| 快速全量 | `bash scripts/dev/test-all.sh fast` | all fast checks passed |
| 许可/密钥/私有边界 | `check-licenses.sh` / `check-secrets.sh` / `check-private.sh` | ok |

## 3. 尚未完成（测试 VM 就绪后补）

1. 真实 ClickHouse/PostgreSQL 迁移与写入/查询联调。
2. 真实 HTTP 端到端：认证 -> ingest -> ClickHouse -> query -> UI。
3. 浏览器 E2E：总览、事件中心、详情抽屉、搜索。
4. 1 Gbps / 20k EPS / 查询 p95 压测。
5. 30 天热数据 + 180 天冷数据保留验证。
6. 可访问性/截图（375/768/1280）。
7. 前端 lint 历史 warning 清理（当前 0 error，约 1560 warning）。

## 4. 风险

- 测试 VM 未就绪，M1 的“真实集成”证据不足；不能把当前状态称为生产验收通过。
- 事件列表的 stage/source 聚合在总览页基于最近 100 条样本；T2.6 改为服务端聚合。
- 前端部分文件存在 CRLF/LF 混用，导致 diff 噪声；后续加 `.gitattributes` 统一。
- 查询关键词为子串匹配，未做全文索引/相关性排序。

## 5. Gate G2 结论

**READY_FOR_REVIEW**：代码与单元/契约/构建验证通过；真实集成与压测待测试 VM。按“不停止”策略继续 M2（ATT&CK 元数据、阶段状态机、实体图），不等待 G2 空转。

## 6. 下一步

- T2.1 ATT&CK 元数据与映射
- T2.2 阶段状态机
- T2.3 实体图与关联
- T2.4 Incident API/生命周期
- T2.5 攻击链/时间线 UI
- T2.6 ATT&CK 覆盖率
- T2.7 关联验证
