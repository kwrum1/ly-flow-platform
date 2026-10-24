# 生产运行优化与误报治理记录

- 日期：2026-10-24
- 环境：`https://10.1.18.198/`
- 目标：基于连续运行数据修复资源、关联、误报和页面口径问题，保持生产级可运维性。

## 1. Redis 资源治理

运行数据：

- Redis 最大内存 8 GB，`noeviction`
- `flows:semantic` 约 310 万条、`telemetry:traffic` 约 125 万条
- 安全引擎无法创建 consumer group，重启计数达到 36

修复：

- Redis 实时流保留从 180 天解耦，默认 `REDIS_STREAM_RETENTION_HOURS=2`
- 清理周期从 6 小时缩短到 15 分钟
- 清理覆盖 `flows:raw`、`flows:semantic`、`sessions:semantic`、`logs:raw`、`telemetry:traffic`、`telemetry:runtime`、`telemetry:rasp`、`telemetry:log_audit`、`events:dead-letter` 等全部实时流
- 历史审计仍由 PostgreSQL / ClickHouse 保存

结果：Redis 从约 5.2 GB 降至约 1 GB，安全引擎不再因 OOM 重启。

## 2. 安全引擎 CPU 预算

- 运行日志显示 `security-engine runtime CPU budget exceeded`
- 生产 compose 增加 `SECURITY_ENGINE_CPU_BUDGET_MS: "1000"`
- 安全引擎当前 `running / healthy / restarts=0`

## 3. 内网横向 Incident 去重

问题：

- 单事件规则把每个流量事件都生成一个 Incident
- 同一 XSS 规则在 30 分钟内产生 240 个重复活动 Incident

修复：

- 按“来源 IP + 受害 IP + 规则 ID”聚合候选
- 同一组合生成一个 Incident，多个事件作为证据时间线
- 对白名单命中的候选跳过
- 对历史逐事件 `inc-traffic-alert-*` 候选执行批量闭环，保留审计
- 当前活动 Incident：13 条，均为按来源/受害资产聚合后的横向候选

## 4. 误报优化

- `GPL POLICY PCAnywhere server response`（`et-open-2100566`）加入默认噪声策略
- 高频 XSS 扫描不再产生每事件 Incident，而是按资产对聚合
- 保留原始事件供事件中心与审计，不伪造删除

## 5. 总览口径

- 安全评分改为按最高未闭环 Incident 等级计算，并随数量有限扣分
- “未闭环高危/严重”和“未闭环 Incident 等级”使用同一批未闭环 Incident
- “检测活动趋势”保留 10 分钟原始检测事件，并明确标注不等同于 Incident

## 6. 验证

- Redis 约 1–3 GB，低于 8 GB maxmemory
- 安全引擎 `healthy`、`restarts=0`
- LyFlow 探针 `running=true`
- 活动 Incident 从 240 降至 13
- 18 个生产页面 HTTP 200、0 错误、0 横向溢出
- 前端 typecheck、测试、build 通过
- 后端 `server/cmd` 测试通过

## 7. 部署

- 服务器二进制和前端静态资源热替换
- 安全引擎使用生产 compose 重新创建以加载 CPU 预算配置
- 未删除数据卷，未重建数据库，未重置管理员密码
