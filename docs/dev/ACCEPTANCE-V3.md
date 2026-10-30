# LyFlow v3 功能验收报告

- 目标：https://10.1.18.241
- 时间：2026-10-28T19:11:33.832346+00:00
- 结果：**25/27 通过**

| 编号 | 验收项 | 结果 | 证据 |
|---|---|---|---|
| A1.0 | HTTPS 可达 | PASS | /api/v1/health 200 in 28 ms |
| A1.1 | 管理员登录 | PASS | http=200 token=yes ms=201 |
| A1.2 | 首次登录强制改密标记 | PASS | needs_password_change=True |
| A1.3 | 首次改密 | PASS | http=200 ms=337 message=password changed |
| A1.4 | 新密码重新登录 | PASS | http=200 token=yes |
| A2.1 | 控制台首页 | PASS | http=200 bytes=851 ms=23 |
| A2.2 | 前端静态资源可达 | PASS | index.html 引用 /assets/ |
| A3.1 | 平台统计 | PASS | http=200 ms=28 |
| A3.2 | 统一统计 | PASS | http=200 ms=41 |
| A3.3 | XDR 统计 | PASS | http=200 ms=50 |
| A4.1 | 事件检索 | PASS | http=200 ms=58 |
| A5.1 | 组件健康 | PASS | http=200 ms=103 |
| A6.1 | Incident 列表 | PASS | http=200 ms=29 |
| A7.1 | 事件搜索接口 | PASS | http=200 ms=56 |
| A8.1 | Agent 列表 | PASS | http=200 ms=22 |
| A8.2 | 资产列表 | PASS | http=200 ms=34 |
| A9.1 | 规则统计 | PASS | http=200 ms=89 |
| A9.2 | 规则源 | PASS | http=200 ms=3759 |
| A10.1 | RASP 统计 | PASS | http=200 ms=23 |
| A10.2 | RASP 保护状态 | FAIL | http=200 ms=30 |
| A11.1 | 引擎健康 | PASS | http=200 ms=18 |
| A12.1 | 系统时间 | PASS | http=200 ms=29 |
| A12.2 | 健康检查 | PASS | http=200 ms=30 |
| A11.2 | 组件状态可解释 | PASS | components=13 non_ok=['security_engine.alert_bus', 'xdr.evaluator'] |
| A12.3 | 时间源可观测 | PASS | source= offset_ms=0 |
| A13.1 | 重启恢复 | FAIL | 需要重启后复跑本脚本确认（operator step） |
| A14.1 | 回滚预案 | PASS | 保留发布包与数据卷；删除虚机即回到部署前 |

> 未执行的项必须标注原因，不得默认记为通过。