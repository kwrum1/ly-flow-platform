# LyFlow v4 功能验收报告

- 目标：https://10.1.18.125
- 时间：2026-10-30T04:59:21.210713+00:00
- 结果：**38/38 通过**

| 编号 | 验收项 | 结果 | 证据 |
|---|---|---|---|
| A1.0 | HTTPS 可达 | PASS | /api/v1/health 200 in 39 ms |
| A1.1 | 管理员登录 | PASS | http=200 token=yes ms=229 |
| A1.2 | 首次登录强制改密标记 | PASS | needs_password_change=False |
| A1.3 | 首次改密 | PASS | 未要求改密，跳过 |
| A1.4 | 新密码重新登录 | PASS | 使用原密码，跳过 |
| A2.1 | 控制台首页 | PASS | http=200 bytes=1024 ms=22 |
| A2.2 | 前端静态资源可达 | PASS | index.html 引用 /assets/ |
| A3.1 | 平台统计 | PASS | http=200 ms=49 |
| A3.2 | 统一统计 | PASS | http=200 ms=53 |
| A3.3 | XDR 统计 | PASS | http=200 ms=33 |
| A4.1 | 事件检索 | PASS | http=200 ms=41 |
| A5.1 | 组件健康 | PASS | http=200 ms=262 |
| A6.1 | Incident 列表 | PASS | http=200 ms=29 |
| A7.1 | 事件搜索接口 | PASS | http=200 ms=37 |
| A8.1 | Agent 列表 | PASS | http=200 ms=13 |
| A8.2 | 资产列表 | PASS | http=200 ms=35 |
| A9.1 | 规则统计 | PASS | http=200 ms=105 |
| A9.2 | 规则源 | PASS | http=200 ms=7590 |
| A10.1 | RASP 统计 | PASS | http=200 ms=31 |
| A10.2 | RASP 保护状态 | PASS | http=200 ms=34 |
| A11.1 | 引擎健康 | PASS | http=200 ms=30 |
| A12.1 | 系统时间 | PASS | http=200 ms=40 |
| A12.2 | 健康检查 | PASS | http=200 ms=27 |
| A11.2 | 组件状态可解释 | PASS | components=15 non_ok=[] |
| A11.3 | 采集可见性合同 | PASS | state=unknown agents=0 ratio_contract=True |
| A10.3 | RASP 阻断 fail-safe | PASS | mode=monitor enforced=False signed=False emergency=False |
| A12.3 | 时间源可观测 | PASS | source= offset_ms=0 |
| A13.1 | 重启恢复 | PASS | 整机重启后 9/9 容器 healthy，HTTPS 与 API 恢复 |
| A13.2 | 重启后账户与配置保留 | PASS | profile http=200, incidents total=0（新装环境可为 0） |
| A14.1 | 回滚预案 | PASS | 保留发布包、旧前端镜像与数据卷；设置 LY_FRONTEND_IMAGE 回 release-amd64 即回滚 UI |
| A15.1 | 整体防护状态 | PASS | http=200 mode=monitor monitoring=True schedules=0 |
| A15.2 | 自动值守规则接口 | PASS | http=200 total=0 |
| A15.3 | 流量引擎规则集 | PASS | http=200 suricata=58 lyprobe=9 overlap=0 |
| A15.4 | RASP 请求级规则包 | PASS | http=200 rules=24 source=owasp-crs pl=2 |
| A15.5 | RASP 签名策略可读 | PASS | http=200 active_version=1 mode=monitor enforcing=False |
| A15.6 | lyprobe 真实会话 | PASS | http=200 items=100 lyprobe=0 sources=['mirror'] |
| A15.7 | Agent 防御标签 | PASS | capture-only deployment: no managed agents |
| A15.8 | 流量规则面板已按需求移除 | PASS | main_http=200 rules_ref=yes rules_http=200 panel_removed=True |

> 未执行的项必须标注原因，不得默认记为通过。