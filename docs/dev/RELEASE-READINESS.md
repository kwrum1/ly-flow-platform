# LyFlow 发布就绪度（2026-10-29）

## 结论

| 维度 | 进度 | 说明 |
|---|---:|---|
| 功能开发 | ~98% | 总览、事件、Incident、资产、规则、RASP、流量、P1/P2/P3 已完成 |
| 功能验收 | 100% | `acceptance.py` **38/38**，覆盖新增防护/流量/RASP/lyprobe |
| 发布级验收 | ~85% | 剩余 clean VM、ESXi 快照、10k EPS、人工签字 |
| 综合 | **~93%** | 功能可演示、可部署；发布签字前还差 4 类环境/评审项 |

## 已完成

- `server:v60` / `frontend:v46` 已部署，验收 **38/38** 全部通过。
- P1：防护会话、自动值守、5 分钟 dry-run、失败回退 monitor、真实时间窗实测通过。
- P2：Suricata 57 条 + lyprobe 9 条规则集，`overlap=0`，sensor 已加载 57 条。
- lyprobe：上游 `ly_probe` 固定 revision 构建，独立 systemd 进程部署；真实 SQLi
  命中 `THREAT_TYPE=SQL/CRUD`，`threat_events` 落库；flow 双向记录都带威胁字段。
- P3：24 条 CRS PL1–2 请求规则；WSGI/ASGI 中间件 monitor/dry-run/block 三态；
  真实 HTTP block 返回 403。
- 离线发布包：`release-v60.tgz`，SHA256
  `60f933e14994b5bf76276abbfcc2a054fe6cb9f6c2d0cb5c4358c01e7d118a27`。

## 剩余发布级项

| # | 项目 | 状态 | 阻塞 | 预估 |
|---|---|---|---|---|
| 1 | clean VM Agent 安装/自检/回滚 | 未完成 | 需要 clean VM / ESXi 凭据 | 2–3 天 |
| 2 | ESXi 快照与恢复演练 | 未完成 | 需要 ESXi 凭据 | 1 天 |
| 3 | 10k EPS 容量复测 | 未完成 | 当前 4 vCPU 测试机不具备容量 | 1–2 天 |
| 4 | G1–G5 人工评审签字 | 未完成 | 需要评审人 | 0.5–1 天 |
| 5 | T4.1/T4.2/T4.5/T4.7/T4.8 复核 | 部分 | 文档/打包/许可审计 | 1–2 天 |
| 6 | BPF 五元组分流 | 挂起 | 非验收项，当前流量未到瓶颈 | — |

## 建议顺序

1. 先做 **T4.8 文档/许可/安全审计** 与 **T4.7 打包复核**（不依赖环境，能立刻推进）。
2. 用现有 `release-v60.tgz` 做一次离线安装/回滚演练，替代部分 clean VM 证据。
3. 拿到 ESXi 凭据后补 clean VM 与快照。
4. 最后做 10k EPS 容量与人工签字。

## 不阻塞发布的功能项

- BPF 分流设计已评审，暂不实施；当前瓶颈在消费端，不在抓包。
- Vector 未启用；lyprobe 走自有 NetFlow collector，不依赖 Vector。
