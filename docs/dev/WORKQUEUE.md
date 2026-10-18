# LyFlow 工作队列

> 顺序：M0 → M1 → M2 → M3 → M4。  
> 状态：`TODO` / `IN_PROGRESS` / `BLOCKED` / `REVIEW` / `DONE`。  
> 一次只做一个 Task；完成后立即取下一个未阻塞 Task。

## M0：基础与契约

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T0.0 | 环境接入与基线 | IN_PROGRESS | — | — |
| T0.1 | 建立开发规范与进度文件 | DONE | T0.0 | — |
| T0.2 | Feature flags 与配置 | DONE | T0.1 | — |
| T0.3 | Event v2 契约 | IN_PROGRESS | T0.1 | — |
| T0.4 | 证据模型与存储 schema | TODO | T0.3 | — |
| T0.5 | CI/测试脚本与许可检查 | TODO | T0.2 | G1 |

## M1：数据主链与 UI shell

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T1.1 | Ingest v2 | TODO | T0.3, T0.4 | — |
| T1.2 | Query v2 + 查询治理 | TODO | T1.1 | — |
| T1.3 | 新 UI shell | TODO | T0.2 | — |
| T1.4 | 总览页 | TODO | T1.2, T1.3 | — |
| T1.5 | 事件中心 + 详情 + 证据面板 | TODO | T1.2, T1.3 | — |
| T1.6 | 统一搜索 | TODO | T1.2 | — |
| T1.7 | M1 验收 | TODO | T1.1–T1.6 | G2 |

## M2：ATT&CK 与 Incident

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T2.1 | ATT&CK 元数据与映射 | TODO | T1.1 | — |
| T2.2 | 阶段状态机 | TODO | T2.1 | — |
| T2.3 | 实体图与关联 | TODO | T2.1 | — |
| T2.4 | Incident API/生命周期 | TODO | T2.2, T2.3 | — |
| T2.5 | 攻击链/时间线 UI | TODO | T2.4, T1.3 | — |
| T2.6 | ATT&CK 覆盖率 | TODO | T2.1, T2.4 | — |
| T2.7 | 关联验证 | TODO | T2.2–T2.6 | G3 |

## M3：Agent、RASP、响应

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T3.1 | `ly-agent` supervisor | TODO | T0.2 | — |
| T3.2 | Linux Elkeid 集成 | TODO | T3.1 | — |
| T3.3 | Windows Wazuh 集成 | TODO | T3.1 | — |
| T3.4 | OpenRASP Java/PHP | TODO | T3.1 | — |
| T3.5 | Elkeid RASP Python/Go/Node | TODO | T3.1 | — |
| T3.6 | Agent 门面/API/UI | TODO | T3.2, T3.3 | — |
| T3.7 | 安装器/自检/回滚 | TODO | T3.1–T3.6 | — |
| T3.8 | 响应审批/时间窗/回滚 | TODO | T3.6 | — |
| T3.9 | 横向移动检测 | TODO | T2.3, T3.2, T3.3 | G4 |

## M4：内容、抓包、性能、交付

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T4.1 | 内容同步服务 | TODO | T1.1 | — |
| T4.2 | Suricata/ET Open 集成 | TODO | T4.1 | — |
| T4.3 | `ly_probe` 产品化补丁 | TODO | T0.0 | — |
| T4.4 | `ly_probe` 规则转换 | TODO | T4.3 | — |
| T4.5 | Capture doctor | TODO | T4.3 | — |
| T4.6 | 查询性能与压测 | TODO | T1.2, T4.2 | — |
| T4.7 | 打包与 Compose profiles | TODO | T3.7, T4.2 | — |
| T4.8 | 文档/许可/安全审计 | TODO | 全部 | G5 |

## Gate 定义

- **G1**：Event v2 + 证据模型 + 许可边界通过评审。
- **G2**：UI shell + 查询性能（7 天 p95 < 2s）通过。
- **G3**：3 条 ATT&CK 链路验证通过。
- **G4**：Agent 安装/回滚 + 响应安全护栏通过。
- **G5**：ESXi 测试机全量验收通过，可发布。
