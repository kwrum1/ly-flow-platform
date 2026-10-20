# LyFlow 工作队列

> 顺序：M0 → M1 → M2 → M3 → M4。  
> 状态：`TODO` / `IN_PROGRESS` / `BLOCKED` / `REVIEW` / `DONE` / `CANCELLED`。  
> 一次只做一个 Task；完成后立即取下一个未阻塞 Task。

## M0：基础与契约

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T0.0 | 环境接入与基线 | DONE | — | — |
| T0.1 | 建立开发规范与进度文件 | DONE | T0.0 | — |
| T0.2 | Feature flags 与配置 | DONE | T0.1 | — |
| T0.3 | Event v2 契约 | DONE | T0.1 | — |
| T0.4 | 证据模型与存储 schema | DONE | T0.3 | — |
| T0.5 | CI/测试脚本与许可检查 | DONE | T0.2 | G1 |

> Gate G1：`READY_FOR_REVIEW`。Event v2、证据 schema、许可/密钥/私有边界检查已完成；等待人工评审。按“不停止”策略继续 M1 中不依赖 G1 的任务。

## M1：数据主链与 UI shell

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T1.1 | Ingest v2 | DONE | T0.3, T0.4 | — |
| T1.2 | Query v2 + 查询治理 | DONE | T1.1 | — |
| T1.3 | 新 UI shell | DONE | T0.2 | — |
| T1.4 | 总览页 | DONE | T1.2, T1.3 | — |
| T1.5 | 事件中心 + 详情 + 证据面板 | DONE | T1.2, T1.3 | — |
| T1.6 | 统一搜索 | DONE | T1.2 | — |
| T1.7 | M1 验收 | IN_PROGRESS | T1.1–T1.6 | G2 |

## M2：ATT&CK 与 Incident

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T2.1 | ATT&CK 元数据与映射 | DONE | T1.1 | — |
| T2.2 | 阶段状态机 | DONE | T2.1 | — |
| T2.3 | 实体图与关联 | DONE | T2.1 | — |
| T2.4 | Incident API/生命周期 | DONE | T2.2, T2.3 | — |
| T2.5 | 攻击链/时间线 UI | DONE | T2.4, T1.3 | — |
| T2.6 | ATT&CK 覆盖率 | DONE | T2.1, T2.4 | — |
| T2.7 | 关联验证 | DONE | T2.2–T2.6 | G3 |

> Gate G3：`READY_FOR_REVIEW`。3 条合成攻击链通过 builder/阶段状态机验证；真实 PCAP/EVTX 回放待测试 VM。

## M3：Agent、RASP、响应

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T3.1 | `ly-agent` supervisor | DONE | T0.2 | — |
| T3.2 | Linux Elkeid 集成 | CANCELLED | T3.1 | — |
| T3.3 | Windows Wazuh 集成 | CANCELLED | T3.1 | — |
| T3.4 | OpenRASP Java/PHP | REVIEW | T3.1 | — |
| T3.5 | Elkeid RASP Python/Go/Node | CANCELLED | T3.1 | — |
| T3.6 | Agent 门面/API/UI | REVIEW | T3.2, T3.3 | — |
| T3.7 | 安装器/自检/回滚 | REVIEW | T3.1–T3.6 | — |
| T3.8 | 响应审批/时间窗/回滚 | DONE | T3.6 | — |
| T3.9 | 横向移动检测 | DONE | T2.3, T3.2, T3.3 | G4 |

> Gate G4：`READY_FOR_REVIEW`。Agent supervisor/provider、RASP 配置、响应策略、
> 横向移动实时接入已完成；安装自检/干净机回滚仍待 ESXi 凭据。Windows/Elkeid 已取消。

## M4：内容、抓包、性能、交付

| ID | 任务 | 状态 | 依赖 | Gate |
|---|---|---|---|---|
| T4.1 | 内容同步服务 | REVIEW | T1.1 | — |
| T4.2 | Suricata/ET Open 集成 | REVIEW | T4.1 | — |
| T4.3 | `ly_probe` 产品化补丁 | REVIEW | T0.0 | — |
| T4.4 | `ly_probe` 规则转换 | REVIEW | T4.3 | — |
| T4.5 | Capture doctor | REVIEW | T4.3 | — |
| T4.6 | 查询性能与压测 | REVIEW | T1.2, T4.2 | — |
| T4.7 | 打包与 Compose profiles | REVIEW | T3.7, T4.2 | — |
| T4.8 | 文档/许可/安全审计 | REVIEW | 全部 | G5 |

## Gate 定义

- **G1**：Event v2 + 证据模型 + 许可边界通过评审。
- **G2**：UI shell + 查询性能（7 天 p95 < 2s）通过。
- **G3**：3 条 ATT&CK 链路验证通过。
- **G4**：Agent 安装/回滚 + 响应安全护栏通过。
- **G5**：ESXi 测试机全量验收通过，可发布。当前：`PASS_WITH_EXCEPTIONS`（2026-10-19，12 服务健康、Pingora 前端、Event v2/Incident、真实 Agent/资产/心跳、YARA、Python/Java/PHP/Node/.NET RASP、OpenRASP alarm→component alerts、Wazuh manager 本地告警进入 NDR/XDR、全部响应动作审批/执行/回滚、SeaweedFS 证据对象存储、横向移动实时接入、Suricata→Vector→ly-server、自签 UI 验收通过；clean VM、ESXi 快照、离线 digest 见例外）。

> 2026-10-20：lyprobe NetFlow v9 collector、flows/sessions 证据链、规则中心 lyprobe 引擎与 eBPF→auditd→procfs
> 进程采集已实现并验证；T4.3/T4.4 继续保留 REVIEW，待 clean VM 安装/回滚验收。

> 2026-10-20 二次回归：17 页面 UI 巡检与定向回归通过；规则中心/流量观测/eBPF 来源/NetFlow 地址过滤已修复。
> 剩余 R1 规则源冷启动、R2 Incident 冷启动为性能优化项。

> 2026-10-20 生产级最终验收：功能/UI/Agent/lyprobe/规则/响应/证据通过；6 条重复路由已重定向并删除页面；
> security-engine CPU budget 重启循环已修复。发布级例外：clean VM 安装回滚、20k EPS 容量复测。
