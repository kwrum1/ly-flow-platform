# M2 验收报告（ATT&CK 与 Incident）

- 日期：2026-10-19
- 分支：`feat/lyflow-v2`
- 环境：编译机 Ubuntu 25.10；测试 VM 尚未就绪

## 1. 范围

- T2.1 ATT&CK 元数据与映射
- T2.2 阶段状态机
- T2.3 实体图与关联
- T2.4 Incident 生命周期候选
- T2.5 攻击链/时间线 UI
- T2.6 ATT&CK 覆盖率
- T2.7 关联验证

## 2. 已通过的验证

| 验证 | 命令 | 结果 |
|---|---|---|
| ATT&CK 映射 | `cd pkg && go test ./attack -count=1` | ok |
| 覆盖率 | `cd pkg && go test ./attack -count=1` | ok |
| 阶段状态机 | `cd server && go test ./correlation/stage -count=1` | ok |
| 实体图 | `cd server && go test ./correlation/graph -count=1` | ok |
| Incident builder | `cd server && go test ./correlation/incident -count=1` | ok |
| 3 条攻击链验证 | `cd server && go test ./correlation/incident -run TestValidatedAttackChains -count=1` | ok |
| 前端类型/构建 | `cd frontend && npm run typecheck && npm run build` | ok |
| 快速全量 | `bash scripts/dev/test-all.sh fast` | all fast checks passed |

## 3. 验证的 3 条链

1. **Web Exploit → Execution → C2**
   - T1190 → T1059 → T1071.001
   - 期望阶段：`command_and_control`
   - 证据：3 条，严重度 critical
2. **Credential Access → Discovery → Lateral Movement**
   - T1110 → T1046 → T1021.004
   - 期望阶段：`lateral_movement`
3. **WebShell → Persistence → Privilege Escalation**
   - T1190 → T1505.003 → T1068
   - 期望阶段：`privilege_escalation`

## 4. 尚未完成

1. 真实 PCAP/EVTX 回放与误报率评估。
2. 实时消费循环：ClickHouse 事件 -> stage/graph -> incident 持久化。
3. 实体图前端可视化（当前 UI 为阶段时间线 + 证据矩阵）。
4. 真实数据下的阶段跳变/时间窗调参。
5. 证据下载与原始 JSON 展开。

## 5. Gate G3 结论

**READY_FOR_REVIEW**：3 条合成链通过 builder + 状态机验证；真实数据回放待测试 VM。继续 M3（Agent / RASP / 响应）。

## 6. 下一步

- T3.1 `ly-agent` supervisor
- T3.2 Linux Elkeid 集成
- T3.3 Windows Wazuh 集成（CANCELLED）
- T3.4 OpenRASP Java/PHP
- T3.5 Elkeid RASP Python/Go/Node
- T3.6 Agent 门面/API/UI
- T3.7 安装器/自检/回滚
- T3.8 响应审批/时间窗/回滚
- T3.9 横向移动检测
