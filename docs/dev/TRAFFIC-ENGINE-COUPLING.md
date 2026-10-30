# 流量引擎耦合与零拷贝设想（挂起）

状态：设计评审中，暂不实施。当前流量未到抓包瓶颈，先解决消费端和误报。

## 目标

- 多个引擎各做自己擅长的分析，不重复同一件事。
- 引擎输出可串联，为 XDR 关联算法提供证据链，而不是把告警堆在一起。
- 同一条 flow 在每个引擎族只处理一次；可能时零拷贝。

## 分层

```text
采集层
  ens192 / mirror
    ├─ PACKET_FANOUT_HASH 组 A → Suricata 0..N
    ├─ PACKET_FANOUT_HASH 组 B → lyprobe 0..N
    └─ 平台 flow-only 规则（可选 consumer）

分析层
  Suricata      包签名、协议异常、复杂 matcher
  lyprobe       flow/NetFlow、L7、服务/设备/OS/中间件指纹、威胁指纹
  平台安全引擎  仅 flow-only 行为规则：扫描、beacon、DNS 隧道、体积异常、罕见目的

关联层
  collector 归一化 → flow_id/session_uid + engine + confidence + threat_type + rule_id
  XDR 用同一 flow_id 串联：
    Suricata alert ─┐
    lyprobe threat ─┼─→ incident evidence → ATT&CK 阶段
    flow behavior ──┘
```

## 关键原则

1. **按引擎族水平分片，不按引擎类型分 flow。**
   - 每个引擎族看到 100% flow 的一个 shard；覆盖不丢。
   - 不要把 flow A 只给 Suricata、flow B 只给 lyprobe，否则两层规则都缺一半。
2. **规则归属不重合。**
   - 继续使用 `signature_hash` + `overlap_count=0`。
   - lyprobe 只收可转换的简单匹配；复杂规则留在 Suricata。
3. **证据链优先于告警数量。**
   - 每条告警带 `flow_id`、`session_uid`、`engine`、`rule_id`、`threat_type`、`confidence`。
   - XDR 以 flow 为锚点合并，不按 message 文本去重。
4. **零拷贝是目标，不是当前前提。**
   - 当前 Suricata 构建：AF_PACKET 支持、PF_RING/AF_XDP 不支持。
   - 可行路径：`PACKET_FANOUT_HASH`（内核分流，仍有 copy）；下一步 PF_RING ZC 或 AF_XDP。
   - 若只抓一次：PF_RING ZC 多应用共享 ring；需要重编 Suricata 和 lyprobe。

## 当前不做

- 不把不同引擎按五元组切开。
- 不在 4 vCPU / ~100 flow/s 的测试机上做多实例 fanout。
- 不先改抓包，先修消费端、误报和证据字段。

## 触发条件

满足任一条件再启动：

- 单 Suricata 进程 4 线程跑满 CPU；
- `ethtool -S` 出现持续 RX drop；
- flow 速率 > 5k/s；
- 需要多 Gbps 镜像接入。

## 下一步（解除挂起后）

1. Suricata `af-packet` + `cluster_flow` + `threads=4` 基线。
2. lyprobe 改 `PACKET_FANOUT_HASH`，每线程独立 socket。
3. 统一 `flow_id` 并让 Suricata/lyprobe/平台规则都写同一关联键。
4. 多实例 EVE 合并（Vector）后再评估 PF_RING ZC。
