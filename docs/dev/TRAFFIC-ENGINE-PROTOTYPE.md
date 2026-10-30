# 流量引擎耦合与按 flow 分片原型

状态：**原型/设计评审，未部署**。代码在 `prototype/traffic-fanout/`，只用于验证分片契约和估算改造成本。
本文件不改变 `server/`、`frontend/`、`agent/`、`security-engine/`，也不改变任何现网采集配置。

关联文档：`docs/dev/TRAFFIC-ENGINE-COUPLING.md`（总体分层与暂缓结论）、
`docs/dev/LYPROBE-DEPLOY.md`、`deploy/compose/server-zone-capture.yml`。

## 1. 结论

1. **不同引擎不能按 flow 互斥分流。** Suricata 和 lyprobe 必须各自看到 100% 的
   flow，再在**各自引擎族内部**按 flow 水平分片。把 flow A 只给 Suricata、
   flow B 只给 lyprobe，会让两边的检测都缺一半输入，且无法通过规则补偿。
2. **同一个 `PACKET_FANOUT` 组不能跨引擎共享。** 内核 fanout 的语义是“组内
   socket 分走互斥的包子集”，不是“每个 socket 都收到全量”。让 lyprobe 加入
   Suricata 的组，等于让两个引擎各看一部分 flow。
3. **当前构建没有可用的零拷贝路径。** Suricata 只启用 AF_PACKET；`PACKET_FANOUT`
   仍然按 socket/组复制 skb，只是用 mmap ring 省掉一次内核→用户拷贝。
   PF_RING ZC / AF_XDP 都需要换构建、换驱动或换数据面，不能作为本次改造前提。
4. **短期最省的一次优化不是 fanout，而是去掉重复消费**：平台 flow-only 规则
   直接消费 lyprobe 的 NetFlow（collector 已归一化），不要为平台规则再抓第三份包。
5. **lyprobe 的 `-O` 不是分片开关。** 上游 `-O` 是“抓包线程数”，多个线程共享
   一个 pcap handle，读包被同一把写锁串行化；内部 hash 只决定 flow 表落在哪个
   分片/锁，不决定哪个线程处理哪个 flow。要按 flow 分片 lyprobe，必须增加
   AF_PACKET fanout 能力（patch/launcher），否则只能接受全量复制。

## 2. 现状核对

### 2.1 采集路径

- Suricata 容器：`network_mode: host`、`NET_RAW/NET_ADMIN`，profile 使用
  `af-packet` + `cluster-type: cluster_flow`（`deploy/suricata/lyflow-suricata-profile.yaml`、
  `rules/suricata/suricata-profile.yaml`）。profile 未显式写 `threads` 和
  `cluster-id`，使用发行版默认值；上线前必须显式固定。
- lyprobe：容器（`server-zone-capture.yml`）或 systemd 独立进程，同样抓镜像口。
  compose 与 unit 都没有传 `-O`，因此使用上游默认值 2 个 fetcher 线程。
- 两者各自打开 AF_PACKET/libpcap socket。内核为每个 socket/组复制一份包，
  所以同一镜像包被处理两次；如果再加平台规则抓包，就是第三次。

### 2.2 lyprobe `-O` 与内部 hash 的真实语义

上游固定 revision `06c097d`：

- `README.md`：`-O <# threads>` = “Number of packet fetcher threads”，默认 2，
  并注明 “Use 1 unless you know what you're doing.”
- `nprobe.c` `fetchPackets()`：所有 fetcher 线程共享同一个
  `readOnlyGlobals.pcapPtr`，`pcap_next_ex()` 在 `pcapLock` 的**写锁**内执行，
  读包后解锁再 `decodePacket()`。所以抓包读取是串行的，`-O` 增加的是并行解码，
  不是并行收包。
- `engine.c` `addPktToHash()`：

  ```c
  idx = (vlanId + proto + srcHost + dstHost + sport + dport + (tos & 0xfe));
  hash_idx = idx % readOnlyGlobals.numPcapThreads;
  idx %= readOnlyGlobals.flowHashSize;
  ```

  这个加法 hash 对正反向是对称的（加法可交换），但它只用于选择
  `theFlowHash[hash_idx]` 和对应的读写锁；处理该包的线程仍是“抢到 pcap 锁的
  fetcher 线程”。因此：
  - 不能把 lyprobe 的内部 hash 当作“flow → worker”的稳定映射；
  - 加法 hash 的分布质量弱（碰撞多、IPv6 把地址按 32 位字相加），只适合做
    表分片，不适合做跨引擎对齐；
  - 想靠 `-O` 提升吞吐，先确认瓶颈在解码而不是收包锁。

结论：**lyprobe 当前不具备按 flow 水平分片的抓包路径**。短期要么保持单实例全量
抓包，要么增加一个很薄的 fanout 启动器/patch；在 patch 落地前不能宣称 lyprobe
已经分片。

## 3. 方案对比

| 方案 | 分流机制 | flow 亲和 | 拷贝/CPU 成本 | 前置条件 | 结论 |
| --- | --- | --- | --- | --- | --- |
| `PACKET_FANOUT_HASH`（内核） | 内核按 `skb_get_hash()`（RSS 或 flow dissector）选组内 socket，模式 `PACKET_FANOUT_HASH` | 普通 TCP/UDP 通常正反向同槽；算法/seed 不对外暴露，分片、隧道、VLAN 场景可能改变 | 每个组/成员 socket 一份 skb；mmap ring 省去内核→用户拷贝，但不是零拷贝 | `CAP_NET_RAW`；host netns；组 ID 16 位且每接口唯一 | Suricata 首选；lyprobe 需要补 socket 分片能力。只在本引擎族内使用 |
| Suricata `af-packet` `cluster_flow` | Suricata 为每个 capture 线程开 socket，加入自己的 fanout 组，`cluster_flow` = hash 分流 | 有，flow 固定在 capture 线程；线程数 = `threads` | 每线程一个 ring；组内复制 | 固定 `threads`、`cluster-id`；CPU 亲和；容器 host netns | 保持 `cluster_flow`，把 `threads` 固定为 worker 数；不要把 Suricata 的组给别的进程 |
| Suricata `cluster_cpu` / `cluster_qm` | `cluster_cpu` = 按处理 CPU 选 socket（`PACKET_FANOUT_CPU`）；`cluster_qm` = 按硬件队列映射 | `cluster_cpu` 单独使用**没有** flow 亲和；`cluster_qm` 依赖 NIC RSS/队列 | 取决于网卡队列和 CPU 拓扑 | 多队列网卡、RSS 对称、IRQ/队列规划；`cluster_qm` 还要 tc/XDP 配置 | 只在 NIC RSS 已验证对称、且完成队列调优时考虑；默认仍用 `cluster_flow` |
| lyprobe `-O` + 内部 hash | 单 pcap handle + N 个 fetcher 线程；内部加法 hash 只分 flow 表/锁 | **无**（同一 flow 的包可由不同线程解码） | 读包串行；解码并行；flow 表分片减少锁竞争 | 无额外依赖 | 不能作为 shard 机制，也不能与 Suricata 对齐；只作为单实例解码并发 |
| PF_RING ZC | `pf_ring` 内核模块 + ZC 驱动；应用加入 PF_RING cluster，按 flow 分到 socket | cluster 内按 flow 分片；同样是把包分给成员，不是每个成员全量 | 真正 ZC 需要 ZC 驱动；每应用/每 ring 一份；省掉内核→用户拷贝 | 支持 ZC 的网卡/驱动、内核模块、重编 Suricata 和 lyprobe、hugepage/IRQ 规划、许可与运维评审 | 当前构建不支持；只有在 fanout 后仍 CPU 打满且硬件合格时才评估。不能让两个独立引擎“共享一次解析” |
| AF_XDP | XDP 程序按 flow hash `bpf_redirect_map()` 到 XSK；每队列一个 XSK | 由 XDP 程序决定；需要自己保证正反向对称 | native XDP 可零拷贝，copy mode 仍有拷贝；每 XSK 一份 | XDP-capable NIC + 原生驱动、队列隔离、重编/改造两个引擎 | 当前不支持；更适合把多个分析合并进一个用户态数据面，而不是耦合两个独立进程。高带宽长期选项 |

### 3.1 为什么“同一个 fanout 组”不能解决问题

内核 fanout 组是一个**负载均衡集合**：

- 组内每个 socket 只收到一部分包（hash/CPU/QM 模式决定分给谁）；
- 组 ID 相同、模式相同的 socket 属于同一集合，无论它来自哪个进程；
- 要让每个引擎都看到全量 flow，只能让每个引擎族拥有**独立组**，由内核为每个组
  复制一份包。

因此正确形态是“两个组、两份包、各自分片”，不是“一个组、两个引擎”。即使使
用 `PACKET_FANOUT_EBPF` 自定义 flow key，也只能把某条 flow 定向给一个 socket，
仍然违背“每个引擎都要全量”的要求，故不采用。

### 3.2 为什么两个引擎的 worker 映射对不齐

- Suricata 的 `cluster_flow` 使用内核 hash + 自己的 capture 线程数；
- lyprobe 的内部 hash 是加法余数，线程/表大小不同；
- 内核 hash 的实现、seed、分片处理和隧道解析随版本变化，且不保证与用户态
  可复现的 hash 一致。

没有任何受支持的接口能让两个引擎对同一条 flow 得到相同的 worker 编号。因此
“跨引擎按 flow 互斥”不仅在语义上错误，在实现上也不可对齐。

## 4. 原型：`prototype/traffic-fanout/`

### 4.1 它证明什么

原型只实现“引擎族内部按 flow 分片”的契约，不抓包、不改引擎：

- `Key`：可双向归一化的五元组（IPv4/IPv6/IPv4-mapped），按地址字节、端口排序；
- `Hash`：对规范编码做 FNV-1a 64，显式编码、固定 known-vector；
- `Shard`/`Group`：`hash % workers`，worker 数固定时同一 flow 永远同一槽；
- `Distribution`/`Imbalance`：验证多 worker 分散度；
- `FanoutArg`：`(groupID << 16) | mode | flags`，与内核 `PACKET_FANOUT`
  setsockopt 参数一致；
- `fanout_linux.go`：`OpenFanoutSocket()` 用 raw AF_PACKET 加入指定 fanout 组，
  仅做成员资格验证，不 mmap ring。Windows 上只做交叉编译检查，未运行。

原型 hash **不是**内核 hash，也**不是** Suricata hash。它的用途是给未来的
launcher/测试工具提供一个可测试的参考实现，并证明三个性质；不能拿它的输出
去推断现网 Suricata/lyprobe 的实际 worker。

### 4.2 测试结果（本地，2026-10-30）

环境：Windows amd64，Go 1.26.5（仓库 `go.work` 要求的版本），
`GOWORK=off`（原型模块独立于 workspace），`CGO_ENABLED=0`。

```text
$ GOWORK=off go test ./...
ok  github.com/lyflow/ly-flow-platform/prototype/traffic-fanout  0.019s

$ GOWORK=off go vet ./...
(no output)
```

9 个测试全部通过：

| 测试 | 结果 |
| --- | --- |
| `TestReverseIsSymmetric`（2002 条 flow，1..16 worker） | PASS |
| `TestSameAddressDifferentPortsIsSymmetric` | PASS |
| `TestIPv4MappedAddressNormalised` | PASS |
| `TestFlowPinnedToWorker`（200 flow × 50 次，正反向） | PASS |
| `TestFlowsSpreadAcrossWorkers`（20000 flow，2/4/8/16 worker，±15%） | PASS |
| `TestShardRejectsInvalidWorkerCount` | PASS |
| `TestWorkerCountChangeRemapsActiveFlows` | PASS |
| `TestFanoutArg` | PASS |
| `TestHashKnownVector` | PASS |

`go run ./cmd/fanout-demo`（4096 条合成 flow，8 worker）：

```text
worker  flows  share
     0    537   13.1%
     1    521   12.7%
     2    489   11.9%
     3    510   12.5%
     4    528   12.9%
     5    484   11.8%
     6    519   12.7%
     7    508   12.4%
max/mean imbalance: 0.049
PASS: symmetric hash, stable assignment, all workers used
```

说明：

- 合成流量是“多个客户端 IP + 少量服务器端口 + 随机临时端口”，只用于证明分散
  性质，不代表现网分布；现网必须用真实 pcap/回放重新测。
- `-race` 未运行：本机缺少 `gcc`/cgo，`go test -race` 直接拒绝。原型是纯函数、
  无 goroutine，风险低，但正式合入前应在有 CGO 工具链的机器补跑。
- `GOOS=linux GOARCH=amd64 go build ./...` 通过，说明 linux-only 的 fanout
  成员资格代码至少能编译；**未在 Linux 上运行**，也没有验证内核实际分流。

### 4.3 复现命令

```bash
cd prototype/traffic-fanout
GOWORK=off go test ./...
GOWORK=off go run ./cmd/fanout-demo
GOWORK=off GOOS=linux GOARCH=amd64 go build ./...
```

不要在 `.241`/`.8` 上运行 `OpenFanoutSocket()`；它需要 `CAP_NET_RAW`，只应在
`TEST_HOST` 的测试接口上验证。

## 5. 目标拓扑

```text
外网 ──┐
       ├── SPAN/mirror（只做外网↔服务器区，不做东西向）
服务器区┘
                    │
              ens192 (host netns, promisc)
                    │
      ┌─────────────┴──────────────┐
      │                            │
 fanout group 41001          fanout group 41002
 仅 Suricata                 仅 lyprobe
 N 个 capture socket         N 个进程/socket（每个 -O 1）
      │                            │
 Suricata af-packet           lyprobe → NetFlow v9 → collector
 cluster_flow, threads=N      127.0.0.1:9995
      │                            │
 EVE alert/flow               sessions:semantic + flows:raw
 community_id                 （平台 flow-only 规则在这里消费）
      └──────────────┬─────────────┘
                     │
             关联：community_id / 规范五元组 + 时间窗
```

要点：

1. **两个组 ID 必须不同**，且每个组只包含一个引擎族的 socket。组 ID 写入部署
   配置并做启动自检（打印 group/mode/socket 数；不符合预期拒绝启动）。
2. Suricata 侧：`cluster-type: cluster_flow`，显式 `threads`、`cluster-id`，
   固定 CPU 亲和；不要开 `cluster_cpu` 除非 NIC RSS 已验证对称。
3. lyprobe 侧：每个实例 `-O 1`、一个 AF_PACKET socket、一个 fanout 成员；需要
   薄 patch/launcher 把 `PACKET_FANOUT` 加到它的 pcap fd 上。patch 未落地前，
   lyprobe 保持单实例全量抓包，**不要**为了“看起来分片”而启动 N 个实例
   （N 个独立 pcap socket 会各收全量，成本 N 倍且 flow 重复导出）。
4. **不设第三组抓包**。平台 flow-only 规则消费 collector 的 flow 记录，这是
   当前最接近“零拷贝”的低成本做法：同一份解析结果多用途，而不是多抓一份包。
5. 关联键：Suricata 已输出 `community_id`（`community-id: true`, seed 0）；
   collector 目前**没有**计算 `community_id`（本次未改）。短期用规范五元组 +
   时间窗关联；长期在 collector 侧按同一 seed 计算，作为上线前置条件之一。
6. 扩容优先加“传感器/接口对”，而不是在运行中加 worker：worker 数变化会重排
   flow（4→6 理论重排约 2/3，原型测试覆盖该行为）。需要扩容时在维护窗口重启
   整个引擎族，接受短时 flow 重建。

## 6. 什么时候才值得上生产

### 6.1 先做低成本项（不做这些就上 fanout 是浪费）

- af-packet：`tpacket-v3`、`use-mmap`、合适的 `ring-size`/`block-size`，
  必要时 `mmap-locked`；
- CPU 亲和、IRQ 亲和、NUMA 对齐；确认没有 RPS/RFS 与 fanout 叠加造成二次分发；
- 关闭 GRO/LRO 等对抓包不友好的 offload（按网卡和驱动确认）；
- 规则归属去重（`signature_hash` + `overlap_count=0`），避免两个引擎重复做同一件事；
- 用真实镜像 pcap 回放建立基线：pps、flow/s、CPU、`capture.kernel_drops`、
  EVE/NetFlow 延迟。

如果瓶颈是 ring 太小、IRQ 集中、规则太多，先修这些；fanout 不会解决。

### 6.2 触发指标（初始阈值，按基线校准）

| 指标 | 采集方式 | 触发阈值（持续窗口） |
| --- | --- | --- |
| Suricata worker CPU | `stats` 的 per-thread / `top -H` | 单 worker >70%，持续 15 分钟 |
| 内核丢包 | Suricata `capture.kernel_drops`；`ip -s link`/`ethtool -S` | >0 且持续增长 10 分钟，或丢包率 >0.01% |
| flow 速率 | collector 计数 / `suri` flow 统计 | >5k flow/s，或新建 flow >2k/s |
| 镜像带宽/pps | `sar -n DEV`、NIC 计数器 | >2 Gbps 或 >200k pps，持续 10 分钟 |
| 检测/导出延迟 | EVE 写入延迟、collector ingest lag | p99 >5 秒 |
| 主机余量 | `mpstat`/`vmstat` | 空闲物理核 <2 |
| 分片倾斜（启用后） | 每 worker 包/flow 计数 | max/mean−1 >20%，持续 1 小时 |

触发不等于上线。至少同时满足：

1. 已排除 ring/IRQ/offload/规则量等低成本因素；
2. 有连续 1–2 周的真实基线，能证明瓶颈与流量增长相关；
3. 规则归属去重完成，两个引擎的输出不会互相重复；
4. 关联键在真实流量上验证通过（`community_id` 或五元组+时间窗命中率达标）；
5. 容量模型成立：worker 数 + 2 个核的余量、每 worker ring 内存、网卡队列数；
6. 在 `TEST_HOST` 用生产同版本规则和镜像 pcap 回放，drop 降低 ≥30% 或同等流量
   下 headroom 翻倍；否则不上；
7. 回滚演练通过（见第 8 节）。

### 6.3 零拷贝的触发条件（比 fanout 更晚）

只有同时满足才评估 PF_RING ZC / AF_XDP：

- fanout 已经上线且仍然 CPU/内存带宽打满，瓶颈确认在内核→用户拷贝；
- 目标网卡/驱动支持 ZC 或 native XDP，且能独占队列；
- 两个引擎要么合并进同一数据面（一次解析、多用途），要么接受各自独立 ring
  （此时 ZC 只省每份拷贝，不减少份数）；
- 有维护内核模块/驱动的运维能力，并完成许可与支持评审；
- 在 `TEST_HOST` 用目标网卡实测，而不是在 virtio/VM 上外推。

## 7. 风险

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 误把两个引擎加入同一 fanout 组 | 两个引擎都只看到部分 flow，静默漏检 | 组 ID 注册表；启动自检；每引擎/每组独立计数告警 |
| 开启 `PACKET_FANOUT_FLAG_ROLLOVER` | ring 满时把包转给别的 socket，flow 亲和被破坏 | 不开启；宁可丢包并告警，也不静默换 worker |
| 分片/隧道/VLAN | 同一 flow 的不同片/内层五元组落到不同 worker | 评估 `PACKET_FANOUT_FLAG_DEFRAG`；对 Geneve/VXLAN 做回放验证；必要时按外层 hash 接受 |
| worker 数变化 | 活跃 flow 重排、短时重复/漏检 | worker 数作为部署常量；变更走维护窗口 |
| 象流（elephant flow） | 单 worker 打满，其他空闲 | 监控 max/mean；接受按 flow 分片的天花板，必要时拆分接口/传感器 |
| lyprobe 多实例 | NetFlow 模板按 exporter IP 缓存（collector 不看源端口），不同模板会互相覆盖；flow 可能重复 | 所有实例使用相同模板 ID/字段；用唯一测试 flow 验证每个 flow 只导出一次；必要时扩展 collector 的 template key（未在本次范围） |
| lyprobe patch 维护 | 上游 revision 升级后 patch 失效 | patch 留在 `patches/lyprobe/`，独立进程/容器，不链接进自有二进制；构建脚本校验 revision |
| 容器 netns 隔离 | fanout 组不可见或分流错误 | 两个引擎都必须 `network_mode: host`；启动自检读取实际接口 |
| 两份全量抓包的内存带宽 | 2 Gbps 镜像变成 4 Gbps 处理 | 先去掉第三份抓包；用 `perf`/`sar` 量化；必要时才上 ZC |
| 关联键缺失 | 告警与 flow 无法合并，XDR 证据链断裂 | Suricata `community_id` 已开；collector 补算后再上线；否则用五元组+时间窗并标注置信度 |

## 8. 回滚

本次变更只新增原型和文档，**没有运行时改动**：

- 回滚代码：删除 `prototype/traffic-fanout/` 和本文件即可；不影响任何服务。
- 未来灰度 fanout 的回滚：
  1. 停止新增的 lyprobe 分片实例，恢复单实例 `-O 1`（或原 `-O` 默认）；
  2. 移除 Suricata 的 `threads`/`cluster-id` 覆盖，恢复原 profile；
  3. 保留 collector 与 NetFlow 链路（无 schema 变更）；
  4. 用 `capture.kernel_drops`、flow 计数、EVE 告警量确认恢复；
  5. 不删除数据、不改数据库，无需数据回滚。
- 若曾修改 offload/IRQ/ring，按变更前记录逐项恢复。

## 9. 未决事项

- Suricata 当前发行版的 `cluster-id` 默认值、最大 capture 线程数与 fanout 成员上限，
  需在 `BUILD_HOST`/`TEST_HOST` 用 `suricata --build-info` 和内核文档确认。
- lyprobe 的 fanout 落地方式（patch `pcap_get_selectable_fd()` 上的 setsockopt，
  还是独立 launcher 创建 socket 后交给 lyprobe）未定；前者改动小但绑定 libpcap
  行为，后者更干净但需要 fd 传递。
- collector 的 NetFlow 模板 key 目前是 exporter IP（`server/cmd/netflow-collector/decode.go`
  `templateKey`），多实例同 IP 依赖“模板完全一致”；是否需要加入源端口待评审。
- `community_id` 在 collector 侧的实现与 seed 对齐未做。
- PF_RING ZC 的许可/支持范围、AF_XDP 在目标 Suricata 构建中的可用性，均未验证。

## 10. 变更文件

```text
prototype/traffic-fanout/go.mod
prototype/traffic-fanout/fanout.go
prototype/traffic-fanout/fanout_test.go
prototype/traffic-fanout/fanout_linux.go
prototype/traffic-fanout/cmd/fanout-demo/main.go
prototype/traffic-fanout/README.md
docs/dev/TRAFFIC-ENGINE-PROTOTYPE.md
```

## 11. 参考

- 上游 ly_probe `06c097dd5c69e391efd3c8b3776d672e03386e49`：`README.md`、
  `nprobe.c` `fetchPackets()`、`engine.c` `addPktToHash()`。
- Linux `include/uapi/linux/if_packet.h`：`PACKET_FANOUT` 模式与 flag。
- Suricata AF_PACKET / `cluster_flow` / `cluster_cpu` / `cluster_qm` 文档。
- 本仓库：`docs/dev/TRAFFIC-ENGINE-COUPLING.md`、
  `deploy/compose/server-zone-capture.yml`、`deploy/suricata/lyflow-suricata-profile.yaml`、
  `server/cmd/netflow-collector/decode.go`。
