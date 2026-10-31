# 运行时性能档位（Suricata / Redis）

`scripts/apply-runtime-profile.sh` 按架构和内存自动选择一套默认值，并写回
`/opt/ly-flow-platform/suricata/lyflow-suricata-profile.yaml` 与 `.env`，随后重建
Suricata 和 Redis 容器。`--dry-run` 只打印选中的档位。

## 两套缺省值

| 项 | x86_64（大内存） | ARM64（4–8 GB） |
|---|---|---|
| 抓包线程 | `min(6, nproc)` | `2` |
| `ring-size` | 8192 | 2048（内存 ≥8 GB 时为 4096） |
| `buffer-size` | 32768 | 32768 |
| Redis `maxmemory` | 8 GB，且不超过内存的 60% | 1 GB |
| Redis 流保留 | 2 小时 | 1 小时 |

两者都会再按实际 CPU 数与内存收敛，避免小机器套用大配置。

## 内存预算

AF_PACKET 环形缓冲是内核内存，约等于：

```
threads × ring-size × buffer-size
```

- x86 8 GB、4 线程、8192×32768：约 1 GB 内核缓冲，Redis 上限 4 GB；
- ARM 4 GB、2 线程、2048×32768：约 128 MB，Redis 1 GB，给 ClickHouse 和系统留余量。

## 实测（10.1.18.125，4 vCPU / 8 GB）

- 调整前：threads=4、ring-size 默认 4096，18 小时累计丢包 **0.98%**（140,055 / 14.3M）
- 调整后：threads=4、ring-size=8192、Redis 4 GB，运行 18 分钟 **0 丢包**（550,217 包）
- 资源：Suricata CPU 1.8% / 404 MB，Redis 2.4 GB / CPU 12%，可用内存 3.1 GB

## 使用

```bash
sudo scripts/apply-runtime-profile.sh --dry-run   # 只看会选什么
sudo scripts/apply-runtime-profile.sh             # 应用并重建容器
```

ARM 机器建议 4 GB 内存配 2 线程 + 1 GB Redis；8 GB 内存自动升到 ring-size 4096。
