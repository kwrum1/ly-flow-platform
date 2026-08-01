# Agent 与 legacy DPI 兼容边界

> 更新日期：2026-08-02。本文描述当前代码边界，不把容器 QA 组件写成现场部署方式。

## 生产角色

政企现场的真实采集端是直接安装到宿主机的 `ly-agent`，不要求 Docker。容器化
`ly-agent` 仅用于本地全系统 QA、Suricata profile 联调和发布验收，Compose profile
为 `container-agent` / `suricata-profile`，不得作为现场 Agent 的安装方式。

安全服务器上的 `ly-local-mirror` 仍属于默认服务，它复用 Agent 抓包能力进行本机旁路
镜像采集。它允许显式选择处于 UP 状态的 loopback 接口，便于单机开发和验收；生产旁路
环境仍应选择实际镜像网卡。

## Linux 3.10 / CentOS 7

Linux Agent 使用 `CGO_ENABLED=0`、`GOAMD64=v1` 的静态二进制，不依赖现场 glibc 或
libpcap，可覆盖 Linux 3.10 及更高内核。Linux 抓包使用纯 Go AF_PACKET/TPACKET；管理面
支持下发 `tcp`、`udp`、`tcp or udp` 三类静态 BPF，未知 libpcap 表达式会明确拒绝。

在 3.10/CentOS 7 上，eBPF 运行监控自动回退到 auditd；AF_PACKET 流量采集、资产快照、
日志审计、心跳和本地 spool 保持可用。安装验收必须检查：静态 ELF、无 `NEEDED` 动态库、
`GOAMD64=v1`、目标机 AF_PACKET 权限，以及 auditd 可用性。

远端 Agent 的生产网络模型只允许访问平台 HTTPS，不应要求现场主机直连 Redis。
流量、运行时和资产主链路已经具备 Agent 凭据保护的 HTTP 接口，但少量 RASP 健康状态和兼容发布路径
仍保留 Redis 客户端代码；这些路径在完成远端现场验收前必须迁移到统一 HTTPS 摄取面。

## legacy DPI

`ly-dpi-engine` 是早期独立流量检测器：消费 Redis `flows:raw`，执行旧规则/域名名单，
输出 `alerts:dpi`，并兼容生成 `flows:semantic` 和 `sessions:semantic`。它不处理 Runtime、
RASP 或日志审计，也不参与统一规则 Bundle 的热加载与审计。

默认检测器是 `ly-security-engine`：消费 `telemetry:traffic`、`telemetry:runtime`、
`telemetry:rasp`、`telemetry:log_audit`，统一输出四类告警并受规则生命周期管理。

因此 legacy DPI 只保留在 `legacy-dpi` Compose profile，用于旧 `flows:raw` 接入迁移、
结果对比和回归测试。不得与统一安全引擎长期并行消费同一业务流，否则可能产生重复告警、
不同规则口径和额外 Redis 压力。无旧数据源时不启动、不安装到现场 Agent。
