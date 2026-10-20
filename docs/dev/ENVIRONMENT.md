# LyFlow 开发环境

> 本文件不包含密码/密钥。实际地址与凭据见编译机上的 `/opt/lyflow/ENVIRONMENT.local.md`（权限 600，不入库）。

## 1. 编译机（BUILD_HOST）

| 项 | 值 |
|---|---|
| 地址 | `BUILD_HOST`（见私有环境文件） |
| 用户 | `root`（首次登录后改用 SSH key） |
| OS | Ubuntu 25.10 |
| CPU | 40 vCPU |
| 内存 | 62 GiB |
| 磁盘 | `/` 295G，剩余约 62G（需持续关注） |
| Docker | 29.2.1 |
| Go | 默认 1.24.4；`/opt/go1.26-clean/bin/go` 为 1.26.0；仓库要求 1.26.5 |
| Node | v22.22.2 |
| 源码 | `/opt/lyflow/src` |
| 产物 | `/opt/lyflow/artifacts` |
| 日志 | `/opt/lyflow/logs` |
| 原工作区 | `/root/ly-flow-platform`（保留，勿覆盖未提交改动） |

### Go 工具链

`go.work` 要求 `go 1.26.5`。当前已验证可用：

```bash
GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go test ...
```

Go 会自动下载 1.26.5；`GOSUMDB=off` 的环境变量会导致工具链校验失败，执行时必须覆盖为 `sum.golang.org`。后续在 `scripts/dev/test-all.sh` 和 CI 中固化。


## 2. 测试机（TEST_HOST）

| 项 | 值 |
|---|---|
| 宿主机 | ESXi 8.0.3，`ESXI_HOST`（见私有环境文件） |
| 数据存储 | `data`，约 855G 可用 |
| 测试 VM | `lyflow-test` |
| VM 地址 | `TEST_VM_HOST`（见私有环境文件） |
| OS | Ubuntu 24.04.5 LTS |
| CPU / 内存 | 6 vCPU / 8 GiB |
| 磁盘 | 120G 虚拟盘，根分区已扩展，约 113G 可用 |
| Docker | 29.1.3 |
| Compose | v2.40.3 |
| 部署目录 | `/opt/lyflow/deploy` |
| 数据目录 | `/opt/lyflow/data` |
| 报告目录 | `/opt/lyflow/reports` |
| 访问 | 编译机 root SSH key 已注入 |

### 测试 VM 准备清单

- [x] 创建专用 Linux VM（Ubuntu 24.04.5 cloud image）
- [x] 6 vCPU / 8 GiB / 120G 磁盘
- [x] 安装 Docker Engine + Compose Plugin
- [x] 静态 IP / 可被编译机 SSH
- [x] 配置 SSH key（与编译机一致）
- [ ] 打快照，记录回滚点（ESXi API 暂时不稳定，稍后补）
- [x] 在 `PROGRESS.md` 记录 VM 信息（不写密码）


## 3. 网络与端口

| 用途 | 端口 |
|---|---|
| SSH | 22 |
| Gitea（编译机） | 10000 |
| 平台 HTTPS | 443 |
| 平台 HTTP | 80（跳转 443） |
| Wazuh Manager | 1514/1515/55000 |
| Elkeid AgentCenter | 6751/6752 |
| ClickHouse | 8123/9000（仅内网） |
| PostgreSQL | 5432（仅内网） |

## 4. 安全要求

- 不在仓库、脚本、Dockerfile、日志、镜像中写密码。
- 首次登录后配置 SSH key，轮换初始密码。
- 破坏性操作前打快照。
- 测试数据使用合成数据，不提交真实 PCAP/客户数据。
