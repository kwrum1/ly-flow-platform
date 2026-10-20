# Agent installer scripts

- `preflight.sh`：安装前检查（root、systemd、命令、磁盘、时间同步、SELinux）。
- `self-test.sh [service] [binary]`：检查二进制、服务状态/启动、日志，输出 OK/WARN/FAIL。
- `install-agent.sh <package> [service] [binary] [unit]`：备份 → 安装 → daemon-reload → 启动 → 自检；失败自动回滚。
- `rollback-agent.sh <backup-dir> [service] [binary]`：手动恢复备份。

示例：

```bash
sudo bash scripts/agent/preflight.sh
sudo bash scripts/agent/install-agent.sh /tmp/ly-agent.tar.gz ly-agent /opt/lyflow/bin/ly-agent /tmp/ly-agent.service
sudo bash scripts/agent/self-test.sh ly-agent /opt/lyflow/bin/ly-agent
```

脚本默认服务名 `ly-agent`，二进制 `/opt/lyflow/bin/ly-agent`，备份目录 `/opt/lyflow/backups/<timestamp>`。
