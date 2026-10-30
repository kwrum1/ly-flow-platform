# 备份、恢复与回滚手册（Gate 6）

> 适用：`10.1.18.241` 上的 `ly-flow-platform` 演示/验收栈。
> 目标：任何一次升级都能在 10 分钟内回到上一个可用版本；任何一次数据损坏都能用演练过的步骤恢复。

## 1. 需要备份什么

| 资产 | 位置 | 方式 | 频率建议 |
|---|---|---|---|
| PostgreSQL（用户、资产、规则、投影任务、身份令牌） | 容器 `ly-flow-platform-postgres-1` | `pg_dump -Fc` 逻辑备份 | 每日 + 升级前 |
| ClickHouse（事件、会话、迁移账本） | 卷 `ly-flow-platform_clickhouse_data` | 停容器后冷备 tar | 每日 + 升级前 |
| 部署配置 | `/opt/ly-flow-platform/.env`、`docker-compose.override.yml` | 复制归档 | 每次变更 |
| 镜像 | `ly-flow/server:v*`、`ly-flow/frontend:v*` | 保留历史 tag，不删除 | 永久保留最近 5 个 |

不备份：容器日志、`agent-center` 临时缓存、Ray/Redis 流（Redis 仅作传输缓冲，不作为事实源）。

## 2. 备份命令（已演练）

```bash
# PostgreSQL
sudo docker exec ly-flow-platform-postgres-1 \
  pg_dump -U lyflow -Fc lyflow > /opt/lyflow-backup/lyflow-pg.dump
sha256sum /opt/lyflow-backup/lyflow-pg.dump

# ClickHouse 冷备（先停服务，避免半写文件）
sudo docker stop ly-flow-platform-clickhouse-1
sudo docker run --rm \
  -v ly-flow-platform_clickhouse_data:/data \
  -v /opt/lyflow-backup:/backup \
  --entrypoint /bin/sh ly-flow/vendor/clickhouse:24.8-alpine-amd64 \
  -c 'tar czf /backup/clickhouse-data.tgz -C /data .'
sudo docker start ly-flow-platform-clickhouse-1
```

## 3. 恢复步骤

```bash
cd /opt/ly-flow-platform

# 1) 停业务写入（保留依赖容器）
sudo docker compose stop ly-server ly-vis ly-security-engine ly-suricata-sensor

# 2) 恢复 PostgreSQL（先确认目标库存在）
sudo docker exec -i ly-flow-platform-postgres-1 \
  pg_restore -U lyflow -d lyflow --clean --if-exists --no-owner < /opt/lyflow-backup/lyflow-pg.dump

# 3) 恢复 ClickHouse
sudo docker stop ly-flow-platform-clickhouse-1
sudo docker run --rm \
  -v ly-flow-platform_clickhouse_data:/data \
  -v /opt/lyflow-backup:/backup \
  --entrypoint /bin/sh ly-flow/vendor/clickhouse:24.8-alpine-amd64 \
  -c 'rm -rf /data/* && tar xzf /backup/clickhouse-data.tgz -C /data'
sudo docker start ly-flow-platform-clickhouse-1

# 4) 启动并验收
sudo docker compose up -d
cd repo && LYFLOW_BASE=https://10.1.18.241 LYFLOW_ADMIN_PASSWORD=... python acceptance.py
```

## 4. 演练记录

### 4.1 PostgreSQL 逻辑恢复（2026-10-29）

- 备份：`pg_dump -Fc`，759 KB，sha256 记录于 `/opt/lyflow-backup/lyflow-pg.dump`。
- 恢复到**独立**容器 `lyflow-restore-test` + 独立卷 `lyflow_restore_data`，未触碰生产库。
- 行数核对：

| 表 | 生产 | 恢复 |
|---|---|---|
| users | 1 | 1 |
| agents | 1 | 1 |
| hosts | 1 | 1 |
| incidents | 0 | 0 |
| assets | 0 | 0 |

- 行级抽查：`hosts(hostname, agent_id)` 完全一致，RESTORE_MATCH = true。

### 4.2 ClickHouse 冷备（2026-10-29）

- 停容器 → tar 卷 → 启容器，全程 130 MB 归档，sha256 记录于 `/opt/lyflow-backup/clickhouse-data.tgz`。
- 恢复后容器 `healthy`，关键表计数一致：

| 表 | 备份前 | 恢复后 |
|---|---|---|
| lyflow_events_v2 | 0 | 0 |
| lyflow_security_events | 0 | 0 |
| lyflow_traffic_sessions | 6306 | 6306 |
| lyflow_event_storage_migrations | 9 | 9 |

> 迁移账本 `1..9` 完整，说明 schema 与数据一起被冷备覆盖。

### 4.3 镜像回滚（2026-10-29）

```
LY_SERVER_IMAGE=ly-flow/server:v17  ->  v16  ->  v17
```

- `v17 -> v16`：容器 `healthy`，`/api/v1/health` 200，UI 200。
- `v16 -> v17`：容器 `healthy`，9/9 容器 healthy，复跑验收 30/30。

## 5. 升级与回滚规则

1. **数据库只加不删**：迁移 `v1..v9` 均可前滚；回滚镜像**不**回滚 schema（新列有默认值，旧版本可读）。
2. **镜像可回退**：`.env` 里只改 `LY_SERVER_IMAGE` / `LY_FRONTEND_IMAGE`，然后 `docker compose up -d --force-recreate <service>`。
3. **数据卷不可回退**：一旦新版本写入新语义（如 `*_port_known`），回退镜像仍能读，但不要回退数据卷；如必须回退数据，用第 3 节冷备恢复。
4. **阻断能力**：RASP `enforce` 必须同时满足 `LYFLOW_RASP_POLICY_SIGNED=true`、未过期、未触发 `LYFLOW_RASP_EMERGENCY_STOP`；任一不满足即 fail-safe 放行。
5. **一键止损**：
   ```bash
   # 立刻停止一切 RASP 阻断
   sudo sed -i 's|^LYFLOW_RASP_EMERGENCY_STOP=.*|LYFLOW_RASP_EMERGENCY_STOP=true|' /opt/ly-flow-platform/.env
   sudo docker compose up -d --force-recreate ly-server
   ```

## 6. 已知限制

- ClickHouse 冷备需要短暂停机（本次约 20 秒）；如果需要零停机，需配置 `BACKUP` 磁盘并改用 `BACKUP DATABASE`。
- 备份文件目前在 `/opt/lyflow-backup` 本机，尚未异地复制；生产环境必须同步到独立存储。
- 本手册的命令均按 `ly-flow-platform` 栈命名，换栈名时同步替换容器名。

## 7. 验收用传感器（ly-agent-node）

`10.1.18.241` 上的真实传感器以容器方式运行，用于验证采集可见性与 Gate 2：

```bash
sudo docker run -d --name ly-agent-node --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /opt/ly-agent/data:/opt/ly-agent/data \
  -e API_SERVER=https://10.1.18.241 -e API_INSECURE_SKIP_VERIFY=true \
  -e AGENT_ID=<uuid> -e AGENT_ENROLL_TOKEN=<token> \
  -e TRAFFIC_ENABLED=true -e TRAFFIC_INTERFACE=lo -e CAPTURE_ENGINE=af_packet \
  -e SPOOL_ENABLED=true -e SPOOL_DIR=/opt/ly-agent/data/spool \
  -e HIDS_ENABLED=false -e ASSET_ENABLED=false -e RASP_ENABLED=false \
  ly-flow/local-mirror:release-amd64
```

- 首次 enrollment 依赖 `/opt/ly-flow-platform/.env` 的 `AGENT_ID` / `AGENT_ENROLL_TOKEN`，并通过
  `docker-compose.override.yml` 注入 `ly-server`；token 只在服务启动后 15 分钟内有效。
- 注册成功后 agent key 保存在 `/opt/ly-agent/data`，后续重启无需再 enroll。
- **轮换**：删除容器与数据卷 → 更新 `.env` 的两个变量 → 重启 `ly-server` → 用新 token 重新 enroll。
- 不要在仓库或文档中记录真实 token；本手册只写变量名。

