# 流影平台当前运维说明

## 生产启动

```bash
cd /opt/ly-flow-platform
docker compose up -d
docker compose ps
```

默认访问 `https://<设备地址>/`，管理端口为 443。默认生产组件包括前端、核心 API、Agent 控制中心、安全引擎、本机镜像探针、PostgreSQL、Redis 和 ClickHouse。

## 数据职责

- PostgreSQL：账号、资产、Agent、规则、配置、事件生命周期和 Incident 处置状态。
- ClickHouse：长期保存全量会话、流量审计和溯源查询数据。
- Redis：事件总线、实时处理队列和短期状态，不作为长期事实数据源。

## 采集边界

- 本机镜像口由控制中心选择，管理口不会出现在可选镜像口列表中。
- 本机高流量镜像使用 PF_RING。
- Linux Agent 面向 CentOS 7 / Linux 3.10，使用 AF_PACKET，并承担 RASP、runtime、日志、YARA 和小流量采集。
- Windows Agent 使用单文件包；Npcap 作为独立依赖下载安装。

## 规则更新

规则中心按规则源展示当前版本、最新版本和运行状态。更新流程为版本发现、固定版本下载、格式转换、编译校验、签名/清单更新和热生效。单条不兼容规则应隔离并记录原因，不得让整个规则包假成功。

## QA 与兼容 Profile

`compose.qa.yml`、`compose.legacy-dpi.yml`、`fixtures/` 和 `scripts/qa/` 只用于测试和兼容性验证，不应加入默认生产启动命令。容器化 Agent 仅用于 QA；政企现场使用无容器静态 Agent。

## 发布前检查

```bash
cd frontend && npm run test -- --run && npm run build
cd ../server && GOWORK=off go test ./...
cd .. && docker compose config
```

完成构建后，必须核对容器健康状态、镜像接口、规则热生效、Agent 注册、全量会话写入和 XDR/ATT&CK 证据链。
