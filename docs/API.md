# 流影 API 文档

> Base URL：`https://<server>/api/v1`  
> 默认认证：登录后使用返回 token。前端通过同源 HTTPS 反向代理访问 API。

## 1. 通用响应

成功响应通常为：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

列表响应通常包含：

```json
{
  "items": [],
  "total": 0,
  "limit": 50,
  "offset": 0
}
```

错误响应包含错误码和信息，HTTP 状态码与错误语义一致。

## 2. 健康与概览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 服务健康检查 |
| GET | `/stats` | 平台统计概览 |
| GET | `/public/situation/global` | 公共态势展示数据 |

## 3. 认证与用户

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录，返回 token、用户信息、是否强制改密 |
| POST | `/auth/logout` | 注销当前 token |
| GET | `/auth/profile` | 当前用户信息 |
| POST | `/auth/change-password` | 当前用户修改密码 |
| GET | `/auth/users` | 用户列表 |
| POST | `/auth/register` | 创建用户 |
| PUT | `/auth/users/{id}` | 更新用户 |
| DELETE | `/auth/users/{id}` | 删除用户 |
| PUT | `/auth/users/password` | 管理员重置用户密码 |

### 登录示例

```bash
curl -k -X POST https://<server>/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"password"}'
```

## 4. Agent 与资产

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/agents` | Agent 列表 |
| GET | `/agents/{agent_id}` | Agent 详情 |
| DELETE | `/agents/{agent_id}` | 删除离线 Agent |
| POST | `/agent/enroll` | Agent 自注册 |
| POST | `/agent/heartbeat` | Agent 心跳与状态更新 |
| POST | `/agent/config` | Agent 拉取配置 |
| POST | `/agent/task-result` | Agent 任务结果上报 |
| POST | `/agent/component-alert` | Agent 上报组件告警 |
| POST | `/agent/runtime-event` | Agent 上报运行时事件 |
| POST | `/agent/snapshot` | Agent 资产快照上报 |
| GET | `/agent/install.sh` | 动态安装脚本 |
| GET | `/agent/uninstall.sh` | 动态卸载脚本 |
| GET | `/agent/download` | Agent 二进制下载 |
| PUT | `/agent/capabilities/{agent_id}` | 开关 Agent 能力 |
| PUT | `/agent/name/{agent_id}` | 修改 Agent 展示名 |
| GET/PUT | `/agent/names` | 展示名映射 |
| GET | `/assets` | 资产列表 |
| GET | `/assets/{host_id}` | 资产详情 |
| GET | `/assets/stats` | 资产统计 |
| GET | `/assets/groups` | 资产组列表 |
| POST | `/assets/heartbeat` | 资产心跳兼容接口 |

资产列表返回前会同步 Agent 离线状态：超过 5 分钟无心跳的 Agent 和绑定 Host 会显示 `offline`，最近上报时间来自真实快照时间，不使用读取时间伪造实时状态。

## 5. 流量观测与威胁

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/traffic/flows` | 流量 Flow 查询 |
| GET | `/traffic/sessions` | 持久化会话查询，支持 `query`、分页 |
| GET | `/traffic/threats` | 流量威胁兼容入口 |
| GET | `/threats/{category}` | 分类威胁列表：`traffic`、`runtime`、`rasp`、`log_audit` |
| GET/PUT | `/traffic/mirror-interface` | 本机镜像接口配置 |

### 会话查询参数

| 参数 | 说明 |
|---|---|
| `query` | 主机名、Agent 名、IP、域名、协议等关键字 |
| `limit` | 返回数量，默认 50 |
| `offset` | 分页偏移 |

### 威胁返回关键字段

- `category`：威胁分类。
- `severity`：`low` / `medium` / `high` / `critical`。
- `agent_id`、`display_name`、`probe_name`：来源 Agent 或镜像。
- `src_ip`、`dst_ip`、`src_port`、`dst_port`：网络上下文。
- `aggregate_key`、`count`、`first_seen`、`last_seen`：聚合展示字段。

## 6. 规则中心

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/rules` | 规则概览 |
| GET | `/rules/inventory` | 规则库存 |
| GET | `/rules/reports` | 规则报告 |
| GET | `/rules/categories` | 规则分类 |
| GET | `/rules/stats` | 规则统计 |
| POST | `/rules/test` | 规则测试 |
| GET/POST | `/rules/sources` | 规则源列表 / 新增 |
| POST | `/rules/sources/{id}` | 更新规则源 |
| GET/POST | `/rules/subscription` | 订阅配置 |
| POST | `/rules/update` | 规则更新 |
| GET | `/rule-platform/sources` | 规则平台源 |
| GET | `/rule-platform/bundles` | Bundle 列表 |
| POST | `/rule-platform/sync` | 同步规则源 |
| POST | `/rule-platform/compile-preview` | 编译预览 |
| GET/POST | `/rule-platform/active-bundle` | 当前生效 Bundle |
| GET | `/rule-platform/versions` | 版本列表 |
| POST | `/rule-platform/rollback` | 回滚版本 |

规则中心会生成并热加载 `rules/security-engine/active-bundle.json`。

## 7. XDR、Incident 与时间线

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/xdr/stats` | XDR 统计 |
| GET | `/xdr/events` | XDR 事件 |
| GET | `/xdr/sources` | XDR 来源 |
| GET | `/xdr/top-events` | Top 事件 |
| GET | `/xdr/chains` | 攻击链 |
| GET | `/xdr/posture` | XDR 态势 |
| GET/POST | `/xdr/log` | XDR 日志接口 |
| GET | `/unified/stats` | 统一事件统计 |
| GET | `/unified/events` | 统一事件查询 |
| POST | `/unified/events/search` | 统一事件搜索 |
| GET | `/incidents` | Incident 列表 |
| GET | `/incidents/{id}` | Incident 详情 |
| GET | `/timeline` | 时间线 |
| GET | `/timeline/{id}` | 时间线详情 |

Incident 只来自关联链。详情中的 `stage_groups` 按攻击阶段挂载证据，证据包含时间。

## 8. RASP、Trace 与引擎状态

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/rasp/stats` | RASP 统计 |
| GET | `/rasp/events` | RASP 事件 |
| GET | `/rasp/rules` | RASP 规则 |
| GET | `/rasp/agents` | RASP Agent |
| POST | `/rasp/event` | RASP Probe 事件上报 |
| POST | `/rasp/protection/enable` | 开启保护 |
| POST | `/rasp/protection/disable` | 关闭保护 |
| GET | `/rasp/protection/status` | 保护状态 |
| GET | `/trace/stats` | Trace 统计 |
| GET | `/trace/sessions` | Trace 会话 |
| GET | `/trace/events` | Trace 事件 |
| POST | `/trace/analyze` | Trace 分析 |
| GET | `/trace/search` | Trace 搜索 |
| GET | `/engine-health` | 检测引擎健康 |
| GET | `/engine-runtime/status` | 原生引擎运行状态 |
| GET/POST | `/engine-rules` | 原生引擎规则 |
| POST | `/engine-rules/update` | 更新原生引擎规则 |

## 9. WebSocket

| 路径 | 说明 |
|---|---|
| `/api/v1/realtime` | 低频实时仪表盘推送 |

前端通过 HTTPS 同源代理访问，生产环境建议保留 `X-Forwarded-Proto: https`。
