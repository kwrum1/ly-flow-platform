# 反代 XFF 真实客户端归因（2026-11-04）

## 现象

真实链路里 `10.1.18.251` / `10.1.18.252` 是反向代理，代理会把真实客户端写入
`X-Forwarded-For`（XFF），但事件列表的来源 IP 只能看到代理地址。

## 根因

- Suricata 抓到的 HTTP 事务里，`src_ip` 是 TCP 层的代理地址；
- 真实客户端在 EVE 的 `http.xff` 字段里（`raw_event.eve.http.xff`）；
- `server/cmd/suricata_eve_ingest.go` 直接把 `event["src_ip"]` 写入
  `threat_events.src_ip`，没有做可信代理归因；
- 代码里已有 `resolveSourceAttribution` 和 `xdr_trusted_proxies` 表，但
  Suricata 入库链路没有使用它们，且 `xdr_trusted_proxies` 为空。

## 方案

1. 在 `xdr_trusted_proxies` 登记反代地址（本环境为
   `10.1.18.251/32`、`10.1.18.252/32`，`tenant_id=default`）。
2. Suricata 入库时：
   - 读取 `http.xff`；
   - 用 `resolveSourceAttribution` 从右向左跳过可信代理，取第一个不可信地址；
   - 把真实客户端写入 `threat_events.src_ip`；
   - 在 `raw_event` 保留 `proxy_ip`、`client_ip` 和完整的
     `source_attribution`（含 `xff_chain`、`confidence`、`reason`）。
3. 只信任 `xdr_trusted_proxies` 中的地址；远端不在白名单时忽略 XFF，防止伪造。
4. 事件 UID 仍按原始 TCP 五元组计算，避免归因变化导致重复事件。

## 代码

- `server/cmd/suricata_eve_attribution.go`：XFF 归因包装函数。
- `server/cmd/suricata_eve_ingest.go`：启动时加载可信代理；入库时替换
  `src_ip` 并写入 `proxy_ip`/`client_ip`/`source_attribution`。
- `server/cmd/suricata_eve_attribution_test.go`：可信代理、不可信远端、
  空 XFF、多跳链、无反代场景。

## 部署

- 需要重新构建 `ly-flow/server` 镜像；
- 启动前写入可信代理表（已在本环境执行）：
  ```sql
  INSERT INTO xdr_trusted_proxies (tenant_id, cidr, description, priority)
  VALUES ('default','10.1.18.251/32','reverse proxy',100),
         ('default','10.1.18.252/32','reverse proxy',100)
  ON CONFLICT (tenant_id, cidr) DO NOTHING;
  ```
- 重启 `ly-server` 后生效。

## 验证

以 2026-11-04 的实际事件为例：

```text
proxy=10.1.18.252  xff=112.91.91.10   host=www.sru.edu.cn
proxy=10.1.18.252  xff=27.46.69.5     host=www.sru.edu.cn
proxy=10.1.18.252  xff=113.194.216.99 host=ssm.sru.edu.cn
```

部署后事件列表应显示 `112.91.91.10`、`27.46.69.5`、
`113.194.216.99`，详情里保留 `proxy_ip=10.1.18.252`。

## 限制

- `lyflow_traffic_sessions`（flow 引擎会话）目前没有 HTTP 头，XFF 只存在于
  Suricata EVE；流量会话页仍只能看到代理。若也要在流量页显示真实 IP，
  需要 flow 引擎或 local-mirror 解析并透传 XFF。
- 反代必须覆盖/追加 XFF，不能原样透传客户端自带的 XFF；否则仍可能被伪造。
