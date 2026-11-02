# 告警降噪与规则优化（2026-11-02）

实例：`10.1.18.125`（镜像口 `mirror0`，Suricata 8.0.7，37,945 条规则）

## 0. 本轮结论

- 24 小时噪声 Top：MSSQL 1433 扫描 968 条、WScript.Shell 264 条、
  Bare IP 下载 97 条、FRP Basic Auth 75 条、爬虫 UA 18 条、
  `smtcdns.com` DNS 9 条。
- 全部在**规则源头**处理，不依赖事后 suppress；ET Open 家族写进
  `deploy/suricata/et-open-refresh.sh`，每日刷新后仍然生效。
- 历史事件先备份再删除：`threat_events_noise_20261102_backup`。
- `.125` 磁盘从 92%（3.4G 可用）降到 82%（6.9G 可用）。

## 1. 抓包基线

除态势感知平台自身地址外全部抓取，包含服务器区内网互访：

```yaml
bpf-filter: "not ( host 10.1.18.125)"
```

自身地址通过 `SURICATA_SELF_IPS`（或 `LYFLOW_SENSOR_SELF_IPS`）配置，
逗号或空格分隔。端口扫描、横向移动、内网 Web 攻击都会进入 Suricata。

## 2. 逐条处理

### 2.1 ET SCAN Suspicious inbound to MSSQL port 1433（968 条 / 24h）

- 现象：18 个内网源（`10.4.x`、`10.5.x`、`10.2.x`、`10.19.x`）访问
  `10.5.10.17:1433`，全天持续。
- 判断：业务系统连接 SQL Server 的正常连接池流量，不是扫描。
- 处理：在 ET Open 刷新脚本的 `DROP_PREFIXES` 中删除该家族。

### 2.2 ET SCAN Behavioral Unusual Port 1433 traffic（14 条 / 24h）

- 源与目的和 2.1 完全相同（`10.2.8.82`、`10.4.0.48`、`10.4.17.92`、
  `10.4.2.235`、`10.4.3.79`、`10.5.134.10` → `10.5.10.17:1433`）。
- 判断：同一批业务连接触发了 40 次/60 秒阈值。
- 处理：同样在 `DROP_PREFIXES` 中删除。

### 2.3 爬虫 User-Agent（18 条 / 24h）

- DuckDuckGo 8 条、AOL 7 条、Naver 3 条，均为搜索引擎爬虫。
- 处理：删除以下家族（前缀匹配，覆盖带括号的变体）：
  - `ET SCAN DuckDuckGo Webcrawler User-Agent`
  - `ET SCAN AOL Webcrawler User-Agent`
  - `ET SCAN Naver Webcrawler User-Agent`
  - `ET SCAN Google Webcrawler User-Agent`
  - `ET SCAN Yandex Webcrawler User-Agent`
  - `ET SCAN Bing Webcrawler User-Agent`

### 2.4 ET MALWARE Suspicious Download from Bare IP（97 条 / 24h）

- 现象：`10.4.16.30`、`10.64.53.6` 等 9 个客户端访问
  `10.1.0.192` 的 `jquery.ztree.exedit.js`，返回 304。
- 原因：规则用 `content:".exe"` 匹配 URI，`.exedit` 被当成 `.exe`。
- 处理（`rules/suricata/et-open.rules`，rev 3）：
  - 把 `content:".exe"` / `content:".zip"` 改成锚定结尾的
    `pcre:"/\.exe(\?|$)/i"` / `pcre:"/\.zip(\?|$)/i"`；
  - 保留“裸 IP + 可执行文件下载”的检测能力，不再误报 `.exedit`。

### 2.5 LY-WSHELL-CN-001 WScript.Shell（264 条 / 24h）

- 现象：全部来自 `10.1.2.41:8099` 的 `/Modules/Wdxm/Wdxm.aspx` 正常页面。
- 原因：ASP.NET 页面的 IE 打印辅助脚本使用
  `new ActiveXObject("WScript.Shell")`，被当成服务端 WebShell。
- 处理（`rules/ly-custom/webshell.rules`，rev 3）：
  - 保留 `WScript.Shell` 和脚本后缀条件；
  - 追加服务端构造条件
    `pcre:"/(?:Server\.CreateObject|new\s+COM|COMObject|\.Exec\s*\()/i"`；
  - 客户端 `ActiveXObject` 不再命中，ASP/PHP 服务端 WebShell 仍能命中。

### 2.6 LY-WSHELL-CN-002 cmd.exe（7 条 / 24h）

- 现象：`10.1.0.101`、`10.1.0.192` 等返回的页面中包含 `cmd.exe` + `/c`。
- 处理（rev 2）：增加 `flow:established,to_server`，只检查请求方向。

### 2.7 LY-FRP-009 FRP HTTP Proxy Basic Auth（75 条 / 24h）

- 现象：`10.1.18.252` 反向代理转发 `xsgzc.sru.edu.cn` 页面到
  `10.1.0.192`，请求头带 `Proxy-Authorization: Basic` 和
  `X-Forwarded-For`。
- 判断：反向代理的正常认证转发，不是 FRP 客户端。
- 处理（rev 3）：增加
  `http.header_names; content:!"X-Forwarded-For";` 和
  `content:!"X-Real-IP";`；直连 FRP 客户端不带这两个头，仍会告警。

### 2.8 LY-PROXY-111 Oport Tunnel（9 条 / 24h）

- 现象：全部来自代理 `10.1.2.40:80` 的响应页面，含 `oport` + `connect`。
- 处理（rev 2）：增加 `flow:established,to_server`，只看请求方向。

### 2.9 LY-CS-003 CobaltStrike DNS Beacon（9 条 / 24h）

- 现象：`v.smtcdns.com` 的 32 位调度标签，属于电信 CDN。
- 处理（`rules/ly-custom/c2.rules`，rev 6）：在 pcre 排除列表中加入
  `smtcdns.com`，与 `footprintdns.com`、`imtmp.net` 等同等处理。

## 3. 事件清理

先备份再删除，备份表：

```sql
threat_events_noise_20261102_backup
```

清理范围：

- `ET SCAN Suspicious inbound to MSSQL port 1433`（968）
- `ET SCAN Behavioral Unusual Port 1433 ...`（14）
- 6 个爬虫 UA 家族（18）
- `ET MALWARE Suspicious Download from Bare IP` 且 URL 含 `exedit`（97）
- `LY-WSHELL-CN-001`（264，全部来自 `10.1.2.41`）
- `LY-FRP-009`（76，全部来自 `10.1.18.252`）
- `LY-PROXY-111`（9，全部来自 `10.1.2.40`）
- `LY-CS-003` 且 DNS 查询含 `smtcdns.com`（9）

`LY-WSHELL-CN-002` 的低量历史事件保留，由 rev 2 的方向限制阻止新增。

## 4. 磁盘清理

清理前：`38G` 总量，`35G` 已用，`3.4G` 可用（92%）。

- 截断 ClickHouse 系统日志表：`text_log`、`processors_profile_log`、
  `part_log`、`query_log`、`trace_log`、`metric_log`、
  `asynchronous_metric_log`。
- EVE 归档只保留最近 24 个 `.gz`（约 24 小时）。
- 删除 Redis 遗留的 `temp-7.rdb`（BGSAVE 失败残留，817MB）。

清理后：`31G` 已用，`6.9G` 可用（82%）。

> 注意：PostgreSQL `traffic_sessions` 仍是主要占用（约 11GB / 3 天，
> 每天约 1.2M 行）。当前保留 3 天是为了漏扫对比；后续如果磁盘再次吃紧，
> 优先评估把该表保留期降到 48 小时，或在低峰期 `VACUUM FULL`。

## 5. 验证

- Suricata 规则加载：`0 rules failed`，规则数 37,945（ET Open 37,888 +
  自定义 58，去重后）。
- 刷新脚本：MSSQL 1433、爬虫 UA 家族被正确 drop，manifest 正常写入。
- 变更后观察窗口：上述家族新增 0 条；真实内网扫描/横向告警正常进入。
- 源码、GitHub、Gitea 三处一致，PR 合并后重新编译并镜像发布。
