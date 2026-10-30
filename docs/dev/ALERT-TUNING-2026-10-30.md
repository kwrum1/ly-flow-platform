# 告警降噪与规则优化（2026-10-30）

实例：`10.1.18.125`（镜像口 `mirror0`，Suricata 8.0.7，57 条 server-zone 规则）

## 0. 结论

- 优化前：6 个 EVE 窗口共 **1,492 条告警 / 8 类规则**。
- 优化后：新窗口 **30,206 行 EVE / 0 条告警**（约 5 分钟），检测链路正常。
- 所有改动写入源码：
  - `rules/ly-custom/{c2,frp,proxy,webshell,scanner}.rules`
  - `rules/suricata/et-open.rules`
  - `server/cmd/debug.go`（`ops.backup` 空目录判定）
- 通过规则平台重新导出并部署到 `.241` 与 `.125`，`overlap_count=0`。

## 1. 逐条处理

### 1.1 SID 9003023 — Fscan UDP Scan（792 条）

- 现象：正常 DNS 查询/响应被当成 UDP 扫描。
- 原因：规则只有 30 包/60 秒阈值，没有内容条件。
- 处理：增加 `dsize:0;`，只匹配空载荷 UDP 探测。
- 同时确认：**规则源文件** `rules/ly-custom/scanner.rules` 必须包含该修复，
  否则规则平台重新导出会把它丢掉（本次已修复该回归）。

### 1.2 SID 1000050 — ET DNS Tunnel（272 条）

- 现象：DNS 服务器 `10.1.0.4 / 10.1.0.251` 查询 `ntp.ubuntu.com`、
  `edge-consumer-static.afd.azureedge.net`、`awsboclb-web01-...` 等正常域名。
- 原因：原 pcre `/[a-z]+\.[a-z]{5,}\.[a-z]{2,4}$/` 命中任意三段域名。
- 处理（按产品要求：长标签 + 无连字符 + 含数字）：
  - `flow:to_server`：只匹配查询方向，避免响应方向重复告警；
  - pcre：`/^(?=[a-z0-9]{24,}\.)(?=[a-z0-9]*[0-9])[a-z0-9]+\./i`；
  - 阈值 5 次/60 秒。
- 验证：
  - `edge-consumer-static...`、`awsboclb-web01-...`、`onedsblobvmssprdcus04...` → 不命中；
  - 30~40 位随机字母数字标签 → 命中。

### 1.3 SID 9002003 — CobaltStrike DNS Beacon（195 条）

- 现象：`*.data.sru.edu.cn`，195 个唯一 40 位随机标签，
  外部递归 DNS 回包到 `10.1.0.6:53`。
- 产品确认：`data.sru.edu.cn` 是**已停用域名**，`10.1.0.6` 是公网权威 DNS，
  该域名没有真实服务器，可以忽略。
- 处理：
  - 同样收紧为“24+ 位、纯字母数字、含数字”标签；
  - 增加 `content:!"sru.edu.cn"`，在规则层排除该停用域名（不依赖 suppress）；
  - `flow:to_server` 去重查询/响应两个方向；
  - 阈值 5 次/60 秒。
- 注意：该形态本身高度接近 DNS 隧道，保留规则用于其他域名。

### 1.4 SID 9001005 — FRP TLS First Byte（162 条）

- 现象：`42.62.2.134 -> 10.1.0.64:44657`、`10.1.0.192:80 -> 10.1.18.252` 等正常 TLS。
- 原因：规则匹配 `17 03`（TLS 1.2 应用数据记录），**所有 TLS 都会命中**，
  与 FRP 没有必然关系。
- 处理：重写为“默认 FRP 控制端口 7000 上的 TLS 建连”：
  - `alert tls ... -> any 7000`
  - `flow:established,to_server`
  - 5 分钟每源限 1 条
- 说明：FRP 开启 TLS 后控制通道与普通 TLS 无法仅靠载荷区分，
  端口范围检测比“匹配任意 TLS 记录”更可靠；明文 FRP 仍由
  `LY-FRP-001/002/003/004` 覆盖。

### 1.5 SID 9001009 — FRP HTTP Basic Auth（46 条）

- 现象：`10.1.0.192:80 -> 10.1.18.252:highport`、
  `10.1.2.40:80 -> 10.1.18.251:highport`，正常代理认证。
- 原因：规则无方向，且匹配 `proxy-authorization` + `Basic` 两个宽字符串，
  响应方向也会命中。
- 处理：
  - `flow:established,to_server`；
  - `http.request_header` 缓冲；
  - 每源每分钟最多 1 条。

### 1.6 SID 9007022 — Venom Admin Port 65010（12 条）

- 现象：公网 IP → 内网 `65010`，但公网并未开放 65010。
- 根因（已用 EVE 原始字段确认）：

```text
flow: 10.1.0.11:65010 -> 60.28.214.153:80
alert packet: 60.28.214.153:80 -> 10.1.0.11:65010, direction=to_client
```

  内网主机用 **临时源端口 65010** 访问公网 80，响应包的目的端口是 65010，
  旧规则没有方向，把响应包当成“访问 Venom 管理端口”。
- 处理：
  - `flow:established,to_server`；
  - 每源 5 分钟最多 1 条。
- 优化后该类告警归零；真正的入站 65010 建连仍会告警。

### 1.7 SID 9004301 — WScript.Shell（8 条）

- 现象：`10.5.10.17:80 -> 10.64.x.x:highport`。
- 产品确认：`10.5.10.17` 是知网代理服务器，`10.64.0.0/16` 是认证用户上网段。
- 原因：规则匹配任意 HTTP 载荷中的 `WScript.Shell`，代理转发页面会命中。
- 处理：
  - 只匹配响应方向 `flow:established,to_client`；
  - 只匹配服务端脚本文件 `file.name` 后缀
    `php|asp|aspx|jsp|jspx|ashx|asmx|cer`；
  - `file.data` 中匹配关键字。
- 实测：用真实 HTTP 响应验证，`shell.php` 返回体含 `WScript.Shell` 可命中；
  代理转发的 HTML 页面不再命中。

### 1.8 SID 9004601 — Godzilla WebShell（6 条）

- 现象：`10.1.0.192:80 -> 10.1.18.252:highport`，大体积 HTTP 响应。
- 原因：`pass` + `key` + `AES` 三个字符串在前端 JS 包中很常见，且无方向限制。
- 处理：
  - `flow:established,to_client`；
  - 只匹配脚本文件后缀；
  - 三个标记必须在 `file.data` 中同时出现；
  - 2 次/60 秒。

## 2. ops.backup

- 问题：全新实例 `/backup` 可读但为空，`checkBackupDirectory` 返回 `degraded`。
- 处理（`server/cmd/debug.go`）：
  - 目录不可读 → `unknown`；
  - 目录可读 → 一律 `ok`；
  - 空目录消息改为 `backup directory ready, no backups yet`。
- 新增测试 `server/cmd/debug_backup_test.go`：
  - 空目录 → ok；
  - 有文件 → ok；
  - 目录不存在 → unknown。
- 部署：`server:v61` 已部署到 `.241` 与 `.125`。
- 结果：
  - `.241`：`ok`，count=3；
  - `.125`：`ok`，count=0。

## 3. 验证

### 3.1 规则加载

```text
241: 57 rules successfully loaded, 0 failed
125: 57 rules successfully loaded, 0 failed
overlap_count: 0
suricata: 57  lyprobe: 9
```

### 3.2 离线 PCAP 功能验证（`.241`）

- DNS：6 条 30 位随机标签查询 → `1000050`、`9002003` 各命中 1 次。
- HTTP：`shell.php` 响应体含 `WScript.Shell` → `9004301` 规则形态命中。
- 普通 HTML/JS、正常 CDN 域名 → 不命中。

### 3.3 线上窗口

```text
EVE lines: 30,206
alerts:    0
services:  9/9 healthy
```

## 5. 新增：SMB Negotiate on Non-Standard Port（SID 9003024）

### 5.1 告警报文

```text
121.43.119.139:36780 -> 10.3.10.74:8080   TCP ACK+PSH   222 bytes
00 00 00 A4 FF 53 4D 42 72 ...
```

解码：

- `00 00 00 A4`：NetBIOS Session Service，长度 164；
- `FF 53 4D 42`：SMB1 头；
- `72`：`SMB_COM_NEGOTIATE`；
- 方言列表：`PC NETWORK PROGRAM 1.0`、`MICROSOFT NETWORKS 1.03`、
  `LANMAN1.0`、`LM1.2X002`、`Samba`、`NT LM 0.12`。

这是**真实的 SMB1 Negotiate 请求**，不是随机载荷。SMB 只应出现在
139/445；外网主机把它发到 8080，属于扫描、SMB-over-HTTP 隧道或漏洞探测，
判定为真实告警。

### 5.2 为什么旧规则会报

ET/GPL 的 SMB 规则经过“单模式转换”后丢失了端口和配套条件，出现：

```text
value: "^.{27}"      # 任意 >=27 字节载荷
value: "|00|"        # 字面量 "|00|"
value: "|FF|SMB%"    # 字面量，不可能匹配真实二进制
```

这些规则要么是泛匹配、要么永远不命中。v62 的
`pattern_too_generic` 门禁已经把它们从运行时移除。

### 5.3 新规则

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET ![139,445] (
  msg:"[LY-SCAN-004] Server Message Block Negotiate on Non-Standard Port";
  flow:established,to_server;
  content:"|FF 53 4D 42 72|"; offset:4; depth:5;
  threshold:type limit, track by_src, count 1, seconds 300;
  classtype:attempted-recon; sid:9003024; rev:1;)
```

- 只匹配外网 → 内网；
- 排除标准 SMB 端口 139/445；
- 在 NetBIOS 头之后精确匹配 `FF SMB 72`；
- 每源 5 分钟最多 1 条，避免扫描刷屏。

### 5.4 验证

用告警原文重建 PCAP（含三次握手 + 该数据包 + ACK），离线运行：

```text
SID 9003024 命中 1 次
58 条 Suricata 规则加载成功，0 failed
```

如果 `10.3.10.74:8080` 实际是已知的 SMB 网关/代理，应只对
`dst 10.3.10.74 and dport 8080` 做定向例外，而不是关闭整条规则。

## 6. 风险与后续

1. `10.1.0.6` 作为权威 DNS 仍可能收到历史域名/扫描流量；当前按域名排除，
   如后续该域名重新启用，需要移除 `content:!"sru.edu.cn"`。
2. FRP TLS 只能按默认端口 7000 检测；改用非默认端口的 TLS 模式仍无法识别，
   依赖流量行为与 JA3 规则补充。
3. WebShell 规则只覆盖“脚本后缀的响应”；上传型 WebShell（请求体）未新增规则，
   避免再次引入代理噪声。
4. `file.name` + `file.data` 依赖 HTTP 事务完整；大文件或分块传输需要后续观察。

## 7. 规则转换自查：端口与配套条件丢失

对 5 个外部签名源做了逐条审计（ET Open、PT Security、Snort Community、
Stamus、OISF traffic-id），共 52,453 条原始规则。

### 7.1 审计口径

转换器把 Suricata 规则压成“一个字段 + 一个模式”，原规则里的：

```text
端口（如 445 / 5060 / 25 / 21 / 1024:）
方向（flow:to_client / from_server）
dsize / offset / depth / distance / within
byte_test / byte_jump / isdataat / urilen / threshold
```

全部不会被保留。判断标准：

- 模式没有 6 位以上连续字母数字 → 拒绝；
- 模式是裸域名或常见词（server/windows/samba/debian.org 等）→ 拒绝；
- `contains` 模式里还有 `|`（二进制内容无法表示）→ 拒绝；
- 丢失了端口/响应方向/偏移等约束，且模式特征 <12 位 → 拒绝；
- 强特征（≥12 位）即使丢了约束也保留。

### 7.2 结果

```text
原始规则              52,453
主动流量规则（改前）      531
主动流量规则（改后）      186
```

`detection_rules` 中被标为 unsupported 的原因：

```text
unrepresentable_binary_content   471
pattern_too_generic              394
lost_match_constraints           195
missing_condition_field           18
bare_domain                       14
common_token                       3
invalid_regex                      2
```

### 7.3 典型的“丢端口/丢条件”规则

| 规则 | 原约束 | 转换后 | 风险 |
|---|---|---|---|
| ET CHAT IRC PRIVMSG | `!6661:6668` + flow | `PRIVMSG` 任意端口 | 任意协议误报 |
| ET CHAT IRC USERHOST | `!6661:6668` | `USERHOST` 任意端口 | 同上 |
| ET VOIP SIP REGISTER/INVITE | `5060` | `REGISTER` / `INVITE` 任意端口 | HTTP 注册/邀请误报 |
| ET P2P Gnutella | `1024:` + depth | `GNUTELLA` 任意端口 | 低 |
| ET P2P BitTorrent | `6881:6889` | `BitTorrent protocol` | 低 |
| ET ATTACK_RESPONSE FTP Banner | `21` + flow | banner 字符串任意端口 | 低 |
| ET MALWARE 邮件上报 | `25` + within | 邮件头字符串任意端口 | 中 |
| GPL NETBIOS SMB | `445` + offset | `^.{27}` / 二进制字面量 | 泛匹配 |
| OISF traffic-id | TLS/HTTP | `debian.org`、`google.com` | 正常流量刷屏 |

### 7.4 处理

- 上述规则在 v63 中统一标记 `unsupported`，不再进入安全引擎运行时；
- 安全引擎活动包从 531 条流量规则降到 186 条；
- `.125` `threat_events` 保持 0；
- 仍保留强特征规则（例如 `Meterpreter`、`Installation of SC-KeyLog on host`、
  `WScript.Shell` 等）。

### 7.5 仍存在的边界

- 方向（`to_client/from_server`）没有在运行时表达，强特征规则仍可能匹配
  响应方向；如果后续要彻底严谨，需要把端口和方向作为 conditions 存进
  规则包，或者让这类签名只留在 Suricata。
- `oisf-trafficid` 整源被判定为“没有可运行规则”，同步会返回
  `no runtime-compatible rules`。这是预期行为，不应视为故障。

## 8. 默认规则降噪（DPI / 日志）

### 8.1 已下线

| 规则 | 原因 |
|---|---|
| `dpi-admin-access-default` | 内部用户访问 `/admin`、`/manager` 等路径即告警；`10.64.24.223 → 10.1.0.192` 已确认误报 |
| `log-collector-heartbeat-default` | 日志采集器心跳不是威胁，只是健康信号；曾产生 155 条事件 |

处理方式：

- 从 `rules/security-engine/default-bundle.json` 移除；
- 代码增加 `retiredDefaultDetectionRuleIDs`，启动/同步时把旧数据库中的同名规则
  置为 `enabled=false, support_level=unsupported`；
- 运行时 loader 再次跳过，避免旧库或重装后复活。

### 8.2 收紧

`dpi-c2-domain-default` 原规则：

```text
(?i)(malware|miner|callback|beacon|\.xyz$)
```

`callback`、`beacon` 和整个 `.xyz` 后缀都会命中正常业务域名。改为按标签边界匹配：

```text
(?i)(^|\.)(malware|miner|ransom|stealer|botnet|c2)(\.|$)
```

### 8.3 结果

```text
.125  dpi-admin-access-default 事件: 5 -> 0
.241  log-collector-heartbeat-default 事件: 155 -> 0
活动 bundle 中已无这两条规则
threat_events: .125 = 0, .241 = 635
```

### 8.4 仍可继续观察

- `log-privilege-escalation-default` 目前会匹配所有 `pam_unix(sudo`，
  可进一步收紧为只匹配 `useradd/usermod/passwd/visudo/...`；
- `runtime-suspicious-download-default` 会匹配管理员正常 `curl/wget` 下载；
- 这两条尚未造成大规模噪声，等出现样本后再改。
