# ly_probe 服务器区探针部署

上游：`https://github.com/Abyssal-Fish-Technology/ly_probe`，固定 revision
`06c097dd5c69e391efd3c8b3776d672e03386e49`（与 `patches/lyprobe/README.md` 一致）。

LyFlow 不修改上游抓包/流算法，只通过 `patches/lyprobe/0001-hot-reload.patch`
增加指纹规则热加载。ly_probe 以独立进程运行，不链接进自有二进制。

## 构建

```bash
cd /opt/lyflow/src
LYPROBE_SOURCE_DIR=/opt/lyflow/build/lyprobe-source \
LYPROBE_OUTPUT_DIR=/opt/lyflow/artifacts/lyprobe \
LYPROBE_JOBS=4 LYPROBE_CPUS=2 \
bash scripts/dev/lyprobe-build.sh
```

源码目录必须是干净的 git 工作区。Windows 检出的源码可能带 CRLF，
构建前需把文本文件规范化为 LF：

```bash
python3 - <<'PY'
import os
root = "/opt/lyflow/build/lyprobe-source"
for base, dirs, files in os.walk(root):
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        path = os.path.join(base, name)
        data = open(path, "rb").read()
        if b"\x00" not in data and b"\r\n" in data:
            open(path, "wb").write(data.replace(b"\r\n", b"\n"))
PY
```

产物：

```text
/opt/lyflow/artifacts/lyprobe/lyprobe
/opt/lyflow/artifacts/lyprobe/liblyprobe-1.0.0.so
/opt/lyflow/artifacts/lyprobe/plugins/servicePlugin.so
/opt/lyflow/artifacts/lyprobe/{SHA256SUMS,BUILD-INFO,lyprobe-help.txt}
```

运行环境需要 `libpcap` 和 `libpcre.so.3`（Ubuntu: `apt install libpcre3`）。

## 部署布局（10.1.18.241）

```text
/opt/ly-flow-platform/lyprobe/
  lyprobe
  liblyprobe-1.0.0.so
  plugins/servicePlugin.so
  fp-patterns/{service,device,os,midware,threat}.json
/opt/lyflow/bin/lyflow-netflow-collector
/etc/lyflow/netflow.env          # 0600，sensor-241 的 agent_id / agent_key
```

lyprobe 输出 NetFlow v9 到 `127.0.0.1:9995`；collector 把 flow 写入
`/api/v1/agent/traffic-event`（`sessions:semantic` + `flows:raw`），威胁命中额外写
`/api/v1/agent/component-alert`。

## systemd

`lyflow-netflow-collector.service`：

```ini
[Service]
EnvironmentFile=/etc/lyflow/netflow.env
Environment=NETFLOW_LISTEN=127.0.0.1:9995
ExecStart=/opt/lyflow/bin/lyflow-netflow-collector
Restart=always
```

`lyflow-lyprobe.service`：

```ini
[Service]
WorkingDirectory=/opt/ly-flow-platform/lyprobe
ExecStart=/opt/ly-flow-platform/lyprobe/lyprobe -i ens192 -d 15 -t 60 \
  -n 127.0.0.1:9995 \
  -T "%%IPV4_SRC_ADDR %%IPV4_DST_ADDR %%PROTOCOL %%L4_SRC_PORT %%L4_DST_PORT %%IN_PKTS %%IN_BYTES %%FIRST_SWITCHED %%LAST_SWITCHED %%SRV_TYPE %%SRV_NAME %%SRV_VERS %%THREAT_TYPE %%THREAT_NAME" \
  -e 0 -w 65536
Restart=always
```

注意：

- systemd 会把 `%` 当 specifier，模板里的 `%IPV4_...` 必须写成 `%%IPV4_...`。
- 不要在 unit 里用带空格的 `-f` BPF 过滤；systemd 会拆参数，实测会漏抓。
  需要过滤时使用单独的 `.pcap-filter` 文件或正确转义的 argv。
- `-d 15 -t 60` 让会话尽快导出；默认生命周期较长，流量页会延迟数分钟。

## 规则

`fp-patterns/` 来自上游，包含：

- 44 条 protocol
- 15 条 device
- 16 条 os
- 25 条 midware
- 16 条 threat

`servicePlugin` 支持热加载：原子替换 `fp-patterns/*.json` 后约 2 秒生效，
日志出现 `Hot-reloaded N patterns`。

威胁规则要求明文 HTTP 且规则里的 SQLi 正则依赖真实空格（`union select`）。
URL 编码的 `%20` 可能因为 `\b` 边界不匹配，这不是探针故障。

## 验证

```bash
systemctl is-active lyflow-lyprobe lyflow-netflow-collector
journalctl -u lyflow-lyprobe -n 20 --no-pager
journalctl -u lyflow-netflow-collector -n 20 --no-pager | grep 'threat matched'
```

平台侧：

```sql
SELECT observed_at, dst_port,
       raw_event->'content'->>'threat_type',
       raw_event->'content'->>'threat_name'
FROM traffic_sessions
WHERE dst_port = 18101
ORDER BY observed_at DESC;
```

实测 SQLi 明文请求得到 `SQL / CRUD`，flow 的双向记录都带威胁字段。

## 回滚

```bash
systemctl disable --now lyflow-lyprobe lyflow-netflow-collector
```

不影响 Suricata、RASP、YARA。删除 `/opt/ly-flow-platform/lyprobe` 和
`/opt/lyflow/bin/lyflow-netflow-collector` 即可完全移除。
