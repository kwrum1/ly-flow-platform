# Suricata / ET Open integration

- `lyflow-suricata-profile.yaml`：生产 profile（含 ET Open 需要的变量与 `suricata.rules` + `lyflow-suricata.rules`）。
- `lyflow-suricata-test.yaml`：测试 profile（`af-packet` 绑定 `ens160`，用于测试 VM）。
- `lyflow-suricata.rules`：LyFlow 自定义规则。
- `rules/suricata/et-open.manifest.json`：ET Open 源元数据。

## 测试 VM 验证

```bash
# 1. 安装 Suricata / suricata-update
apt-get install -y suricata suricata-update

# 2. 拉取 ET Open
suricata-update update-sources
suricata-update --no-reload

# 3. 复制 profile/规则
install -m 0644 deploy/suricata/lyflow-suricata-test.yaml /etc/suricata/
install -m 0644 deploy/suricata/lyflow-suricata.rules /var/lib/suricata/rules/

# 4. 校验 + 回放
suricata -T -c /etc/suricata/lyflow-suricata-test.yaml
bash scripts/dev/suricata-replay.sh
```

2026-10-19 在 `lyflow-test` 实测：

- Suricata 7.0.3 / suricata-update 1.3.0
- ET Open + 自定义规则共 53,162 条成功加载
- PCAP 回放触发 `LYFLOW INERT pinned profile verification`（sid 9000001）
- EVE 输出包含 `alert`、`dns`、`flow`

## 生产注意

- ET Open 规则引用 `HTTP_SERVERS` 等变量；profile 已补齐。
- 若禁用 `smb`/`krb5` 等 app-layer，必须同时排除对应协议规则，否则 `suricata -T` 会失败。
- 生产环境建议先 `suricata -T`，再灰度重载。
