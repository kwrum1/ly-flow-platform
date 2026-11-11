# Suricata 部署：方向语义与资产范围

> 关联决策：`docs/dev/DECISIONS.md` D-019

## 为什么不能手改 profile

`HOME_NET` 定义"这个传感器保护哪些资产"，`EXTERNAL_NET` 由 `!$HOME_NET` 推导。
手改这两个值极易造成方向语义塌陷：

| HOME_NET | 后果（7 天真实告警实测） |
|---|---|
| `any` | 入站规则命中内网↔内网、内网→外网；**90.4% 告警是方向误报** |
| `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | 真正的攻击者被判定为"自己人"，只剩 **8.4%** 告警 |
| `10.1.18.0/24`（服务器区） | 保留 **49.9%** |
| `10.1.18.0/24` + 公网 NAT | 保留 **90.1%** |

因此 profile 只允许由渲染器生成。

## 渲染

```bash
SURICATA_HOME_NET="[10.1.18.0/24,113.194.3.11/32]" \
SURICATA_INTERFACE=mirror0 \
SURICATA_THREADS=4 \
SURICATA_BPF_FILTER="not ( host 10.1.18.125)" \
  deploy/suricata/render-profile.sh --output /opt/ly-flow-platform/suricata/lyflow-suricata-profile.yaml
```

- `SURICATA_HOME_NET` **没有默认值**，必须显式给。给 `any` 会直接被拒绝。
- 渲染器原地重写目标文件（保留 inode）。这一点是必需的：profile 是单文件 bind mount，
  用 `mv` 替换会让容器永远读到旧 inode。
- 校验现有部署文件：`deploy/suricata/render-profile.sh --check <path>`。

## 生效

单文件 bind mount 在容器启动时绑定 inode。原地重写后内容会立即更新，
但**已启动的 Suricata 进程仍使用旧配置**，需要：

```bash
docker restart ly-flow-platform-ly-suricata-sensor-1
```

`et-open-refresh.sh` 每天同步 ET Open 前会先 `--check`，方向语义不合法就拒绝刷新。
这是为了避免每日同步把修复冲掉。

## 资产范围变更流程

1. 改 `/opt/ly-flow-platform/.env` 的 `SURICATA_HOME_NET`
2. 用渲染器重新生成 profile
3. `render-profile.sh --check` 确认
4. `suricata -T` 确认规则可加载
5. 重启 sensor

## 验收测试

```bash
# 渲染器单测（离线）
bash scripts/qa/render-profile_test.sh

# 需要 Suricata 镜像
SURICATA_IMAGE=ly-flow/suricata-profile:v67 bash scripts/qa/suricata-direction_test.sh
SURICATA_IMAGE=ly-flow/suricata-profile:v67 bash scripts/qa/suricata-asset-scope_test.sh
```

`suricata-asset-scope_test.sh` 用本环境真实告警里的攻击载荷（sid 2049400，
`/chat/imController/showOrDownByurl.do?dbPath=../../../../../etc/passwd`）构造四条会话：

| 会话 | 目标 | 期望 |
|---|---|---|
| 扫描源 → 受保护反代 `10.1.18.253` | 受保护资产 | **告警** |
| 扫描源 → 受保护公网 NAT `113.194.3.11` | 受保护资产 | **告警** |
| 扫描源 → 非受保护内网 `10.1.2.52` | 不在保护范围 | 不告警 |
| 扫描源 → 非受保护内网 `10.20.215.161` | 不在保护范围 | 不告警 |

`HOME_NET=any` 时四条全部告警；`HOME_NET=RFC1918` 时一条都不告警。
