# Docker 镜像源记录

目标：在 Docker Hub 直连不稳定时，为 LyFlow 构建和测试提供可复现的镜像来源。
生产发布仍必须使用校验过的离线镜像包，不应依赖公共镜像站的长期可用性。

## 脚本

```bash
bash deploy/compose/pull-image.sh library/postgres:16-alpine
```

会依次尝试：

1. `DOCKER_MIRROR`
2. `ALIYUN_MIRROR`（阿里云 ACR 个人加速地址，需要账号）
3. `docker.1ms.run`（毫秒镜像）
4. `docker.m.daocloud.io`
5. `docker.1panel.live`
6. `docker.xuanyuan.me`
7. `docker.1panel.top`
8. `dockerpull.org`
9. `registry.dockermirror.com`

## 2026-10-19 实测

| 源 | 结果 |
|---|---|
| `docker.1ms.run` | `library/rust:1.85-bookworm` 拉取成功；PostgreSQL/ClickHouse 大镜像多次停在 layer 下载，超时 |
| `docker.m.daocloud.io` | 测试时未返回可用 manifest |
| `docker.1panel.live` | 部分 blob 访问被拒绝/限流 |
| `docker.xuanyuan.me` | `/v2/` 请求超时 |
| `docker.1panel.top` | Cloudflare 429/限流 |
| `dockerpull.org` | `/v2/` 请求超时 |
| `registry.cn-hangzhou.aliyuncs.com` | 匿名访问需要认证；公共镜像加速器需使用账号生成的 ACR 地址 |
| `registry.dockermirror.com` | 超时 |
| `docker.anyhub.us.kg` / `dockerhub.icu` / `docker.chenby.cn` / `docker.rainbond.cc` / `docker.kejilion.pro` | 超时、DNS 失败或 525 |

## 本次 G5 的处理

- Rust builder：从 `docker.1ms.run/library/rust:1.85-bookworm` 拉取成功。
- PostgreSQL：使用编译机已有的 `safeline-postgres:15.18`（标准 PostgreSQL entrypoint）
  标签为 `ly-flow/postgres:15.18`，save/load 到测试机。
- Redis：用 Ubuntu 24.04 + `redis-server` 构建 `ly-flow/redis:7.2`。
- ClickHouse：测试机已有原生 26.9.21.9，G5 使用 host-network + 原生进程。
- 其他 LyFlow 服务：本地构建 `ly-flow/server`、`security-engine`、`frontend`（Pingora）、
  `suricata`、`lyprobe`、`capturedoctor`、`rulecompiler`。

## 生产要求

- 设定 `ALIYUN_MIRROR` 或 `DOCKER_MIRROR` 后重试 `pull-image.sh`。
- 发布包必须带 `docker save` 的离线镜像 tar、镜像 digest 清单和校验和。
- `lean.yml` 的镜像 tag 不得依赖 `latest` 或未固定 digest。
- 本记录不把镜像站的可用性当作 LyFlow 的安全边界。
