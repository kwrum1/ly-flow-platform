# 发布来源与交付边界

## 当前正式方式

正式交付由 GitHub Actions 的“正式服务端发布”工作流生成。发布不是旧的 Gitea 签名验收包，也不要求包外 trust root。当前固定产物为 AMD64、ARM64 两个服务端一键部署包。

## 来源

- 源码来自触发运行的 GitHub `main` 提交。
- Go 与 npm 依赖从公开模块仓库重新解析，不复用跨运行缓存。
- PostgreSQL、Redis、ClickHouse、Nginx 和 Suricata 镜像在对应 CPU 架构 runner 上重新拉取。
- 五个公开规则源在每次构建时重新下载、记录来源摘要、转换、去重和编译。
- 产品 Docker 镜像使用 `--pull --no-cache` 构建。

## 包内校验

工作流在发布前执行以下必要校验：

1. 五个规则源均生成有效清单，编译规则摘要可复算。
2. 所有镜像架构与目标服务端架构一致。
3. 服务端归档可通过 gzip 完整性检查。
4. 包内 `images/architecture` 与文件名架构一致。
5. 包内存在本次规则快照和一键安装脚本。

正式 Release 不附带 `.sha256` 文件。下载链路依赖 GitHub HTTPS；安装后依靠 Docker 镜像可读性、容器健康检查和应用健康接口判断部署结果。当前发布不宣称可复现字节级构建，也不宣称具备离线签名供应链认证。

## 安装边界

目标机必须是 Linux AMD64 或 ARM64，并预先安装 Docker Engine 与 Compose Plugin。安装器拒绝主机与包架构不一致，导入包内镜像并启动 `/opt/ly-flow-platform` 正式栈。

首次登录固定为 `admin/password`，必须立即改密。PostgreSQL、Redis、ClickHouse、JWT 和内部控制口令由安装器写入本机 `.env`，不应提交到源码仓库或复制到文档。

## 历史脚本

`scripts/build-offline-release.sh`、`scripts/install-offline.sh` 和相关签名验收脚本仍保留用于历史 QA 与回归，不是当前正式 Release 的操作入口。历史设计记录位于 `docs/archive/`，不得据此判断当前发布内容。
