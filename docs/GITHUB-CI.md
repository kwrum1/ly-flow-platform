# GitHub 正式服务端发布

## 仓库分工

- GitHub：公开维护、正式构建和服务端发布。
- Gitea：内部源码镜像与故障恢复，不默认自动构建。

## 触发方式

`.github/workflows/release.yml` 每月 1 日和 16 日 `02:00 UTC` 自动执行，也支持在 GitHub Actions 页面手动触发。普通 push 不触发固件编译，仓库不再配置独立“平台验证”工作流。

## 构建内容

每次运行都使用新的 GitHub 托管 runner，不使用 Go、npm、Docker 或规则的跨运行缓存。规则阶段从公网重新获取 ET Open、OISF Traffic ID、Snort Community、Stamus Lateral 和 Positive Technologies AttackDetection，记录上游版本与摘要，转换并编译为本次构建规则快照。

AMD64 与 ARM64 使用各自原生 runner。每个服务端包包含正式 Compose、前端、核心服务、安全引擎、本机镜像采集、Suricata、PostgreSQL、Redis、ClickHouse、双架构 Linux Agent、规则和一键安装脚本。

## 发布文件

正式 Release 标签固定为 `latest-server`，只包含：

- `lyflow-server-amd64.tar.gz`
- `lyflow-server-arm64.tar.gz`

不发布源码压缩包以外的自定义附件，也不发布 `.sha256` 边车文件。工作流仍在 runner 内校验规则摘要、gzip 完整性、包内架构和安装脚本，防止产生不可安装的包。

## 历史清理

双架构构建成功后，发布任务先删除已经完成的旧 Actions 运行记录，再删除旧 Release 及其标签，最后创建新的 `latest-server`。这样构建失败时仍保留上一版正式包，成功时仓库只保留最新正式发布。

## 权限

工作流只使用 GitHub 自动签发的 `GITHUB_TOKEN`，权限限定为 `actions: write` 和 `contents: write`。仓库不需要保存长期 GitHub PAT、Gitea 密码或服务器 SSH 凭据。

## CI（拉取请求 / 主分支）

`.github/workflows/ci.yml` 在 push 和 pull request 时执行：

- Go：pkg、server 核心包、agent、security-engine；
- server/cmd 定向测试：事件契约、规则转换保真、默认规则、EVE 入库、保留策略；
- 前端：typecheck、单测、lint、生产构建；
- Python RASP：request hook、bridge 过期、策略模式、阻断、SQL 和一致性测试；
- secrets / private / license 检查。

CI 不依赖外部数据库或真实传感器；涉及数据库和真机的验收仍在测试环境执行。
