# 流影平台开发流程

> 版本: v1.0.0
> 更新日期: 2026-05-09
> 状态: 已确定

---

## 一、开发环境概览

```
┌─────────────────────────────────────────────────────────────┐
│                    Gitea CI/CD 平台                       │
│  http://10.1.18.100:10000                               │
│  仓库: ly-flow-platform/ly-flow-platform                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    开发机器 (本地)                          │
│  代码目录: /root/ly-flow-platform                         │
│  Git Remote: http://10.1.18.100:10000/                   │
│            ly-flow-platform/ly-flow-platform.git           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  CI/CD Runner                             │
│  Runner: local-docker-runner (online)                      │
│  自动构建 Docker 镜像                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、开发流程 (标准)

### 流程图

```
1. 创建/修改代码
       │
       ▼
2. git add + git commit
       │
       ▼
3. git push (推送到 Gitea)
       │
       ▼
4. CI 自动触发
       │
       ├── 构建 5 个 Docker 镜像
       │   - ly-flow/probe
       │   - ly-flow/dpi-engine
       │   - ly-flow/server
       │   - ly-flow/frontend
       │   - ly-flow/agent
       │
       ▼
5. 测试验证
       │
       ▼
6. 完成
```

### 详细步骤

#### Step 1: 克隆仓库 (首次)

```bash
cd /root/ly-flow-platform
git clone http://10.1.18.100:10000/ly-flow-platform/ly-flow-platform.git .
git remote -v
```

#### Step 2: 创建开发分支

```bash
# 创建新功能分支
git checkout -b feature/your-feature-name

# 或创建 bug 修复分支
git checkout -b fix/issue-description
```

#### Step 3: 修改代码

```bash
# 编辑代码...
# 例如: vim server/api/handlers/handlers.go
```

#### Step 4: 提交代码

```bash
git add .
git commit -m "feat: 添加新功能描述

- 详细说明 1
- 详细说明 2

Closes #issue-number"
```

#### Step 5: 推送到 Gitea

```bash
git push -u origin feature/your-feature-name
```

#### Step 6: 在 Gitea 创建 Pull Request

1. 访问: http://10.1.18.100:10000/ly-flow-platform/ly-flow-platform
2. 点击 "Compare and create pull request"
3. 填写 PR 标题和描述
4. 点击 "Create Pull Request"

#### Step 7: CI 自动构建

Gitea 会自动：
1. 检测到 PR 创建
2. 触发 CI 工作流
3. 构建所有 Docker 镜像
4. 报告构建结果

#### Step 8: 合并 PR

```bash
# 在 Gitea Web UI 点击 Merge
# 或使用命令行
gh pr merge PR_NUMBER --squash
```

---

## 三、Git 提交规范

### 提交类型

| 类型 | 说明 |
|------|------|
| feat | 新功能 |
| fix | Bug 修复 |
| docs | 文档更新 |
| style | 代码格式 |
| refactor | 重构 |
| test | 测试 |
| ci | CI/CD |
| build | 构建系统 |

### 提交示例

```bash
# 新功能
git commit -m "feat: 添加用户认证模块

- 添加 JWT token 验证
- 实现登录/登出接口"

# Bug 修复
git commit -m "fix: 修复 API 超时问题

- 增加 Redis 连接池大小
- 添加重试机制"

# CI/CD
git commit -m "ci: 优化 Docker 构建缓存"
```

---

## 四、CI/CD 工作流

### 工作流文件

位置: `.gitea/workflows/docker-build.yml`

### 触发条件

- Push 到 `main` 分支
- 创建 Pull Request

### 构建步骤

1. **安装依赖**: git, curl, wget, docker
2. **克隆仓库**: 从 Gitea 拉取最新代码
3. **构建镜像**:
   - `probe` - 流量采集探针
   - `dpi-engine` - DPI 分析引擎
   - `server` - API 服务
   - `frontend` - Vue3 前端
   - `agent` - 终端 Agent

### 查看构建状态

```bash
# API 查看
curl -s -H "Authorization: token TOKEN" \
  "http://10.1.18.100:10000/api/v1/repos/ly-flow-platform/ly-flow-platform/actions/runs"

# Web UI
http://10.1.18.100:10000/ly-flow-platform/ly-flow-platform/actions
```

---

## 五、日常开发命令

### 常用 Git 命令

```bash
# 查看状态
git status

# 查看远程
git remote -v

# 拉取最新
git pull origin main

# 切换分支
git checkout main
git checkout feature/xxx

# 查看提交历史
git log --oneline -10

# 查看差异
git diff

# 撤销修改
git checkout -- file.txt
git reset HEAD file.txt
```

### 本地构建命令

```bash
cd /root/ly-flow-platform

# 构建所有镜像
make build-all

# 或使用脚本
./build.sh all

# 查看镜像
docker images | grep ly-flow

# 启动本地服务
docker compose up -d

# 查看服务状态
docker compose ps
```

---

## 六、遇到问题

### CI 构建失败

1. 查看构建日志: http://10.1.18.100:10000/ly-flow-platform/ly-flow-platform/actions
2. 本地复现构建命令
3. 修复代码并重新提交

### Runner 离线

```bash
# 检查 Runner 状态
curl -s -H "Authorization: token TOKEN" \
  "http://10.1.18.100:10000/api/v1/repos/ly-flow-platform/ly-flow-platform/actions/runners"

# 重启 Runner
pkill act_runner
cd /tmp && ./act_runner daemon &
```

### 推送被拒绝

```bash
# 确认分支
git branch

# 确保不是 main 分支
git checkout -b feature/xxx

# 重新推送
git push -u origin feature/xxx
```

---

## 七、联系方式

- **Gitea**: http://10.1.18.100:10000
- **仓库**: http://10.1.18.100:10000/ly-flow-platform/ly-flow-platform
- **API Token**: `b934e5b1facb989e128266b8fc7408da02b710dd`
