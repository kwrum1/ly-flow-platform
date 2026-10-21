# Incident 闭环与规则抑制

- 日期：2026-10-21
- 生产环境：`https://10.1.18.198/`
- 目标：让分析师能在 Incident 页面明确判断告警性质、关闭告警并留下审计记录，同时减少重复误报。

## 1. Incident 闭环

- 新增“闭环结论”面板：
  - 继续观察（不关闭）
  - 确认误报并关闭
  - 授权/预期操作并关闭
  - 确认已处置并关闭
- 关闭必须填写原因；后端按生命周期合法路径完成 `triaged → processing → resolved → closed`，每一步写入不可变审计记录。
- 关闭后列表显示“已关闭”，详情显示最近闭环原因；可重新打开后再次闭环。
- 修复重复闭环时幂等键冲突导致状态不前进的问题，幂等键包含 Incident 版本。

## 2. 规则抑制

- Incident 闭环时可选择抑制：
  - 同规则（当前证据）
  - 同来源 IP
  - 同资产/受害实体
- 抑制时长 7/30/90 天，写入 `xdr-response-policy` 的 `suppressions`，过期自动失效。
- 威胁详情页新增“标记误报并抑制 30 天”，用于没有 Incident 的单点流量告警。
- 当前验证：`GPL NETBIOS SMB NT Trans NT CREATE oversized Security Descriptor attempt`（`et-open-2103018`）已抑制 30 天；抑制后流量告警查询不再返回该规则。
- 策略持久化到 `.sisyphus/runtime/xdr-response-policy.json`，使用 `response_data` 卷，容器重建后保留。

## 3. 本轮生产处置

- 已将当前 `test8-final3` 的 SSH 自己登录/ sudo 操作按“授权操作”关闭。
- 已将旧 `test8-fresh` 重复链按历史测试数据关闭。
- 生产 Incident 当前均为 `closed`，并保留完整审计。

## 4. UI 调整

- 平台设置三张卡片改为等高布局，控件底部对齐，避免卡片高度参差。
- Incident 右侧增加闭环面板、规则快捷抑制按钮和最近闭环原因。
- 威胁详情抽屉增加规则误报抑制入口。

## 5. 验证

- Go：`server/cmd` 全量测试通过。
- 前端：117 项测试、typecheck、build 通过。
- Playwright：Incident 页面闭环面板、规则快捷按钮可见；UI 提交闭环成功并显示“已关闭”；无 console/page error。
- 生产 API：闭环审计条目、规则抑制、流量告警过滤均已验证。
