<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">ASSET OPERATIONS</p>
        <h1>资产运维</h1>
        <p>统一管理资产、Agent 身份与采集能力。状态来自真实心跳与能力上报，未上报的能力显示为未知，不按已启用处理。</p>
      </div>
      <div class="v-head-actions">
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '刷新中…' : '刷新' }}</button>
        <button class="v-btn primary" type="button" @click="tab = 'install'">安装 Agent</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <section class="v-grid c4">
      <article class="v-stat">
        <span class="v-stat-label"><i />资产总数</span>
        <strong class="v-stat-value">{{ ready.assets ? assets.length : '—' }}</strong>
        <span class="v-stat-note">{{ ready.assets ? `已纳管 ${assets.length} 台主机` : '正在读取资产' }}</span>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />在线 Agent</span>
        <strong class="v-stat-value" :class="onlineAgents ? 'success' : 'unknown'">{{ ready.agents ? onlineAgents : '—' }}</strong>
        <span class="v-stat-note">{{ ready.agents ? `共 ${agents.length} 台，离线 ${offlineAgents} 台` : '正在读取心跳' }}</span>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />采集能力覆盖</span>
        <strong class="v-stat-value">{{ ready.agents ? capabilitySummary.total : '—' }}</strong>
        <span class="v-stat-note">{{ ready.agents ? capabilitySummary.text : '正在聚合能力' }}</span>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />心跳延迟</span>
        <strong class="v-stat-value" :class="heartbeatTone">{{ heartbeatText }}</strong>
        <span class="v-stat-note">最近一台在线 Agent 的上报时间</span>
      </article>
    </section>

    <div class="v-tabs" role="tablist">
      <button v-for="t in tabs" :key="t.key" type="button" class="v-tab" :class="{ active: tab === t.key }" @click="tab = t.key">{{ t.label }}</button>
    </div>

    <!-- inventory -->
    <article v-if="tab === 'inventory'" class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">资产清单</div>
        <span class="v-panel-meta">{{ filteredAssets.length }} / {{ assets.length }} 台</span>
      </div>
      <div class="v-panel-body">
        <div class="v-toolbar">
          <label class="v-field grow"><span>检索</span><input v-model.trim="query" class="v-input" placeholder="主机名 / IP / Agent ID"></label>
          <label class="v-field"><span>状态</span>
            <select v-model="statusFilter" class="v-select">
              <option value="">全部</option><option value="online">在线</option><option value="offline">离线</option>
            </select>
          </label>
          <label class="v-field"><span>能力</span>
            <select v-model="capabilityFilter" class="v-select">
              <option value="">全部</option>
              <option v-for="c in capabilityDefs" :key="c.key" :value="c.key">{{ c.label }}</option>
            </select>
          </label>
        </div>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead>
            <tr><th>资产</th><th>网络</th><th>系统</th><th>Agent</th><th>状态</th><th>采集能力</th><th>最后心跳</th><th class="actions">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="asset in filteredAssets" :key="asset.key" class="clickable" @click="select(asset)">
              <td>
                <template v-if="editingKey === asset.key">
                  <input v-model.trim="editingName" class="v-input inline-name" @click.stop @keyup.enter="commitRename(asset)" @keyup.esc="cancelRename" @blur="commitRename(asset)" />
                </template>
                <template v-else>
                  <b class="editable-name" @click.stop="beginRename(asset)">{{ asset.name }}</b>
                </template>
                <small>{{ asset.agentId || '未绑定 Agent' }}</small>
              </td>
              <td><span class="v-mono">{{ asset.ip || '-' }}</span><small>{{ asset.hostname || '-' }}</small></td>
              <td>{{ asset.os || '-' }}</td>
              <td>{{ asset.agentVersion || '-' }}</td>
              <td><span class="v-state" :data-state="asset.state">{{ asset.stateLabel }}</span></td>
              <td>
                <span v-for="c in asset.capabilities" :key="c.key" class="v-badge" :class="c.enabled ? 'info' : 'unknown'">{{ c.label }}</span>
                <span v-if="!asset.capabilities.length" class="v-dim">未上报</span>
              </td>
              <td class="num">{{ asset.lastSeenText }}</td>
              <td class="actions" @click.stop>
                <button class="v-btn sm" type="button" @click="select(asset)">详情</button>
                <button class="v-btn sm danger" type="button" :disabled="asset.state === 'online' || deleting" :title="asset.state === 'online' ? '在线服务器不能删除' : '删除离线服务器'" @click="remove(asset)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="!filteredAssets.length" class="v-table-empty"><strong>{{ loading ? '正在读取资产' : '没有匹配的资产' }}</strong>{{ loading ? '' : '调整筛选条件，或在安装页接入新的 Agent。' }}</div>
      </div>
    </article>

    <!-- capability matrix -->
    <article v-else-if="tab === 'capabilities'" class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">采集能力矩阵</div>
        <span class="v-panel-meta">{{ agents.length }} 台服务器 · 仅流量可手动开关</span>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead>
            <tr><th>服务器</th><th v-for="c in capabilityDefs" :key="c.key">{{ c.label }}</th><th>最近心跳</th></tr>
          </thead>
          <tbody>
            <tr v-for="agent in agents" :key="agent.agent_id">
              <td><b>{{ agent.display_name || agent.hostname || agent.agent_id }}</b><small>{{ agent.agent_id }} · {{ agent.ip || '-' }}</small></td>
              <td v-for="c in capabilityDefs" :key="c.key">
                <button v-if="c.toggleable" class="v-toggle" :class="{ on: capabilityOf(agent, c.key) }" type="button" :disabled="toggling === `${agent.agent_id}:${c.key}`" @click="toggleCapability(agent, c)">
                  {{ capabilityOf(agent, c.key) ? '已启用' : '未启用' }}
                </button>
                <span v-else class="v-state" :data-state="capabilityOf(agent, c.key) ? 'healthy' : 'unknown'">{{ capabilityOf(agent, c.key) ? '已上报' : '未上报' }}</span>
              </td>
              <td class="num">{{ shortTime(agent.last_seen || agent.last_heartbeat) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="capabilityNotice" class="v-notice">{{ capabilityNotice }}</div>
        <div v-if="!agents.length" class="v-table-empty">暂无服务器心跳</div>
      </div>
    </article>

    <!-- defense -->
    <article v-else-if="tab === 'defense'" class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">防御能力</div>
        <span class="v-panel-meta">
          {{ policy?.enforcing ? '阻断已生效' : policy?.allow_production_block ? '可演练后提升' : '阻断提升未开启' }}
        </span>
      </div>

      <div class="v-panel-body">
        <div v-if="!policy" class="v-notice">正在读取 RASP 策略生命周期…</div>
        <template v-else>
          <section class="v-grid c4">
            <article class="v-stat">
              <span class="v-stat-label"><i />策略状态</span>
              <strong class="v-stat-value">{{ policyStateLabel }}</strong>
              <span class="v-stat-note">{{ policy.active ? `版本 ${policy.active.version} · ${policy.active.mode}` : '没有活动策略' }}</span>
            </article>
            <article class="v-stat">
              <span class="v-stat-label"><i />执行模式</span>
              <strong class="v-stat-value" :class="policy.enforcing ? 'success' : 'unknown'">{{ policy.enforcing ? '阻断' : '监控 / 演练' }}</strong>
              <span class="v-stat-note">{{ policy.enforcing ? '命中即拦截' : '只上报，不拦截业务调用' }}</span>
            </article>
            <article class="v-stat">
              <span class="v-stat-label"><i />演练命中</span>
              <strong class="v-stat-value">{{ policy.dry_run?.would_block ?? 0 }}</strong>
              <span class="v-stat-note">当前版本 would-block 次数</span>
            </article>
            <article class="v-stat">
              <span class="v-stat-label"><i />已阻断</span>
              <strong class="v-stat-value" :class="(policy.dry_run?.blocked ?? 0) > 0 ? 'warning' : 'unknown'">{{ policy.dry_run?.blocked ?? 0 }}</strong>
              <span class="v-stat-note">当前版本真实阻断次数</span>
            </article>
          </section>

          <div class="v-notice" v-if="!policy.allow_production_block">
            服务端未开启阻断提升：需要显式设置 <code>LYFLOW_RASP_ALLOW_BLOCK=true</code>。未开启时只能做监控与演练。
          </div>

          <div v-if="policyError" class="v-error">{{ policyError }}</div>
        </template>
      </div>

      <!-- current defense session -->
      <section class="defense-section">
        <div class="v-panel-head">
          <div class="v-panel-title">当前防护会话</div>
          <span class="v-panel-meta">
            {{ activeSession ? `${sessionModeLabel(activeSession)} · 剩余 ${remainingText}` : '监控中 · 未开启防护会话' }}
          </span>
        </div>
        <div class="v-panel-body">
          <div v-if="defenseError" class="v-error">{{ defenseError }}</div>
          <div v-if="!defense" class="v-notice">正在读取防护会话…</div>
          <template v-else>
            <div v-if="activeSession" class="session-card">
              <div class="session-main">
                <span class="v-state" :data-state="activeSession.status === 'active' && activeSession.mode === 'block' ? 'degraded' : 'healthy'">{{ sessionStateLabel(activeSession) }}</span>
                <b>{{ activeSession.scope === 'tag' ? `标签 ${activeSession.scope_value}` : activeSession.scope_value }}</b>
                <small>
                  {{ activeSession.source === 'schedule' ? '自动值守' : '手动' }} ·
                  {{ activeSession.reason || '未填写原因' }} · 发起人 {{ activeSession.created_by }} ·
                  策略版本 {{ activeSession.policy_version || '-' }}
                </small>
              </div>
              <div class="session-time">
                <strong>{{ remainingText }}</strong>
                <small>{{ shortTime(activeSession.ends_at) }} 结束</small>
              </div>
              <button class="v-btn sm danger" type="button" :disabled="defenseBusy !== ''" @click="stopSession(activeSession)">
                {{ defenseBusy === 'stop' ? '停止中…' : '停止并回监控' }}
              </button>
            </div>
            <div v-else class="v-notice">
              当前为监控模式。创建防护会话或启用自动值守规则后，RASP 才会进入演练/阻断；流量只检测不阻断，YARA 只检测。
            </div>
            <div v-if="activeSession?.failure_reason" class="v-notice">失败原因：{{ activeSession.failure_reason }}</div>
            <div v-if="defense?.last_failed" class="v-notice">
              最近一次防护失败：{{ shortTime(defense.last_failed.updated_at) }} · {{ defense.last_failed.failure_reason || '原因未记录' }}（已自动回监控）
            </div>
            <div v-if="activeSession?.status === 'dry_run'" class="v-notice">
              演练中：{{ promotionText }} 后自动提升为阻断；期间出现真实拦截或 Agent 未确认会自动回监控。
            </div>

            <div class="v-toolbar defense-form">
              <label class="v-field"><span>范围</span>
                <select v-model="sessionForm.scope" class="v-select">
                  <option value="agent">单 Agent</option>
                  <option value="tag">Tag 分组</option>
                </select>
              </label>
              <label v-if="sessionForm.scope === 'agent'" class="v-field grow"><span>Agent</span>
                <select v-model="sessionForm.scope_value" class="v-select">
                  <option value="">选择 Agent</option>
                  <option v-for="agent in agents" :key="agent.agent_id" :value="agent.agent_id">
                    {{ agent.display_name || agent.hostname || agent.agent_id }}
                  </option>
                </select>
              </label>
              <label v-else class="v-field grow"><span>Tag</span>
                <input v-model.trim="sessionForm.scope_value" class="v-input" list="defense-tags" placeholder="输入或选择标签">
              </label>
              <label class="v-field"><span>模式</span>
                <select v-model="sessionForm.mode" class="v-select">
                  <option value="block">阻断</option>
                  <option value="monitor">监控</option>
                </select>
              </label>
              <label class="v-field"><span>时长（分钟）</span>
                <input v-model.number="sessionForm.duration_minutes" class="v-input" type="number" min="1" max="10080">
              </label>
              <label class="v-field grow"><span>原因</span>
                <input v-model.trim="sessionForm.reason" class="v-input" placeholder="例如：发布窗口临时阻断">
              </label>
              <button class="v-btn primary" type="button" :disabled="defenseBusy !== ''" @click="createSessionFromForm">
                {{ defenseBusy === 'create' ? '创建中…' : '创建防护会话' }}
              </button>
            </div>
          </template>
        </div>
      </section>

      <!-- automatic watch schedules -->
      <section class="defense-section">
        <div class="v-panel-head">
          <div class="v-panel-title">自动值守规则</div>
          <span class="v-panel-meta">按 tag 分组 · 每天时段 · 窗口前 5 分钟演练</span>
        </div>
        <div class="v-panel-body">
          <div class="v-toolbar defense-form">
            <label class="v-field"><span>Tag</span>
              <input v-model.trim="scheduleForm.tag" class="v-input" list="defense-tags" placeholder="prod">
            </label>
            <label class="v-field"><span>每天开始</span>
              <input v-model="scheduleForm.start_time" class="v-input" type="time">
            </label>
            <label class="v-field"><span>每天结束</span>
              <input v-model="scheduleForm.end_time" class="v-input" type="time">
            </label>
            <label class="v-field"><span>优先级</span>
              <input v-model.number="scheduleForm.priority" class="v-input" type="number" min="-100" max="100">
            </label>
            <label class="v-field grow"><span>原因</span>
              <input v-model.trim="scheduleForm.reason" class="v-input" placeholder="例如：每日业务高峰值守">
            </label>
            <button class="v-btn primary" type="button" :disabled="defenseBusy !== ''" @click="createSchedule">
              {{ defenseBusy === 'schedule' ? '保存中…' : '新增规则' }}
            </button>
          </div>
          <datalist id="defense-tags">
            <option v-for="tag in defenseTags" :key="tag.tag" :value="tag.tag">{{ tag.agents }} 台</option>
          </datalist>
        </div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>Tag</th><th>每日时段</th><th>优先级</th><th>演练</th><th>状态</th><th>下次开始</th><th class="actions">操作</th></tr></thead>
            <tbody>
              <tr v-for="schedule in defenseSchedules" :key="schedule.id">
                <td><b>{{ schedule.tag }}</b><small>{{ schedule.reason || '未填写原因' }}</small></td>
                <td class="num">{{ schedule.start_time }} – {{ schedule.end_time }}</td>
                <td class="num">{{ schedule.priority }}</td>
                <td class="num">{{ formatDuration(schedule.dry_run_seconds) }}</td>
                <td>
                  <span class="v-badge" :class="schedule.enabled ? 'info' : 'unknown'">{{ schedule.enabled ? '启用' : '停用' }}</span>
                  <span v-if="schedule.active_now" class="v-badge medium">{{ schedule.phase === 'dry_run' ? '演练中' : '窗口内' }}</span>
                </td>
                <td class="num">{{ schedule.next_start ? shortTime(schedule.next_start) : '-' }}</td>
                <td class="actions">
                  <button class="v-btn sm" type="button" :disabled="defenseBusy !== ''" @click="toggleSchedule(schedule)">
                    {{ schedule.enabled ? '停用' : '启用' }}
                  </button>
                  <button class="v-btn sm danger" type="button" :disabled="defenseBusy !== ''" @click="removeSchedule(schedule)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="!defenseSchedules.length" class="v-table-empty">
            <strong>还没有自动值守规则</strong>新增后调度器每 30 秒评估一次窗口。
          </div>
        </div>
      </section>

      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>服务器</th><th>当前模式</th><th>RASP</th><th class="actions">操作</th></tr></thead>
          <tbody>
            <tr v-if="!agents.length"><td colspan="4" class="v-table-empty"><strong>没有服务器在线</strong>安装并上报后才会出现在这里。</td></tr>
            <tr v-for="agent in agents" :key="`defense-${agent.agent_id}`">
              <td><b>{{ agent.display_name || agent.hostname || agent.agent_id }}</b><small>{{ agent.ip || '-' }}</small></td>
              <td><span class="v-state" :data-state="policy?.enforcing ? 'degraded' : 'healthy'">{{ policy?.enforcing ? '阻断' : '监控' }}</span></td>
              <td>
                <span class="v-state" :data-state="capabilityOf(agent, 'rasp') ? 'healthy' : 'unknown'">
                  {{ capabilityOf(agent, 'rasp') ? '已开启' : '未开启' }}
                </span>
              </td>
              <td class="actions">
                <button v-if="!policy?.enforcing" class="v-btn sm" type="button" :disabled="policyBusy !== ''" @click="switchDefense(agent, 'block')">
                  {{ policyBusy === 'block' ? '下发中…' : '切换为阻断' }}
                </button>
                <button v-else class="v-btn sm" type="button" :disabled="policyBusy !== ''" @click="switchDefense(agent, 'monitor')">
                  {{ policyBusy === 'monitor' ? '切换中…' : '切换为监控' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="v-panel-body">
        <ul class="notes">
          <li>切换为阻断后，后端创建防护会话并下发签名策略：先演练收集 would-block，确认后自动提升为真实阻断。</li>
          <li>切换为监控会立即回滚到监控版本，不再拦截业务调用；自动值守窗口结束后同样回监控。</li>
          <li>任何失败（Agent 未确认、演练异常、策略提升失败）都会 fail-safe 回监控并写入审计。</li>
        </ul>
      </div>
    </article>

    <!-- install -->
    <div v-else class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">安装 Agent</div><span class="v-panel-meta">Linux AMD64 / ARM64</span></div>
        <div class="v-panel-body install-body">
          <p class="install-note">在目标主机以 root 执行。安装脚本由平台动态生成，包含当前服务端地址与一次性注册令牌。</p>
          <pre class="cmd">{{ installCommand || '正在生成安装命令…' }}</pre>
          <div class="install-actions">
            <button class="v-btn" type="button" @click="copy(installCommand)">复制命令</button>
            <button class="v-btn" type="button" :disabled="loadingInstall" @click="loadInstall">{{ loadingInstall ? '生成中…' : '重新生成' }}</button>
          </div>
        </div>
      </article>
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">卸载 Agent</div><span class="v-panel-meta">保留或清理本地数据</span></div>
        <div class="v-panel-body install-body">
          <p class="install-note">卸载会停止采集并移除服务单元。请先确认该资产不再参与检测，避免出现采集盲区。</p>
          <pre class="cmd">{{ uninstallCommand || '正在生成卸载命令…' }}</pre>
          <div class="install-actions">
            <button class="v-btn" type="button" @click="copy(uninstallCommand)">复制命令</button>
          </div>
        </div>
      </article>
    </div>

    <!-- detail -->
    <div v-if="selected" class="v-scrim" @click.self="selected = null">
      <aside class="v-drawer">
        <div class="v-drawer-head">
          <div>
            <p class="v-eyebrow">ASSET DETAIL</p>
            <div class="v-panel-title">{{ selected.name }}</div>
          </div>
          <button class="v-btn ghost" type="button" @click="selected = null">关闭</button>
        </div>
        <div class="v-drawer-body detail-body">
          <section>
            <h3>主机信息</h3>
            <dl class="v-kv">
              <dt>服务器名称</dt><dd>{{ selected.name }}</dd>
              <dt>IP 地址</dt><dd class="v-mono">{{ selected.ip || '-' }}</dd>
              <dt>操作系统</dt><dd>{{ selected.os || '-' }}</dd>
              <dt>服务器 ID</dt><dd class="v-mono">{{ shortId(selected.agentId) }}</dd>
              <dt>最近心跳</dt><dd>{{ selected.lastSeenText }}</dd>
              <dt>防御标签</dt>
              <dd>
                <div class="tag-editor">
                  <input v-model="tagDraft" class="v-input" type="text" placeholder="prod, web（逗号分隔）" :disabled="savingTags" />
                  <button class="v-btn ghost" type="button" :disabled="savingTags || !selected.agentId" @click="saveAgentTags">
                    {{ savingTags ? '保存中' : '保存标签' }}
                  </button>
                </div>
                <small class="tag-hint">自动值守按 tag 匹配服务器。{{ tagNotice }}</small>
              </dd>
            </dl>
          </section>

          <section>
            <h3>运行信息</h3>
            <div class="ops-metrics">
              <div class="ops-metric">
                <span>CPU</span>
                <div class="ops-bar"><i :style="{ width: barWidth(selected.cpuUsage) }" /></div>
                <b>{{ formatPercent(selected.cpuUsage) }}</b>
                <small>{{ selected.cpu || '-' }}</small>
              </div>
              <div class="ops-metric">
                <span>内存</span>
                <div class="ops-bar"><i :style="{ width: barWidth(selected.memoryUsage) }" /></div>
                <b>{{ formatPercent(selected.memoryUsage) }}</b>
                <small>{{ selected.memory || '-' }}</small>
              </div>
              <div class="ops-metric">
                <span>磁盘</span>
                <div class="ops-bar"><i :style="{ width: barWidth(selected.diskUsage) }" /></div>
                <b>{{ formatPercent(selected.diskUsage) }}</b>
                <small>{{ selected.disk || '-' }}</small>
              </div>
            </div>
            <dl class="v-kv">
              <dt>负载</dt><dd>{{ selected.load || '未上报' }}</dd>
              <dt>运行时长</dt><dd>{{ selected.uptime || '未上报' }}</dd>
            </dl>
          </section>
        </div>
        </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { assetAgentClient, raspPolicyClient } from '../../api/domain'
import api from '../../api/index'
import { formatChinaDateTime } from '../../shared/time'

// Defense sessions and automatic watch schedules are owned by the defense page.
// Keeping the client here avoids touching the shared domain client; the main
// agent can move it to frontend/src/api/domain.js without changing call sites.
const defenseClient = Object.freeze({
  status: () => api.get('/defense/status'),
  sessions: (params = {}) => api.get('/defense/sessions', { params }),
  createSession: (payload) => api.post('/defense/sessions', payload),
  stopSession: (id, payload) => api.post(`/defense/sessions/${encodeURIComponent(id)}/stop`, payload),
  schedules: () => api.get('/defense/schedules'),
  createSchedule: (payload) => api.post('/defense/schedules', payload),
  updateSchedule: (id, payload) => api.put(`/defense/schedules/${encodeURIComponent(id)}`, payload),
  deleteSchedule: (id, payload) => api.delete(`/defense/schedules/${encodeURIComponent(id)}`, { data: payload }),
  audit: (params = {}) => api.get('/defense/audit', { params }),
})

const tabs = [
  { key: 'inventory', label: '资产清单' },
  { key: 'capabilities', label: '采集能力' },
  { key: 'defense', label: '防御能力' },
  { key: 'install', label: '安装与卸载' },
]

const capabilityDefs = [
  { key: 'traffic', label: '流量', field: 'traffic', toggleable: true },
  { key: 'runtime', label: '运行时', field: 'runtime', toggleable: false },
  { key: 'rasp', label: 'RASP', field: 'rasp', toggleable: false },
  { key: 'yara', label: 'YARA', field: 'yara', toggleable: false },
  { key: 'log_audit', label: '日志审计', field: 'log_audit', toggleable: false },
]

const tab = ref('inventory')
const loading = ref(false)
const error = ref('')
const assets = ref([])
const agents = ref([])
const engines = ref([])
const ready = ref({ assets: false, agents: false, engines: false })
const query = ref('')
const statusFilter = ref('')
const capabilityFilter = ref('')
const selected = ref(null)
const renameValue = ref('')
const tagDraft = ref('')
const savingTags = ref(false)
const tagNotice = ref('')
const renaming = ref(false)
const editingKey = ref('')
const editingName = ref('')
const deleting = ref(false)
const toggling = ref('')
const capabilityNotice = ref('')
const installCommand = ref('')
const uninstallCommand = ref('')
const loadingInstall = ref(false)
const now = ref(Date.now())
const policy = ref(null)
const policyError = ref('')
const policyBusy = ref('')
const canaryForm = ref({
  owner: 'security-owner',
  required_acks: 1,
  replay_min_samples: 1000,
  replay_max_false_positive_rate: 0.01,
  max_blocks_per_minute: 60,
  expires_in_seconds: 86400,
  rollback_window_seconds: 7200,
})
const canaryResult = ref({ succeeded: true, sample_count: 1, false_positive_rate: 0, failure_reason: '' })
const defense = ref(null)
const defenseError = ref('')
const defenseBusy = ref('')
const sessionForm = ref({
  scope: 'agent',
  scope_value: '',
  mode: 'block',
  duration_minutes: 480,
  reason: '手动切换为阻断',
})
const scheduleForm = ref({
  tag: '',
  start_time: '09:00',
  end_time: '18:00',
  priority: 10,
  reason: '每日值守',
})
let clockTimer = null

const onlineAgents = computed(() => agents.value.filter((a) => String(a.status || '').toLowerCase() === 'online').length)
const offlineAgents = computed(() => Math.max(0, agents.value.length - onlineAgents.value))

const capabilitySummary = computed(() => {
  const counts = capabilityDefs.map((c) => ({ label: c.label, count: agents.value.filter((a) => capabilityOf(a, c.key)).length }))
  const enabled = counts.filter((c) => c.count > 0)
  return {
    total: enabled.length,
    text: enabled.length ? enabled.map((c) => `${c.label} ${c.count}`).join(' · ') : '尚未上报采集能力',
  }
})

const heartbeatText = computed(() => {
  const stamps = agents.value.map((a) => new Date(a.last_seen || a.last_heartbeat).getTime()).filter(Number.isFinite)
  if (!stamps.length) return '—'
  const diff = Math.max(0, Math.round((now.value - Math.max(...stamps)) / 1000))
  if (diff < 60) return `${diff}s`
  if (diff < 3600) return `${Math.round(diff / 60)}m`
  return `${Math.round(diff / 3600)}h`
})

const heartbeatTone = computed(() => {
  const stamps = agents.value.map((a) => new Date(a.last_seen || a.last_heartbeat).getTime()).filter(Number.isFinite)
  if (!stamps.length) return 'unknown'
  const diff = (now.value - Math.max(...stamps)) / 1000
  return diff < 120 ? 'success' : diff < 600 ? 'warning' : 'danger'
})

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? response ?? {}
}

function capabilityOf(agent, key) {
  const caps = agent.capabilities || agent.metadata?.capabilities || {}
  if (key === 'traffic') return Boolean(caps.traffic_collector?.enabled ?? caps.traffic_sensor?.enabled ?? caps.traffic?.enabled ?? false)
  if (key === 'runtime') return Boolean(caps.runtime_sensor?.enabled ?? caps.runtime?.enabled ?? false)
  if (key === 'rasp') return Boolean(caps.rasp_probe_manager?.enabled ?? caps.rasp?.enabled ?? false)
  if (key === 'yara') return Boolean(caps.yara_scanner?.enabled ?? caps.engine_supervisors?.yara?.installed ?? caps.engine_supervisors?.yara?.running ?? caps.yara?.enabled ?? false)
  if (key === 'log_audit') return Boolean(caps.log_collector?.enabled ?? caps.log_audit?.enabled ?? false)
  return false
}

const merged = computed(() => {
  const agentById = new Map(agents.value.map((a) => [String(a.agent_id), a]))
  const agentByHost = new Map(agents.value.map((a) => [String(a.hostname || '').toLowerCase(), a]))
  const rows = assets.value.map((asset) => {
    const agent = agentById.get(String(asset.agent_id || asset.host_id)) || agentByHost.get(String(asset.hostname || '').toLowerCase()) || null
    return buildRow(asset, agent)
  })
  // agents without an asset row still need to appear; they are the operator's responsibility.
  for (const agent of agents.value) {
    const exists = rows.some((r) => r.agentId === agent.agent_id)
    if (!exists) rows.push(buildRow({}, agent))
  }
  return rows
})

function buildRow(asset, agent) {
  const status = String(agent?.status || asset.status || '').toLowerCase()
  const online = status === 'online'
  return {
    key: asset.host_id || asset.agent_id || agent?.agent_id || asset.hostname || asset.ip || Math.random().toString(36),
    hostId: asset.host_id || asset.id || agent?.host_id || '',
    agentId: agent?.agent_id || asset.agent_id || '',
    name: agent?.display_name || asset.display_name || agent?.hostname || asset.hostname || asset.ip || agent?.agent_id || '未命名资产',
    hostname: agent?.hostname || asset.hostname || '',
    ip: agent?.ip || asset.ip || '',
    os: agent?.os || asset.os || '',
    agentVersion: agent?.version || agent?.agent_version || '',
    state: agent ? (online ? 'online' : 'failed') : 'unknown',
    stateLabel: agent ? (online ? '在线' : '离线') : '无 Agent',
    capabilities: agent ? capabilityDefs.filter((c) => capabilityOf(agent, c.key)).map((c) => ({ key: c.key, label: c.label, enabled: true })) : [],
    lastSeenText: shortTime(agent?.last_seen || agent?.last_heartbeat || asset.last_seen),
    cpu: asset.cpu || '',
    memory: asset.memory_mb ? `${asset.memory_mb} MB` : '',
    disk: asset.disk_gb ? `${asset.disk_gb} GB` : '',
    cpuUsage: asset.cpu_usage_percent,
    memoryUsage: asset.memory_usage_percent,
    diskUsage: asset.disk_usage_percent,
    load: asset.load_avg_1 !== undefined && asset.load_avg_1 !== null
      ? [asset.load_avg_1, asset.load_avg_5, asset.load_avg_15].filter((v) => v !== undefined && v !== null).map((v) => Number(v).toFixed(2)).join(' / ')
      : '',
    uptime: formatUptime(asset.uptime_seconds),
    engines: engines.value.filter((e) => e.agent_id === (agent?.agent_id || '')).map((e) => ({
      engine: e.engine,
      version: e.version,
      rulePack: e.rule_pack_version,
      label: e.running ? '运行中' : '未运行',
      state: e.running ? 'online' : 'degraded',
    })),
    rawAgent: agent,
  }
}

const filteredAssets = computed(() => {
  const q = query.value.toLowerCase()
  return merged.value.filter((row) => {
    if (statusFilter.value === 'online' && row.state !== 'online') return false
    if (statusFilter.value === 'offline' && row.state === 'online') return false
    if (capabilityFilter.value && !row.capabilities.some((c) => c.key === capabilityFilter.value)) return false
    if (!q) return true
    return [row.name, row.hostname, row.ip, row.agentId].some((v) => String(v || '').toLowerCase().includes(q))
  })
})

const policyStateLabel = computed(() => {
  const state = policy.value?.active?.state || policy.value?.latest?.state || ''
  return ({ draft: '草稿', canary: '演练中', active: '已生效', expired: '已过期', rolled_back: '已回滚', superseded: '已替代' })[state] || '未知'
})

const activeSession = computed(() => defense.value?.session || null)
const defenseSchedules = computed(() => defense.value?.schedules || [])
const defenseTags = computed(() => defense.value?.tags || [])

const sessionRemaining = computed(() => {
  const ends = activeSession.value?.ends_at ? new Date(activeSession.value.ends_at).getTime() : NaN
  if (!Number.isFinite(ends)) return 0
  return Math.max(0, Math.round((ends - now.value) / 1000))
})
const remainingText = computed(() => formatDuration(sessionRemaining.value))

const promotionRemaining = computed(() => {
  const target = activeSession.value?.dry_run_until ? new Date(activeSession.value.dry_run_until).getTime() : NaN
  if (!Number.isFinite(target)) return 0
  return Math.max(0, Math.round((target - now.value) / 1000))
})
const promotionText = computed(() => formatDuration(promotionRemaining.value))

function sessionModeLabel(session) {
  return session?.mode === 'block' ? '阻断' : '监控'
}

function sessionStateLabel(session) {
  const labels = { dry_run: '演练中', active: session?.mode === 'block' ? '阻断中' : '监控中', stopped: '已停止', expired: '已到期', failed: '已失败' }
  return labels[session?.status] || session?.status || '未知'
}

function formatDuration(value) {
  const seconds = Math.max(0, Math.round(Number(value) || 0))
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const rest = seconds % 60
  if (hours > 0) return `${hours} 小时 ${minutes} 分`
  if (minutes > 0) return `${minutes} 分 ${rest} 秒`
  return `${rest} 秒`
}

function agentPolicyState(agent) {
  const probe = agent?.capabilities?.rasp_probe_manager || {}
  if (!policy.value) return '未知'
  if (policy.value.enforcing && probe.enforcing) return '阻断已生效'
  if (policy.value.latest?.state === 'canary') return probe.status === 'dry_run' ? '演练上报中' : '等待 Agent ACK'
  if (policy.value.enforcing) return '等待 Agent 应用'
  return '监控'
}

async function refreshPolicy() {
  try {
    const res = await raspPolicyClient.status()
    policy.value = unwrap(res)
  } catch (e) {
    policyError.value = e?.response?.data?.message || e?.message || '读取 RASP 策略失败'
  }
}

async function refreshDefense() {
  try {
    const res = await defenseClient.status()
    defense.value = unwrap(res)
    defenseError.value = ''
  } catch (e) {
    defenseError.value = e?.response?.data?.message || e?.message || '读取防护会话失败'
  }
}

async function defenseAction(name, action) {
  defenseBusy.value = name
  defenseError.value = ''
  try {
    await action()
    await Promise.all([refreshDefense(), refreshPolicy()])
  } catch (e) {
    defenseError.value = e?.response?.data?.message || e?.message || '防护操作失败'
  } finally {
    defenseBusy.value = ''
  }
}

function createSessionFromForm() {
  const form = sessionForm.value
  const scopeValue = String(form.scope_value || '').trim()
  if (!scopeValue) {
    defenseError.value = form.scope === 'agent' ? '请选择要防护的 Agent' : '请填写 Tag'
    return
  }
  const minutes = Number(form.duration_minutes)
  const duration = Math.round((Number.isFinite(minutes) && minutes > 0 ? minutes : 480) * 60)
  return defenseAction('create', () => defenseClient.createSession({
    scope: form.scope,
    scope_value: scopeValue,
    mode: form.mode,
    duration_seconds: Math.max(60, duration),
    ...(form.mode === 'block' ? { dry_run_seconds: 0 } : {}),
    reason: form.reason || '手动创建防护会话',
  }))
}

function stopSession(session) {
  if (!session?.id) return
  return defenseAction('stop', () => defenseClient.stopSession(session.id, { reason: '手动停止防护会话' }))
}

function createSchedule() {
  const form = scheduleForm.value
  if (!String(form.tag || '').trim()) {
    defenseError.value = '请填写自动值守的 Tag'
    return
  }
  return defenseAction('schedule', () => defenseClient.createSchedule({
    tag: String(form.tag).trim(),
    start_time: form.start_time,
    end_time: form.end_time,
    priority: Number(form.priority) || 0,
    reason: form.reason || '每日值守',
  }))
}

function toggleSchedule(schedule) {
  return defenseAction('schedule', () => defenseClient.updateSchedule(schedule.id, { enabled: !schedule.enabled }))
}

function removeSchedule(schedule) {
  return defenseAction('schedule', () => defenseClient.deleteSchedule(schedule.id, { reason: '删除自动值守规则' }))
}

async function policyAction(name, action) {
  policyBusy.value = name
  policyError.value = ''
  try {
    await action()
    await refreshPolicy()
  } catch (e) {
    policyError.value = e?.response?.data?.message || e?.message || '操作失败'
  } finally {
    policyBusy.value = ''
  }
}

async function switchDefense(agent, mode) {
  policyBusy.value = mode
  policyError.value = ''
  defenseError.value = ''
  try {
    if (mode === 'monitor') {
      const live = activeSession.value
      if (live && live.mode === 'block') {
        await defenseClient.stopSession(live.id, { reason: '手动切换为监控' })
      } else {
        await defenseClient.createSession({
          scope: 'agent',
          scope_value: agent.agent_id,
          mode: 'monitor',
          duration_seconds: 8 * 3600,
          reason: '手动切换为监控',
        })
      }
    } else {
      await defenseClient.createSession({
        scope: 'agent',
        scope_value: agent.agent_id,
        mode: 'block',
        duration_seconds: 8 * 3600,
        dry_run_seconds: 0,
        reason: '手动切换为阻断',
      })
    }
    await Promise.all([refreshPolicy(), refreshDefense()])
  } catch (e) {
    policyError.value = e?.response?.data?.message || e?.message || '防御模式切换失败'
  } finally {
    policyBusy.value = ''
  }
}

function startCanary() {
  return policyAction('canary', () => raspPolicyClient.startCanary(canaryForm.value))
}

function completeCanary() {
  const version = policy.value?.latest?.version
  if (!version) return
  return policyAction('complete', () => raspPolicyClient.complete(version, canaryResult.value))
}

function promoteCanary() {
  const version = policy.value?.latest?.version
  if (!version) return
  return policyAction('promote', () => raspPolicyClient.promote(version))
}

function rollbackPolicy(version) {
  if (!version) return
  return policyAction('rollback', () => raspPolicyClient.rollback(version))
}

function emergencyStop() {
  return policyAction('stop', () => raspPolicyClient.emergencyStop())
}

function shortTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '-'
  return formatChinaDateTime(d)
}

function select(row) {
  selected.value = row
  renameValue.value = row.name
  tagDraft.value = ''
  tagNotice.value = ''
  if (row.agentId) {
    loadAgentTags(row.agentId)
  }
}

async function loadAgentTags(agentId) {
  try {
    const res = await assetAgentClient.agentTags(agentId)
    const tags = (res.data?.data || res.data || {}).tags || []
    if (selected.value?.agentId === agentId) {
      tagDraft.value = tags.join(', ')
    }
  } catch {
    tagNotice.value = '标签读取失败'
  }
}

async function saveAgentTags() {
  const row = selected.value
  if (!row?.agentId) return
  savingTags.value = true
  tagNotice.value = ''
  try {
    const tags = tagDraft.value.split(',').map((item) => item.trim()).filter(Boolean)
    const res = await assetAgentClient.setAgentTags(row.agentId, tags)
    const saved = (res.data?.data || res.data || {}).tags || []
    tagDraft.value = saved.join(', ')
    tagNotice.value = `已保存 ${saved.length} 个标签`
    await load()
  } catch (e) {
    tagNotice.value = e?.response?.data?.message || '标签保存失败'
  } finally {
    savingTags.value = false
  }
}

async function load() {
  loading.value = true
  error.value = ''
  now.value = Date.now()
  const [a, g, e, p, d] = await Promise.allSettled([
    assetAgentClient.assets({ limit: 500 }),
    assetAgentClient.agents({ limit: 500 }),
    assetAgentClient.engineHealth(),
    raspPolicyClient.status(),
    defenseClient.status(),
  ])
  if (a.status === 'fulfilled') { assets.value = unwrap(a.value).items || []; ready.value.assets = true }
  if (g.status === 'fulfilled') { agents.value = unwrap(g.value).items || []; ready.value.agents = true }
  if (e.status === 'fulfilled') { engines.value = unwrap(e.value).items || []; ready.value.engines = true }
  if (p.status === 'fulfilled') { policy.value = unwrap(p.value) }
  if (d.status === 'fulfilled') {
    defense.value = unwrap(d.value)
    defenseError.value = ''
  } else {
    defenseError.value = d.reason?.response?.data?.message || d.reason?.message || '读取防护会话失败'
  }

  stateOfCall([a, g, e])
  loading.value = false
}

function stateOfCall(results) {
  const failed = results.filter((r) => r.status === 'rejected').length
  if (failed === results.length) error.value = '资产接口全部不可达，页面不显示任何"在线"结论。'
  else if (failed) error.value = `${failed} 个接口读取失败，对应字段显示为未知。`
}

async function loadInstall() {
  loadingInstall.value = true
  try {
    const res = await assetAgentClient.installScript()
    installCommand.value = typeof res === 'string' ? res : (res?.data || res?.script || '')
  } catch {
    installCommand.value = ''
  }
  try {
    const res = await assetAgentClient.uninstallScript?.()
    uninstallCommand.value = typeof res === 'string' ? res : (res?.data || '')
  } catch {
    uninstallCommand.value = ''
  }
  loadingInstall.value = false
}

async function copy(text) {
  if (!text) return
  try { await navigator.clipboard.writeText(text) } catch { /* clipboard unavailable */ }
}

async function toggleCapability(agent, cap) {
  const key = `${agent.agent_id}:${cap.key}`
  const next = !capabilityOf(agent, cap.key)
  toggling.value = key
  error.value = ''
  capabilityNotice.value = ''
  try {
    if (cap.key === 'traffic') {
      agent.capabilities = { ...(agent.capabilities || {}), traffic_collector: { ...(agent.capabilities?.traffic_collector || {}), enabled: next } }
    }
    await assetAgentClient.toggleAgentCapability(agent.agent_id, cap.field, next)
    capabilityNotice.value = `${agent.display_name || agent.hostname || agent.agent_id} 的流量采集已${next ? '开启' : '关闭'}，等待 Agent 下次拉取配置（约 30–60 秒）`
    window.setTimeout(() => { load() }, 40000)
  } catch (e) {
    const detail = e?.response?.data?.message || e?.message || ''
    error.value = `能力开关写回失败，未改变本地状态。${detail ? `原因：${detail}` : ''}`
  } finally {
    toggling.value = ''
  }
}

function shortId(value) {
  const text = String(value || '')
  return text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text || '-'
}

function formatPercent(value) {
  const number = Number(value)
  return Number.isFinite(number) ? `${number.toFixed(1)}%` : '-'
}

function barWidth(value) {
  const number = Number(value)
  if (!Number.isFinite(number)) return '0%'
  return `${Math.max(2, Math.min(100, number))}%`
}

function formatUptime(value) {
  const seconds = Number(value)
  if (!Number.isFinite(seconds) || seconds <= 0) return ''
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return days > 0 ? `${days} 天 ${hours} 小时` : hours > 0 ? `${hours} 小时 ${minutes} 分` : `${minutes} 分`
}

function beginRename(row) {
  editingKey.value = row.key
  editingName.value = row.name
}

function cancelRename() {
  editingKey.value = ''
  editingName.value = ''
}

async function commitRename(row) {
  if (editingKey.value !== row.key) return
  const name = editingName.value.trim()
  editingKey.value = ''
  if (!row.agentId || !name || name === row.name) return
  try {
    await assetAgentClient.renameAgent(row.agentId, name)
    await load()
  } catch {
    error.value = '重命名失败。'
  }
}

async function rename(row) {
  if (!row.agentId) return
  renaming.value = true
  try {
    await assetAgentClient.renameAgent(row.agentId, renameValue.value)
    await load()
    selected.value = null
  } catch {
    error.value = '重命名失败。'
  } finally {
    renaming.value = false
  }
}

async function remove(row) {
  if (!row.agentId) return
  deleting.value = true
  try {
    await assetAgentClient.deleteAgent(row.agentId)
    await load()
    selected.value = null
  } catch {
    error.value = '删除失败：只能删除离线 Agent。'
  } finally {
    deleting.value = false
  }
}

onMounted(() => {
  load()
  loadInstall()
  clockTimer = window.setInterval(() => {
    now.value = Date.now()
  }, 1000)
})

onUnmounted(() => {
  if (clockTimer) {
    window.clearInterval(clockTimer)
    clockTimer = null
  }
})
</script>

<style scoped>
.clickable { cursor: pointer; }
.install-body { display: grid; gap: 12px; }
.install-note { color: var(--v-ink-3); font-size: 12px; line-height: 1.7; }
.cmd { margin: 0; padding: 14px; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-3); color: var(--v-ink-2); font-family: var(--v-mono); font-size: 11.5px; line-height: 1.7; white-space: pre-wrap; overflow-wrap: anywhere; }
.install-actions { display: flex; gap: 8px; }
.tag-editor { display: flex; gap: 8px; align-items: center; }
.tag-editor .v-input { flex: 1; min-width: 130px; }
.tag-hint { display: block; margin-top: 4px; color: var(--v-ink-3); font-size: 11px; }

.v-toggle { height: 26px; padding: 0 10px; border: 1px solid var(--v-line-2); border-radius: 999px; background: var(--v-surface); color: var(--v-ink-3); font: inherit; font-size: 11px; cursor: pointer; }
.v-toggle.on { border-color: var(--v-accent-line); background: var(--v-accent-soft); color: var(--v-accent); font-weight: 600; }
.v-toggle:disabled { opacity: 0.5; cursor: wait; }

.detail-body { display: grid; gap: 22px; }
.detail-body h3 { margin-bottom: 10px; color: var(--v-ink); font-size: 12.5px; font-weight: 620; }
.cap-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.cap-cell { display: grid; gap: 2px; padding: 10px 12px; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-2); }
.cap-cell b { color: var(--v-ink-2); font-size: 12px; font-weight: 600; }
.cap-cell span { color: var(--v-ink-3); font-size: 10.5px; }
.cap-cell.on { border-color: var(--v-accent-line); background: var(--v-accent-soft); }
.cap-cell.on b { color: var(--v-accent); }
.detail-actions { display: flex; flex-wrap: wrap; gap: 8px; }

@media (max-width: 720px) {
  .cap-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
.v-drawer { width: min(38vw, 520px); max-width: 520px; }
.ops-metrics { display: grid; gap: 10px; margin-bottom: 12px; }
.ops-metric { display: grid; grid-template-columns: 38px minmax(0, 1fr) 54px 72px; align-items: center; gap: 8px; }
.ops-metric span { color: var(--v-ink-3); font-size: 11px; }
.ops-bar { height: 8px; overflow: hidden; border-radius: 999px; background: var(--v-surface-3); }
.ops-bar i { display: block; height: 100%; border-radius: 999px; background: var(--v-accent); }
.ops-metric b { text-align: right; color: var(--v-ink); font-size: 11.5px; }
.ops-metric small { text-align: right; color: var(--v-ink-3); font-size: 10.5px; }
.advanced { margin-top: 12px; }
.advanced summary { cursor: pointer; color: var(--v-ink-2); font-size: 12px; font-weight: 600; }

.defense-section { border-top: 1px solid var(--v-line); }
.defense-form { margin-bottom: 4px; }
.defense-form .v-field { min-width: 132px; }
.session-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 16px;
  margin-bottom: 12px;
  padding: 12px 14px;
  border: 1px solid var(--v-line);
  border-radius: var(--v-radius-sm);
  background: var(--v-surface-2);
}
.session-main { display: grid; gap: 4px; min-width: 0; }
.session-main b { color: var(--v-ink); font-size: 13px; }
.session-main small { color: var(--v-ink-3); font-size: 11px; overflow-wrap: anywhere; }
.session-time { text-align: right; }
.session-time strong { display: block; color: var(--v-ink); font-size: 16px; font-weight: 650; font-variant-numeric: tabular-nums; }
.session-time small { color: var(--v-ink-3); font-size: 10.5px; }

@media (max-width: 720px) {
  .session-card { grid-template-columns: 1fr; }
  .session-time { text-align: left; }
}
</style>
