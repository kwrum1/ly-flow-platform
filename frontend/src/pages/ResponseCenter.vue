<template>
  <section class="sx-page response-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">RESPONSE ORCHESTRATION</p>
        <h2 class="sx-title">响应处置</h2>
        <p class="sx-subtitle">所有动作都从真实审批队列进入；L2/L3 需要第二名管理员审批，执行结果由 Agent 回写，可回滚动作在这里直接回滚。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">刷新</button>
      </div>
    </header>

    <section class="response-stats">
      <article class="sx-metric"><span class="sx-metric-label"><i />全部动作</span><strong class="sx-metric-value">{{ formatNumber(actions.length) }}</strong><span class="sx-metric-note">最近 100 条记录</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />待审批</span><strong class="sx-metric-value warning">{{ formatNumber(pendingCount) }}</strong><span class="sx-metric-note">需要不同管理员审批</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />已执行</span><strong class="sx-metric-value success">{{ formatNumber(executedCount) }}</strong><span class="sx-metric-note">Agent 已回写结果</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />失败 / 回滚</span><strong class="sx-metric-value danger">{{ formatNumber(failedCount) }}</strong><span class="sx-metric-note">需要人工核查</span></article>
    </section>

    <section class="sx-panel automation-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">定时自动化处置</div>
        <span class="sx-badge" :class="automation.active ? 'low' : 'muted'">{{ automation.active ? '当前窗口生效中' : '当前未自动执行' }}</span>
      </div>
      <div class="sx-panel-body automation-body">
        <label class="automation-toggle">
          <input v-model="automationForm.enabled" type="checkbox" />
          <span><b>启用自动处置窗口</b><small>窗口内仅 L2 动作自动执行；L3 始终需要第二名管理员审批</small></span>
        </label>
        <label><span>开始小时</span><select v-model.number="automationForm.window_start_hour" class="sx-select"><option v-for="hour in hourOptions" :key="`s-${hour}`" :value="hour">{{ String(hour).padStart(2, '0') }}:00</option></select></label>
        <label><span>结束小时</span><select v-model.number="automationForm.window_end_hour" class="sx-select"><option v-for="hour in hourOptions" :key="`e-${hour}`" :value="hour">{{ String(hour).padStart(2, '0') }}:00</option></select></label>
        <label><span>审批 TTL（分钟）</span><input v-model.number="automationForm.approval_ttl_minutes" class="sx-input" type="number" min="1" max="1440" /></label>
        <div class="automation-actions">
          <span class="sx-muted">时区：Asia/Shanghai · {{ automation.scope || 'L2 actions only' }}</span>
          <button class="sx-btn primary" type="button" :disabled="automationSaving" @click="saveAutomation">{{ automationSaving ? '保存中…' : '保存自动化策略' }}</button>
        </div>
        <div v-if="automationMessage" class="response-message" :class="automationMessageType">{{ automationMessage }}</div>
      </div>
    </section>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="response-create sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">发起响应动作</div>
        <span class="sx-panel-meta">提交后进入审批队列</span>
      </div>
      <div class="sx-panel-body create-grid">
        <label class="agent-field"><span>Agent</span>
          <select v-model="form.agent_id" class="sx-select">
            <option value="" disabled>{{ agents.length ? '选择 Agent' : '暂无已注册 Agent' }}</option>
            <option v-for="agent in agents" :key="agent.agent_id" :value="agent.agent_id">
              {{ agent.display_name || agent.hostname || agent.agent_id }} · {{ agent.ip || '无 IP' }} · {{ agent.status === 'online' ? '在线' : '离线' }}
            </option>
          </select>
        </label>
        <label><span>动作</span>
          <select v-model="form.action" class="sx-select">
            <option v-for="item in actionOptions" :key="item.value" :value="item.value">{{ item.label }}</option>
          </select>
        </label>
        <label v-if="requiresTarget" class="wide"><span>目标</span><input v-model.trim="form.target" class="sx-input" :placeholder="targetPlaceholder" /></label>
        <label class="wide description-field"><span>说明</span><textarea v-model.trim="form.reason" class="sx-input reason-input" rows="2" placeholder="处置依据 / 变更单号（可选）" /></label>
        <div class="create-actions">
          <span class="sx-muted">L2 在自动化窗口内可直接执行；L3 始终进入审批。</span>
          <span v-if="message" :class="['response-message', messageType]">{{ message }}</span>
          <button class="sx-btn primary" type="button" :disabled="creating || !canCreate" @click="createAction">{{ creating ? '提交中…' : '提交处置' }}</button>
        </div>
      </div>
    </section>

    <form class="sx-filter" @submit.prevent="load">
      <label><span>状态</span>
        <select v-model="statusFilter" class="sx-select">
          <option value="">全部</option>
          <option value="pending_approval">待审批</option>
          <option value="approved">已批准</option>
          <option value="executed">已执行</option>
          <option value="failed">失败</option>
          <option value="rolled_back">已回滚</option>
        </select>
      </label>
      <label><span>风险</span>
        <select v-model="riskFilter" class="sx-select">
          <option value="">全部</option><option value="L1">L1</option><option value="L2">L2</option><option value="L3">L3</option>
        </select>
      </label>
      <label class="wide"><span>关键字</span><input v-model.trim="query" class="sx-input" placeholder="动作 / 目标 / Incident / 发起人" /></label>
      <button type="submit" class="sx-btn primary" :disabled="loading">筛选</button>
    </form>

    <section class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">动作历史</div>
        <span class="sx-panel-meta">{{ filteredActions.length }} 条</span>
      </div>
      <div class="sx-table-wrap sx-scroll">
        <table class="sx-table response-table">
          <thead><tr><th>动作</th><th>目标</th><th>风险</th><th>状态</th><th>Incident</th><th>发起 / 审批</th><th>时间</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !actions.length"><td colspan="8" class="sx-empty">正在读取响应动作…</td></tr>
            <tr v-else-if="!filteredActions.length"><td colspan="8" class="sx-empty"><div><strong>没有匹配的响应动作</strong>调整筛选条件或发起新动作。</div></td></tr>
            <tr v-for="action in filteredActions" :key="action.id">
              <td><b>{{ actionLabel(action.action) }}</b><small class="sx-mono">{{ action.id }}</small></td>
              <td class="sx-mono">{{ action.target || '-' }}</td>
              <td><span class="sx-badge" :class="riskTone(action.risk)">{{ action.risk || '-' }}</span></td>
              <td><span class="sx-badge" :class="statusTone(action.status)">{{ statusLabel(action.status) }}</span></td>
              <td>{{ action.incident_id || '-' }}</td>
              <td><b>{{ action.requested_by || '-' }}</b><small>{{ action.approved_by ? `审批 ${action.approved_by}` : '等待审批' }}</small></td>
              <td><b>{{ formatTime(action.created_at) }}</b><small>{{ action.completed_at ? formatTime(action.completed_at) : '' }}</small></td>
              <td>
                <div class="action-buttons">
                  <button v-if="action.status === 'pending_approval'" class="sx-btn" type="button" :disabled="updating === action.id" @click="approve(action)">审批</button>
                  <button v-if="canRollback(action)" class="sx-btn ghost" type="button" :disabled="updating === action.id" @click="rollback(action)">回滚</button>
                </div>
                <span v-if="action.error" class="action-error">{{ action.error }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { assetAgentClient, responseClient } from '../api/domain'

const loading = ref(false)
const creating = ref(false)
const updating = ref('')
const error = ref('')
const message = ref('')
const messageType = ref('success')
const actions = ref([])
const agents = ref([])
const automation = ref({})
const automationSaving = ref(false)
const automationMessage = ref('')
const automationMessageType = ref('success')
const statusFilter = ref('')
const riskFilter = ref('')
const query = ref('')
const form = reactive({ agent_id: '', action: 'isolate_host', target: '', reason: '' })
const automationForm = reactive({ enabled: false, window_start_hour: 0, window_end_hour: 23, approval_ttl_minutes: 15 })
const hourOptions = Array.from({ length: 24 }, (_, index) => index)

const actionOptions = [
  { value: 'observe', label: '观察' }, { value: 'block_ip', label: '封禁 IP' }, { value: 'isolate_host', label: '主机隔离' },
  { value: 'process_kill', label: '终止进程' }, { value: 'file_delete', label: '隔离文件' }, { value: 'account_disable', label: '禁用账号' },
  { value: 'namespace_isolate', label: '容器网络隔离' },
]
const targetPlaceholder = computed(() => ({ block_ip: 'IP 地址（必须在 RESPONSE_ALLOWED_CIDRS 内）', process_kill: 'PID', file_delete: '绝对文件路径', account_disable: '用户名', namespace_isolate: '容器 ID' })[form.action] || '目标')
const requiresTarget = computed(() => ['block_ip', 'process_kill', 'file_delete', 'account_disable', 'namespace_isolate'].includes(form.action))
const pendingCount = computed(() => actions.value.filter((item) => item.status === 'pending_approval').length)
const executedCount = computed(() => actions.value.filter((item) => item.status === 'executed').length)
const failedCount = computed(() => actions.value.filter((item) => ['failed', 'rolled_back'].includes(item.status)).length)
const canCreate = computed(() => Boolean(form.agent_id && (form.action === 'observe' || form.action === 'isolate_host' || form.target)))
const filteredActions = computed(() => actions.value.filter((item) => {
  if (statusFilter.value && item.status !== statusFilter.value) return false
  if (riskFilter.value && item.risk !== riskFilter.value) return false
  if (query.value) {
    const haystack = [item.action, item.target, item.incident_id, item.requested_by, item.approved_by, item.id].join(' ').toLowerCase()
    if (!haystack.includes(query.value.toLowerCase())) return false
  }
  return true
}))

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function actionLabel(value) { return ({ observe: '观察', block_ip: '封禁 IP', unblock_ip: '解封 IP', isolate_host: '主机隔离', host_unisolate: '取消隔离', process_kill: '终止进程', file_delete: '隔离文件', file_restore: '恢复文件', account_disable: '禁用账号', account_enable: '恢复账号', namespace_isolate: '容器隔离', namespace_restore: '恢复容器网络' })[value] || value || '-' }
function statusLabel(value) { return ({ pending_approval: '待审批', approved: '已批准', executed: '已执行', failed: '失败', rolled_back: '已回滚' })[value] || value || '-' }
function statusTone(value) { return ({ pending_approval: 'medium', approved: 'info', executed: 'low', failed: 'critical', rolled_back: 'muted' })[value] || 'muted' }
function riskTone(value) { return ({ L1: 'low', L2: 'medium', L3: 'critical' })[value] || 'muted' }
function canRollback(action) { return ['executed', 'failed'].includes(action.status) && ['block_ip', 'isolate_host', 'file_delete', 'account_disable', 'namespace_isolate'].includes(action.action) }

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [actionResult, agentResult, automationResult] = await Promise.allSettled([
      responseClient.actions({ limit: 100 }),
      assetAgentClient.agents({ limit: 200 }),
      responseClient.automation(),
    ])
    if (actionResult.status === 'fulfilled') {
      const data = unwrap(actionResult.value)
      actions.value = Array.isArray(data.items) ? data.items : []
    }
    if (agentResult.status === 'fulfilled') {
      const data = unwrap(agentResult.value)
      agents.value = Array.isArray(data.items) ? data.items : []
      if (!form.agent_id && agents.value.length) form.agent_id = agents.value[0].agent_id
    }
    if (automationResult.status === 'fulfilled') {
      automation.value = unwrap(automationResult.value)
      Object.assign(automationForm, {
        enabled: Boolean(automation.value.enabled),
        window_start_hour: Number(automation.value.window_start_hour ?? 0),
        window_end_hour: Number(automation.value.window_end_hour ?? 23),
        approval_ttl_minutes: Number(automation.value.approval_ttl_minutes ?? 15),
      })
    }
    if ([actionResult, agentResult].every((result) => result.status === 'rejected')) {
      error.value = '响应处置数据加载失败。'
    }
  } finally {
    loading.value = false
  }
}

async function saveAutomation() {
  automationSaving.value = true
  automationMessage.value = ''
  try {
    const data = unwrap(await responseClient.updateAutomation({
      enabled: Boolean(automationForm.enabled),
      window_start_hour: Number(automationForm.window_start_hour),
      window_end_hour: Number(automationForm.window_end_hour),
      require_different_approver: Boolean(automation.value.require_different_approver ?? true),
      approval_ttl_minutes: Number(automationForm.approval_ttl_minutes || 15),
    }))
    automation.value = data
    automationMessage.value = data.enabled ? '自动化策略已保存并生效。' : '自动化策略已保存，窗口内暂不自动执行。'
    automationMessageType.value = 'success'
  } catch (cause) {
    automationMessage.value = cause?.message || '自动化策略保存失败。'
    automationMessageType.value = 'error'
  } finally {
    automationSaving.value = false
  }
}

async function createAction() {
  if (!canCreate.value) return
  creating.value = true
  message.value = ''
  try {
    await responseClient.create({
      agent_id: form.agent_id,
      action: form.action,
      target: requiresTarget.value ? form.target : form.agent_id,
      reason: form.reason || '响应中心人工处置',
      ttl_seconds: 300,
    })
    message.value = '处置已提交；L2 在自动化窗口内会直接执行，L3 进入审批队列。'
    messageType.value = 'success'
    form.target = ''
    form.reason = ''
    await load()
  } catch (cause) {
    message.value = cause?.message || '响应动作提交失败。'
    messageType.value = 'error'
  } finally {
    creating.value = false
  }
}

async function approve(action) {
  updating.value = action.id
  try {
    await responseClient.approve(action.id, {})
    await load()
  } catch (cause) {
    error.value = cause?.message || '审批失败：审批人必须与发起人不同。'
  } finally {
    updating.value = ''
  }
}

async function rollback(action) {
  updating.value = action.id
  try {
    await responseClient.rollback(action.id)
    await load()
  } catch (cause) {
    error.value = cause?.message || '回滚失败。'
  } finally {
    updating.value = ''
  }
}

onMounted(load)
</script>

<style scoped>
.response-page { gap: 14px; }
.response-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.automation-panel { border-color: var(--sx-accent-line); }
.automation-body { display: grid; grid-template-columns: minmax(220px, 1.4fr) 120px 120px 150px; gap: 10px; align-items: end; }
.automation-toggle { display: flex; min-height: 34px; align-items: center; gap: 8px; cursor: pointer; }
.automation-toggle input { width: 15px; height: 15px; accent-color: var(--sx-accent); }
.automation-toggle span { display: grid; gap: 2px; }
.automation-toggle b { color: var(--sx-text); font-size: 11px; }
.automation-toggle small { color: var(--sx-text-3); font-size: 9px; }
.automation-body label { display: grid; gap: 4px; }
.automation-body label > span { color: var(--sx-text-3); font-size: 9px; }
.automation-actions { display: flex; grid-column: 1 / -1; align-items: center; justify-content: space-between; gap: 10px; }
.create-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 9px; align-items: end; }
.create-grid label { display: grid; gap: 4px; min-width: 0; }
.create-grid label > span { color: var(--sx-text-3); font-size: 9px; }
.create-grid .agent-field { grid-column: span 2; }
.create-grid .wide { grid-column: span 2; }
.create-grid .description-field { grid-column: 1 / -1; }
.reason-input { height: auto; min-height: 58px; padding: 8px 9px; resize: vertical; }
.create-actions { display: flex; grid-column: 1 / -1; align-items: center; justify-content: flex-end; gap: 12px; }
.response-message { font-size: 10px; }
.response-message.success { color: var(--sx-success); }
.response-message.error { color: var(--sx-danger); }
.response-table { min-width: 1080px; }
.action-buttons { display: flex; gap: 4px; }
.action-buttons .sx-btn { height: 25px; padding: 0 7px; font-size: 9px; }
.action-error { display: block; max-width: 180px; margin-top: 3px; overflow: hidden; color: var(--sx-danger); font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
@media (max-width: 1100px) {
  .response-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .create-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .create-grid .wide, .create-actions { grid-column: span 2; }
}
@media (max-width: 700px) {
  .response-stats, .create-grid { grid-template-columns: 1fr; }
  .create-grid .wide, .create-actions { grid-column: auto; }
}
</style>
