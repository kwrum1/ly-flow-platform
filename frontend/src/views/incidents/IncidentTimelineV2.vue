<template>
  <section class="sx-page incident-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">ATTACK CHAIN RESPONSE</p>
        <h2 class="sx-title">攻击链处置</h2>
        <p class="sx-subtitle">按 Incident 聚合跨源证据、阶段时间线与响应动作；审批使用当前登录身份，L3 动作需要第二名管理员。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="loadIncidents({ live: true })">刷新</button>
      </div>
    </header>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="incident-layout">
      <aside class="sx-panel incident-sidebar">
        <div class="sidebar-head">
          <div><b>Incident</b><span>{{ formatNumber(incidentTotal) }} 条</span></div>
          <div class="sidebar-filters">
            <select v-model="statusFilter" class="sx-select" @change="applyIncidentFilters">
              <option value="active">未闭环</option>
              <option value="">全部状态</option>
              <option value="open">新发</option>
              <option value="triaged">已分诊</option>
              <option value="processing">处理中</option>
              <option value="resolved">已解决</option>
              <option value="closed">已关闭</option>
            </select>
            <select v-model="severityFilter" class="sx-select" @change="applyIncidentFilters">
              <option value="">全部等级</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
          </div>
        </div>
        <div class="incident-list sx-scroll">
          <button
            v-for="item in filteredIncidents"
            :key="item.id"
            type="button"
            class="incident-list-row"
            :class="{ active: selected?.id === item.id }"
            @click="selectIncident(item)"
          >
            <span class="sx-badge" :class="item.severity">{{ severityLabel(item.severity) }}</span>
            <div>
              <b>{{ item.title }}</b>
              <small>{{ item.affectedAsset || item.entityId || '未绑定资产' }} · {{ formatShort(item.updatedAt || item.createdAt) }}</small>
              <div class="row-stage-line">
                <span v-for="stage in (item.stages || []).slice(0, 4)" :key="stage.id">{{ stage.name }}</span>
              </div>
            </div>
            <span class="row-status">{{ statusLabel(item.status) }}</span>
          </button>
          <div v-if="!filteredIncidents.length" class="sx-empty"><div><strong>暂无匹配 Incident</strong>调整筛选条件或等待关联链生成。</div></div>
        </div>
        <div class="sidebar-pager">
          <button class="sx-btn" type="button" :disabled="loading || incidentPage <= 1" @click="changeIncidentPage(-1)">上一页</button>
          <span>{{ incidentPage }} / {{ incidentPages }}</span>
          <button class="sx-btn" type="button" :disabled="loading || incidentPage >= incidentPages" @click="changeIncidentPage(1)">下一页</button>
        </div>
      </aside>

      <main class="incident-main">
        <div v-if="!selected" class="sx-panel no-selection">
          <div class="sx-empty"><div><strong>选择左侧 Incident</strong>查看阶段时间线、证据和响应动作。</div></div>
        </div>
        <template v-else>
          <section class="sx-panel incident-hero">
            <div class="incident-hero-main">
              <div class="incident-hero-top">
                <span class="sx-badge" :class="selected.severity">{{ severityLabel(selected.severity) }}</span>
                <span class="sx-badge muted">{{ selected.id }}</span>
              </div>
              <h3>{{ selected.title }}</h3>
              <p>{{ selected.affectedAsset || selected.entityId || '未绑定资产' }} · 创建于 {{ formatTime(selected.createdAt) }} · 更新于 {{ formatTime(selected.updatedAt) }}</p>
            </div>
            <div class="incident-hero-actions">
              <select class="sx-select" :value="selected.status" :disabled="updatingStatus" @change="updateStatus($event.target.value)">
                <option v-for="status in availableStatuses" :key="status" :value="status">{{ statusLabel(status) }}</option>
              </select>
            </div>
          </section>

          <section class="incident-facts">
            <div><span>源 IP</span><b class="sx-mono">{{ selected.sourceIPs?.join(', ') || '-' }}</b></div>
            <div><span>受害 IP</span><b class="sx-mono">{{ selected.victimIPs?.join(', ') || '-' }}</b></div>
            <div><span>实体 / Agent</span><b>{{ agentIdentity }}</b></div>
            <div><span>证据</span><b>{{ selected.evidence?.length || 0 }} 条</b></div>
            <div><span>建议动作</span><b>{{ selected.recommendedAction || '待研判' }}</b></div>
          </section>

          <section class="sx-panel stage-ribbon-panel">
            <div class="sx-panel-head">
              <div class="sx-panel-title">攻击阶段</div>
              <span class="sx-panel-meta">阶段状态来自 Incident 关联链</span>
            </div>
            <div class="sx-panel-body">
              <div class="sx-stage-ribbon">
                <div v-for="stage in stageRibbon" :key="stage.key" class="sx-stage" :class="{ active: stage.active }">
                  <span>{{ stage.label }}</span>
                  <strong>{{ stage.count }}</strong>
                  <i :style="{ width: stage.active ? '100%' : '0%' }" />
                </div>
              </div>
            </div>
          </section>

          <div class="incident-detail-grid">
            <article class="sx-panel timeline-panel">
              <div class="sx-panel-head">
                <div class="sx-panel-title">阶段时间线</div>
                <span class="sx-panel-meta">{{ groups.length }} 个阶段 · {{ selected.evidence?.length || 0 }} 条证据</span>
              </div>
              <div v-if="groups.length" class="timeline sx-scroll">
                <div v-for="group in groups" :key="group.id" class="timeline-group">
                  <div class="timeline-marker"><i /><span>{{ group.name || stageLabel(group.stage) }}</span><small>{{ group.tactic || '' }}</small></div>
                  <div class="timeline-body">
                    <div v-if="group.evidence.length" class="timeline-evidence">
                      <button v-for="evidence in group.evidence" :key="evidence.id" type="button" class="timeline-evidence-row" @click="toggleEvidence(group.id)">
                        <span class="sx-badge info">{{ evidence.sourceModule || 'xdr' }}</span>
                        <div><b>{{ evidence.title }}</b><small>{{ evidence.summary }}</small></div>
                        <time>{{ formatTime(evidence.time) }}</time>
                      </button>
                      <pre v-if="expandedEvidence === group.id" class="evidence-raw sx-scroll">{{ prettyEvidence(group.evidence[0]) }}</pre>
                    </div>
                    <div v-else class="timeline-empty">该阶段暂无可展示证据。</div>
                  </div>
                </div>
              </div>
              <div v-else class="sx-empty"><div><strong>暂无阶段证据</strong>Incident 尚未产生可展示的关联链。</div></div>
            </article>

            <aside class="incident-side-stack">
              <article class="sx-panel response-panel">
                <div class="sx-panel-head">
                  <div class="sx-panel-title">响应处置</div>
                  <span class="sx-panel-meta">{{ actionsForIncident.length }} 条记录</span>
                </div>
                <div class="sx-panel-body">
                  <div class="closure-box">
                    <div class="closure-head">
                      <div><b>闭环结论</b><small>确认告警性质后关闭 Incident；关闭动作会写入审计记录</small></div>
                      <span class="sx-badge" :class="closureBadgeTone">{{ statusLabel(selected.status) }}</span>
                    </div>
                    <div v-if="selected.status === 'closed'" class="closure-closed">
                      <b>该 Incident 已关闭</b>
                      <small>{{ latestClosureReason || '可在阶段时间线中查看审计记录' }}</small>
                    </div>
                    <template v-else>
                      <div class="closure-grid">
                        <label><span>结论</span>
                          <select v-model="closureForm.disposition" class="sx-select">
                            <option value="observe">继续观察（不关闭）</option>
                            <option value="false_positive">确认误报并关闭</option>
                            <option value="expected_activity">授权/预期操作并关闭</option>
                            <option value="resolved">确认已处置并关闭</option>
                          </select>
                        </label>
                        <label><span>原因（必填）</span>
                          <input v-model.trim="closureForm.reason" class="sx-input" placeholder="例如：GPL NETBIOS 为误报 / 本人 SSH 登录" />
                        </label>
                      </div>
                      <div v-if="closureForm.disposition !== 'observe'" class="closure-grid closure-suppress-grid">
                        <label><span>减少重复告警</span>
                          <select v-model="closureForm.suppress_scope" class="sx-select" @change="syncSuppressionValue">
                            <option value="none">不抑制，仅关闭本次</option>
                            <option value="rule">抑制同规则（当前证据）</option>
                            <option value="source">抑制同来源 IP</option>
                            <option value="victim">抑制同资产/受害实体</option>
                          </select>
                        </label>
                        <label><span>抑制时长</span>
                          <select v-model.number="closureForm.suppress_days" class="sx-select" :disabled="closureForm.suppress_scope === 'none'">
                            <option :value="7">7 天</option>
                            <option :value="30">30 天</option>
                            <option :value="90">90 天</option>
                          </select>
                        </label>
                      </div>
                      <div v-if="closureForm.suppress_scope !== 'none'" class="closure-value-line">
                        <span>匹配值</span><input v-model.trim="closureForm.suppress_value" class="sx-input" :placeholder="suppressionValuePlaceholder" />
                      </div>
                      <div class="closure-hint">误报才使用“同规则”抑制；本人登录等预期操作请选择“授权/预期操作”，不要屏蔽 SSH 规则。</div>
                      <div v-if="evidenceRules.length" class="rule-hints">
                        <span>当前证据规则</span>
                        <button v-for="rule in evidenceRules" :key="rule.value" type="button" class="sx-btn ghost" @click="presetRuleSuppression(rule)">误报？抑制 {{ rule.label }}</button>
                      </div>
                      <div class="closure-actions">
                        <span v-if="closureMessage" :class="['response-message', closureMessageType]">{{ closureMessage }}</span>
                        <button class="sx-btn primary" type="button" :disabled="closingIncident || !closureForm.reason" @click="submitClosure">{{ closingIncident ? '提交中…' : '确认闭环' }}</button>
                      </div>
                    </template>
                  </div>
                  <div class="response-form">
                    <div class="response-agent"><span>处置 Agent</span><b>{{ agentIdentity }}</b><small>来自当前 Incident 证据</small></div>
                    <div class="response-form-row">
                      <label><span>动作</span>
                        <select v-model="actionForm.action" class="sx-select">
                          <option value="observe">观察</option>
                          <option value="block_ip">封禁 IP</option>
                          <option value="isolate_host">主机隔离</option>
                          <option value="process_kill">终止进程</option>
                          <option value="file_delete">隔离文件</option>
                          <option value="account_disable">禁用账号</option>
                          <option value="namespace_isolate">容器网络隔离</option>
                        </select>
                      </label>
                      <label v-if="actionRequiresTarget"><span>目标</span><input v-model.trim="actionForm.target" class="sx-input" :placeholder="actionTargetPlaceholder" /></label>
                    </div>
                    <label><span>说明</span><textarea v-model.trim="actionForm.reason" class="sx-input reason-input" rows="2" placeholder="处置依据 / 变更单号（可选）" /></label>
                    <div class="response-form-actions">
                      <span v-if="actionMessage" :class="['response-message', actionMessageType]">{{ actionMessage }}</span>
                      <button class="sx-btn primary" type="button" :disabled="creatingAction || !canCreateAction" @click="createAction">{{ creatingAction ? '提交中…' : '提交处置' }}</button>
                    </div>
                  </div>

                  <div v-if="actionsForIncident.length" class="action-list">
                    <div v-for="action in actionsForIncident" :key="action.id" class="action-row">
                      <div>
                        <b>{{ actionLabel(action.action) }}</b>
                        <small>{{ action.target || '-' }} · {{ action.risk }} · {{ action.requested_by }}</small>
                        <em v-if="action.error">{{ action.error }}</em>
                      </div>
                      <span class="sx-badge" :class="actionTone(action.status)">{{ actionStatusLabel(action.status) }}</span>
                      <div class="action-buttons">
                        <button v-if="action.status === 'pending_approval'" class="sx-btn" type="button" :disabled="updatingAction === action.id" @click="approveAction(action)">审批</button>
                        <button v-if="canRollback(action)" class="sx-btn ghost" type="button" :disabled="updatingAction === action.id" @click="rollbackAction(action)">回滚</button>
                      </div>
                    </div>
                  </div>
                  <div v-else class="sx-muted response-empty">该 Incident 还没有响应动作。</div>
                </div>
              </article>

              <article class="sx-panel evidence-panel">
                <div class="sx-panel-head">
                  <div class="sx-panel-title">证据包</div>
                  <span class="sx-panel-meta">{{ bundlesForIncident.length }} 个</span>
                </div>
                <div class="sx-panel-body">
                  <div class="evidence-actions">
                    <button class="sx-btn primary" type="button" :disabled="creatingBundle || !selected.evidence?.length" @click="createBundle">{{ creatingBundle ? '打包中…' : '生成证据包' }}</button>
                    <span class="sx-muted">使用当前 Incident 的证据事件</span>
                  </div>
                  <div v-if="bundleMessage" class="response-message" :class="bundleMessageType">{{ bundleMessage }}</div>
                  <div v-if="bundlesForIncident.length" class="bundle-list">
                    <div v-for="bundle in bundlesForIncident" :key="bundle.id" class="bundle-row">
                      <div><b class="sx-mono">{{ bundle.id }}</b><small>{{ formatSize(bundle.size) }} · {{ formatTime(bundle.created_at) }}</small></div>
                      <button class="sx-btn" type="button" @click="downloadBundle(bundle)">下载</button>
                    </div>
                  </div>
                  <div v-else class="sx-muted evidence-empty">尚未生成证据包。</div>
                </div>
              </article>
            </aside>
          </div>
        </template>
      </main>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { attackWorkbenchClient, evidenceClient, responseClient } from '../../api/domain'
import { incidentsAPI } from '../../api/events'
import { severityLabel, stageLabel } from '../../domain/attack-labels'
import { normalizeIncident, normalizeIncidents } from '../../domain/incidents'

const route = useRoute()
const PAGE_SIZE = 20
const incidents = ref([])
const incidentTotal = ref(0)
const incidentPage = ref(1)
const selected = ref(null)
const loading = ref(false)
const updatingStatus = ref(false)
const updatingAction = ref('')
const creatingAction = ref(false)
const creatingBundle = ref(false)
const error = ref('')
const actionMessage = ref('')
const actionMessageType = ref('success')
const bundleMessage = ref('')
const bundleMessageType = ref('success')
const expandedEvidence = ref('')
const statusFilter = ref('active')
const severityFilter = ref('')
const actions = ref([])
const bundles = ref([])
const statuses = ['open', 'triaged', 'processing', 'resolved', 'closed']
const statusTransitions = {
  open: ['open', 'triaged', 'processing'],
  triaged: ['triaged', 'open', 'processing'],
  processing: ['processing', 'open', 'triaged', 'resolved'],
  resolved: ['resolved', 'processing', 'open', 'closed'],
  closed: ['closed', 'open'],
}
const actionForm = reactive({ action: 'observe', target: '', agent_id: '', reason: '' })
const closureForm = reactive({ disposition: 'observe', reason: '', suppress_scope: 'none', suppress_value: '', suppress_days: 30 })
const closingIncident = ref(false)
const closureMessage = ref('')
const closureMessageType = ref('success')

const stageDefinitions = [
  ['detection', '检测命中'], ['recon', '侦察'], ['initial_access', '初始访问'], ['execution', '执行'],
  ['persistence', '持久化'], ['privilege_escalation', '提权'], ['lateral_movement', '横向移动'],
  ['command_and_control', '命令控制'], ['exfiltration', '外传'], ['impact', '影响'],
]

const filteredIncidents = computed(() => incidents.value.filter((item) => {
  if (statusFilter.value === 'active') {
    if (item.status === 'closed') return false
  } else if (statusFilter.value && item.status !== statusFilter.value) {
    return false
  }
  if (severityFilter.value && item.severity !== severityFilter.value) return false
  return true
}))
const availableStatuses = computed(() => statusTransitions[selected.value?.status] || statuses)
const incidentPages = computed(() => Math.max(1, Math.ceil(incidentTotal.value / PAGE_SIZE)))
const groups = computed(() => {
  if (!selected.value) return []
  if (selected.value.stageGroups?.length) return selected.value.stageGroups
  const evidence = selected.value.evidence || []
  return (selected.value.stages || []).map((stage) => ({
    ...stage,
    id: stage.id,
    stage: stage.stageKey,
    name: stage.name,
    tactic: stage.tactic,
    evidence: evidence.filter((item) => item.stage === stage.stageKey),
  }))
})
const stageRibbon = computed(() => {
  const counts = {}
  for (const stage of selected.value?.stages || []) counts[stage.stageKey] = (counts[stage.stageKey] || 0) + 1
  return stageDefinitions.map(([key, label]) => ({ key, label, active: Boolean(counts[key]), count: counts[key] || 0 }))
})
const agentIdentity = computed(() => incidentAgent(selected.value))
const actionsForIncident = computed(() => actions.value.filter((item) => item.incident_id === selected.value?.id))
const bundlesForIncident = computed(() => bundles.value.filter((item) => item.incident_id === selected.value?.id))
const actionRequiresTarget = computed(() => ['block_ip', 'process_kill', 'file_delete', 'account_disable', 'namespace_isolate'].includes(actionForm.action))
const actionTargetPlaceholder = computed(() => ({ block_ip: 'IP 地址（必须在 RESPONSE_ALLOWED_CIDRS 内）', process_kill: 'PID', file_delete: '绝对文件路径', account_disable: '用户名', namespace_isolate: '容器 ID' })[actionForm.action] || '目标')
const canCreateAction = computed(() => Boolean(actionForm.agent_id && (!actionRequiresTarget.value || actionForm.target)))
const evidenceRules = computed(() => {
  const seen = new Set()
  return (selected.value?.evidence || []).map((item) => {
    const value = item.ruleId || item.ruleName
    const label = item.ruleId || item.ruleName
    return value && !seen.has(value) && seen.add(value) ? { value, label } : null
  }).filter(Boolean)
})
const closureBadgeTone = computed(() => selected.value?.status === 'closed' ? 'low' : selected.value?.status === 'resolved' ? 'info' : 'medium')
const latestClosureReason = computed(() => {
  const audit = [...(selected.value?.audit || [])].reverse()
  return audit.find((item) => item.reason)?.reason || ''
})
const suppressionValuePlaceholder = computed(() => ({ rule: '规则 ID 或名称', source: '来源 IP', victim: 'Agent / 资产名' })[closureForm.suppress_scope] || '')
function syncSuppressionValue() {
  if (closureForm.suppress_scope === 'rule') closureForm.suppress_value = evidenceRules.value[0]?.value || ''
  else if (closureForm.suppress_scope === 'source') closureForm.suppress_value = selected.value?.sourceIPs?.[0] || ''
  else if (closureForm.suppress_scope === 'victim') closureForm.suppress_value = agentIdentity.value !== '-' ? agentIdentity.value : selected.value?.victimIPs?.[0] || selected.value?.affectedAsset || ''
  else closureForm.suppress_value = ''
}
function presetRuleSuppression(rule) {
  closureForm.disposition = 'false_positive'
  closureForm.suppress_scope = 'rule'
  closureForm.suppress_value = rule.value
  if (!closureForm.reason) closureForm.reason = `确认 ${rule.label} 为误报`
}

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function formatShort(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) }
function formatSize(value) { const size = Number(value || 0); return size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B` }
function statusLabel(value) { return ({ new: '新发', open: '新发', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭' })[value] || value || '-' }
function actionStatusLabel(value) { return ({ pending_approval: '待审批', approved: '已批准', executed: '已执行', failed: '失败', rolled_back: '已回滚' })[value] || value || '-' }
function actionTone(value) { return ({ pending_approval: 'medium', approved: 'info', executed: 'low', failed: 'critical', rolled_back: 'muted' })[value] || 'muted' }
function actionLabel(value) { return ({ observe: '观察', block_ip: '封禁 IP', isolate_host: '主机隔离', process_kill: '终止进程', file_delete: '隔离文件', account_disable: '禁用账号', namespace_isolate: '容器隔离' })[value] || value || '-' }
function canRollback(action) { return ['executed', 'failed'].includes(action.status) && ['block_ip', 'isolate_host', 'file_delete', 'account_disable', 'namespace_isolate'].includes(action.action) }
function incidentAgent(item) {
  const evidenceAgent = (item?.evidence || []).map((evidence) => evidence.entityId).find((value) => value && !/^(inc-|hyp-)/.test(value))
  return evidenceAgent || item?.affectedAsset || item?.entityId || '-'
}

function prettyEvidence(evidence) { try { return JSON.stringify(evidence?.raw || evidence, null, 2) } catch { return String(evidence?.raw || '') } }
function toggleEvidence(id) { expandedEvidence.value = expandedEvidence.value === id ? '' : id }

async function loadIncidents(options = {}) {
  loading.value = true
  error.value = ''
  try {
    const offset = (incidentPage.value - 1) * PAGE_SIZE
    const params = { limit: PAGE_SIZE, offset, live: options.live ? 1 : 0 }
    if (statusFilter.value) params.status = statusFilter.value
    if (severityFilter.value) params.severity = severityFilter.value
    const data = unwrap(await attackWorkbenchClient.incidents(params))
    incidents.value = normalizeIncidents(Array.isArray(data.items) ? data.items : [])
    incidentTotal.value = Number(data.total ?? incidents.value.length) || incidents.value.length
    const wanted = String(route.query.id || '')
    const current = incidents.value.find((item) => item.id === wanted) || incidents.value.find((item) => item.id === selected.value?.id) || incidents.value[0]
    if (current) selectIncident(current)
  } catch (cause) {
    error.value = 'Incident 数据加载失败，请检查后端连接。'
  } finally {
    loading.value = false
  }
}

function changeIncidentPage(delta) {
  const next = incidentPage.value + delta
  if (next < 1 || next > incidentPages.value) return
  incidentPage.value = next
  loadIncidents()
}

function applyIncidentFilters() {
  incidentPage.value = 1
  loadIncidents()
}

async function selectIncident(item) {
  if (!item) return
  selected.value = item
  closureMessage.value = ''
  closureForm.disposition = 'observe'
  closureForm.reason = ''
  closureForm.suppress_scope = 'none'
  closureForm.suppress_value = ''
  closureForm.suppress_days = 30
  actionForm.agent_id = incidentAgent(item) === '-' ? '' : incidentAgent(item)
  try {
    const detail = unwrap(await attackWorkbenchClient.incident(item.id))
    selected.value = normalizeIncident(Object.keys(detail).length ? detail : item)
  } catch { /* keep list row */ }
  await Promise.all([loadActions(), loadBundles()])
}

async function loadActions() {
  try {
    const data = unwrap(await responseClient.actions({ limit: 100 }))
    actions.value = Array.isArray(data.items) ? data.items : []
  } catch { actions.value = [] }
}

async function loadBundles() {
  try {
    const data = unwrap(await evidenceClient.bundles({ limit: 100 }))
    bundles.value = Array.isArray(data.items) ? data.items : []
  } catch { bundles.value = [] }
}

async function updateStatus(status) {
  if (!selected.value || status === selected.value.status) return
  updatingStatus.value = true
  try {
    await incidentsAPI.updateStatus(selected.value.id, status)
    selected.value = { ...selected.value, status }
    await loadIncidents()
  } catch (cause) {
    error.value = cause?.message || 'Incident 状态更新失败。'
  } finally {
    updatingStatus.value = false
  }
}

async function submitClosure() {
  if (!selected.value || !closureForm.reason.trim()) return
  closingIncident.value = true
  closureMessage.value = ''
  try {
    if (closureForm.disposition === 'observe') {
      await incidentsAPI.updateStatus(selected.value.id, selected.value.status, {
        reason: `[observe] ${closureForm.reason.trim()}`,
      })
      closureMessage.value = '已记录观察结论，Incident 保持当前状态。'
      closureMessageType.value = 'success'
    } else {
      const options = {
        disposition: closureForm.disposition,
        reason: closureForm.reason.trim(),
      }
      if (closureForm.suppress_scope !== 'none') {
        options.suppress_scope = closureForm.suppress_scope
        options.suppress_value = closureForm.suppress_value
        options.suppress_days = closureForm.suppress_days
      }
      const result = unwrap(await incidentsAPI.updateStatus(selected.value.id, 'closed', options))
      selected.value = normalizeIncident(Object.keys(result).length ? result : { ...selected.value, status: 'closed' })
      closureMessage.value = result.suppression
        ? `已关闭，并抑制 ${result.suppression.scope}:${result.suppression.value} 至 ${formatTime(result.suppression.expires_at)}。`
        : '已关闭并写入审计记录。'
      closureMessageType.value = 'success'
    }
    const pendingMessage = closureMessage.value
    const pendingType = closureMessageType.value
    await loadIncidents()
    closureMessage.value = pendingMessage
    closureMessageType.value = pendingType
  } catch (cause) {
    closureMessage.value = cause?.message || 'Incident 闭环失败。'
    closureMessageType.value = 'error'
  } finally {
    closingIncident.value = false
  }
}

async function createAction() {
  if (!selected.value || !canCreateAction.value) return
  creatingAction.value = true
  actionMessage.value = ''
  try {
    await responseClient.create({
      incident_id: selected.value.id,
      agent_id: actionForm.agent_id,
      action: actionForm.action,
      target: actionRequiresTarget.value ? actionForm.target : actionForm.agent_id,
      reason: actionForm.reason || `Incident ${selected.value.id} 人工处置`,
      ttl_seconds: 300,
    })
    actionMessage.value = '已提交审批队列。'
    actionMessageType.value = 'success'
    actionForm.target = ''
    actionForm.reason = ''
    await loadActions()
  } catch (cause) {
    actionMessage.value = cause?.message || '响应动作提交失败。'
    actionMessageType.value = 'error'
  } finally {
    creatingAction.value = false
  }
}

async function approveAction(action) {
  updatingAction.value = action.id
  try {
    await responseClient.approve(action.id, {})
    await loadActions()
  } catch (cause) {
    error.value = cause?.message || '审批失败：需要与发起人不同的管理员身份。'
  } finally {
    updatingAction.value = ''
  }
}

async function rollbackAction(action) {
  updatingAction.value = action.id
  try {
    await responseClient.rollback(action.id)
    await loadActions()
  } catch (cause) {
    error.value = cause?.message || '回滚失败。'
  } finally {
    updatingAction.value = ''
  }
}

async function createBundle() {
  if (!selected.value || !selected.value.evidence?.length) return
  creatingBundle.value = true
  bundleMessage.value = ''
  try {
    const eventUIDs = [...new Set(selected.value.evidence.map((item) => item.id).filter(Boolean))]
    const result = unwrap(await evidenceClient.createBundle({
      incident_id: selected.value.id,
      agent_id: (() => { const agent = incidentAgent(selected.value); return agent === '-' ? '' : agent })(),
      event_uids: eventUIDs,
      note: `Incident ${selected.value.id} evidence bundle`,
    }))
    bundleMessage.value = `证据包已生成：${result.id || '已提交'}`
    bundleMessageType.value = 'success'
    await loadBundles()
  } catch (cause) {
    bundleMessage.value = cause?.message || '证据包生成失败：证据事件可能不在 Event v2 存储中。'
    bundleMessageType.value = 'error'
  } finally {
    creatingBundle.value = false
  }
}

async function downloadBundle(bundle) {
  try {
    const blob = await evidenceClient.download(bundle.id)
    const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([blob]))
    const link = document.createElement('a')
    link.href = url
    link.download = `${bundle.id}.json`
    link.click()
    URL.revokeObjectURL(url)
  } catch {
    error.value = '证据包下载失败。'
  }
}

onMounted(() => {
  loadActions()
  loadBundles()
  loadIncidents()
})
</script>

<style scoped>
.incident-page { gap: 14px; }
.incident-layout { display: grid; grid-template-columns: 306px minmax(0, 1fr); gap: 14px; min-height: 620px; }
.incident-sidebar { display: flex; min-height: 620px; flex-direction: column; }
.sidebar-head { display: grid; gap: 8px; padding: 11px 12px; border-bottom: 1px solid var(--sx-line-soft); }
.sidebar-head > div:first-child { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.sidebar-head b { color: var(--sx-text); font-size: 12px; }
.sidebar-head span { color: var(--sx-text-3); font-size: 12px; }
.sidebar-filters { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.incident-list { flex: 1; }
.sidebar-pager { display: flex; align-items: center; justify-content: space-between; gap: 6px; padding: 7px 10px; border-top: 1px solid var(--sx-line-soft); color: var(--sx-text-3); font-size: 11px; }
.sidebar-pager .sx-btn { height: 24px; padding: 0 7px; font-size: 11px; }
.incident-list-row { display: grid; width: 100%; grid-template-columns: 46px minmax(0, 1fr) auto; align-items: start; gap: 8px; padding: 10px 12px; border: 0; border-bottom: 1px solid var(--sx-line-soft); background: transparent; color: inherit; text-align: left; cursor: pointer; transition: background var(--transition-fast); }
.incident-list-row:hover, .incident-list-row.active { background: var(--sx-accent-soft); }
.incident-list-row.active { box-shadow: inset 3px 0 var(--sx-accent); }
.incident-list-row > div { min-width: 0; }
.incident-list-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 11px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.incident-list-row small { display: block; overflow: hidden; margin-top: 2px; color: var(--sx-text-3); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.row-stage-line { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 4px; }
.row-stage-line span { padding: 1px 4px; border-radius: 3px; background: var(--sx-surface-3); color: var(--sx-text-2); font-size: 12px; }
.row-status { color: var(--sx-text-3); font-size: 11px; white-space: nowrap; }
.incident-main { display: grid; min-width: 0; align-content: start; gap: 12px; }
.no-selection { min-height: 320px; }
.incident-hero { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 15px 17px; }
.incident-hero-top { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.incident-hero h3 { margin: 7px 0 0; color: var(--sx-text); font-size: 19px; font-weight: 720; letter-spacing: -0.03em; }
.incident-hero p { margin: 4px 0 0; color: var(--sx-text-3); font-size: 12px; }
.incident-hero-actions { flex: 0 0 auto; }
.incident-facts { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; }
.incident-facts > div { min-width: 0; padding: 9px 11px; border: 1px solid var(--sx-line); border-radius: var(--sx-radius-sm); background: var(--sx-surface); }
.incident-facts span { display: block; color: var(--sx-text-3); font-size: 11px; }
.incident-facts b { display: block; overflow: hidden; margin-top: 2px; color: var(--sx-text); font-size: 11px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.incident-detail-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(300px, 0.9fr); gap: 12px; align-items: start; }
.timeline { max-height: 620px; padding: 12px 14px 16px; }
.timeline-group { display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: 10px; }
.timeline-marker { position: relative; display: flex; flex-direction: column; gap: 2px; padding: 2px 0 18px 16px; color: var(--sx-accent); font-size: 12px; font-weight: 650; }
.timeline-marker::before { content: ""; position: absolute; top: 1px; left: 0; width: 7px; height: 7px; border-radius: 50%; background: var(--sx-accent); box-shadow: 0 0 0 3px var(--sx-accent-soft); }
.timeline-marker::after { content: ""; position: absolute; top: 12px; bottom: 0; left: 3px; width: 1px; background: var(--sx-line); }
.timeline-group:last-child .timeline-marker::after { display: none; }
.timeline-marker small { color: var(--sx-text-3); font-size: 12px; font-weight: 500; }
.timeline-body { min-width: 0; padding-bottom: 12px; }
.timeline-evidence { display: grid; gap: 5px; }
.timeline-evidence-row { display: grid; grid-template-columns: 58px minmax(0, 1fr) 90px; align-items: center; gap: 8px; width: 100%; padding: 7px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); color: inherit; text-align: left; cursor: pointer; }
.timeline-evidence-row:hover { border-color: var(--sx-accent-line); }
.timeline-evidence-row > div { min-width: 0; }
.timeline-evidence-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.timeline-evidence-row small { display: block; overflow: hidden; margin-top: 1px; color: var(--sx-text-3); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.timeline-evidence-row time { color: var(--sx-text-3); font-size: 12px; text-align: right; }
.evidence-raw { max-height: 220px; margin: 4px 0 0; padding: 9px; overflow: auto; border-radius: 5px; background: #071a2d; color: #c7e7ff; font-family: var(--sx-font-mono); font-size: 11px; line-height: 1.5; }
.timeline-empty { padding: 8px 0; color: var(--sx-text-3); font-size: 12px; }
.incident-side-stack { display: grid; gap: 12px; }
.closure-box { display: grid; gap: 9px; margin-bottom: 12px; padding: 10px; border: 1px solid #cfe3f6; border-radius: 7px; background: linear-gradient(180deg, #f5faff, #fff); }
.closure-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
.closure-head b { display: block; color: var(--sx-text); font-size: 11px; }
.closure-head small { display: block; margin-top: 2px; color: var(--sx-text-3); font-size: 11px; line-height: 1.5; }
.closure-grid { display: grid; grid-template-columns: 1fr 1.25fr; gap: 7px; }
.closure-suppress-grid { grid-template-columns: 1.4fr 0.8fr; }
.closure-grid label { display: grid; gap: 3px; }
.closure-grid label > span { color: var(--sx-text-3); font-size: 11px; }
.closure-value-line { display: grid; grid-template-columns: 42px minmax(0, 1fr); align-items: center; gap: 6px; }
.closure-value-line > span { color: var(--sx-text-3); font-size: 11px; }
.closure-hint { color: var(--sx-text-3); font-size: 11px; line-height: 1.5; }
.closure-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.closure-closed { display: grid; gap: 3px; padding: 8px 9px; border-radius: 5px; background: #edf8f1; color: #1c6b43; }
.closure-closed b { font-size: 12px; }
.closure-closed small { font-size: 11px; line-height: 1.5; }
.rule-hints { display: flex; flex-wrap: wrap; align-items: center; gap: 5px; padding-top: 2px; }
.rule-hints > span { color: var(--sx-text-3); font-size: 11px; }
.rule-hints .sx-btn { height: 24px; padding: 0 7px; font-size: 11px; }
.response-form { display: grid; gap: 7px; }
.response-agent { display: flex; align-items: center; gap: 7px; padding: 7px 9px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.response-agent span { color: var(--sx-text-3); font-size: 11px; }
.response-agent b { color: var(--sx-text); font-size: 12px; font-weight: 650; }
.response-agent small { color: var(--sx-text-3); font-size: 12px; }
.response-form-row { display: grid; grid-template-columns: 1fr 1.1fr; gap: 7px; }
.reason-input { height: auto; min-height: 52px; padding: 7px 9px; resize: vertical; }
.response-form label { display: grid; gap: 3px; }
.response-form label > span { color: var(--sx-text-3); font-size: 11px; }
.response-form-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.response-message { margin-top: 6px; font-size: 12px; }
.response-message.success { color: var(--sx-success); }
.response-message.error { color: var(--sx-danger); }
.response-empty { margin-top: 10px; font-size: 12px; }
.action-list { display: grid; gap: 5px; margin-top: 10px; }
.action-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: 6px; padding: 7px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.action-row > div:first-child { min-width: 0; }
.action-row b { display: block; color: var(--sx-text); font-size: 12px; }
.action-row small { display: block; overflow: hidden; color: var(--sx-text-3); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.action-row em { display: block; color: var(--sx-danger); font-size: 12px; font-style: normal; }
.action-buttons { display: flex; gap: 4px; }
.action-buttons .sx-btn { height: 25px; padding: 0 7px; font-size: 11px; }
.evidence-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.evidence-actions .sx-muted { font-size: 11px; }
.evidence-empty { margin-top: 9px; font-size: 12px; }
.bundle-list { display: grid; gap: 5px; margin-top: 8px; }
.bundle-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.bundle-row b { display: block; color: var(--sx-text); font-size: 11px; }
.bundle-row small { display: block; color: var(--sx-text-3); font-size: 12px; }
.bundle-row .sx-btn { height: 25px; padding: 0 7px; font-size: 11px; }

@media (max-width: 1180px) {
  .incident-layout { grid-template-columns: 260px minmax(0, 1fr); }
  .incident-detail-grid { grid-template-columns: 1fr; }
  .incident-facts { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .incident-layout { grid-template-columns: 1fr; }
  .incident-sidebar { min-height: 260px; max-height: 360px; }
  .incident-list { max-height: 240px; }
  .incident-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 620px) {
  .incident-hero { flex-direction: column; }
  .incident-facts { grid-template-columns: 1fr; }
  .timeline-group { grid-template-columns: 1fr; }
  .timeline-marker::after { display: none; }
  .response-form-row { grid-template-columns: 1fr; }
}
</style>
