<template>
  <div class="page-shell incidents-workbench">
    <section class="incidents-hero">
      <div>
        <span class="page-kicker">Incident Workbench</span>
        <h1 class="page-title" data-testid="incidents-title">Incidents 事件</h1>
        <p class="page-subtitle">只展示由 XDR/规则关联形成的攻击链事件，用于分诊、复核证据和闭环处置。</p>
      </div>
      <div class="incident-summary">
        <span>{{ summary.critical }} 严重</span>
        <span>{{ summary.high }} 高危</span>
        <span>{{ summary.open }} 待闭环</span>
      </div>
    </section>

    <section class="surface-card filter-card">
      <div class="filter-row">
        <el-select v-model="filters.severity" clearable placeholder="严重度" style="width: 140px" @change="loadIncidents">
          <el-option label="严重" value="critical" />
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>
        <el-select v-model="filters.status" clearable placeholder="处置状态" style="width: 150px" @change="loadIncidents">
          <el-option label="新发" value="new" />
          <el-option label="待确认" value="open" />
          <el-option label="已分诊" value="triaged" />
          <el-option label="处理中" value="processing" />
          <el-option label="已解决" value="resolved" />
          <el-option label="已关闭" value="closed" />
        </el-select>
        <el-input v-model="searchQuery" clearable placeholder="搜索资产、实体、规则" style="max-width: 280px" />
        <span class="auto-load-note">列表自动就绪，详情按需加载</span>
      </div>
    </section>

    <div v-if="error" class="page-state error" data-testid="incidents-error-state">
      <span>{{ error }}</span>
      <el-button type="primary" plain data-testid="incidents-retry" @click="loadIncidents">重试加载</el-button>
    </div>

    <div v-if="statusActionError" class="page-state error" data-testid="incident-status-error">
      <span>{{ statusActionError }}</span>
      <el-button v-if="statusActionRetry" type="primary" plain @click="retryStatusAction">重试操作</el-button>
    </div>
    <div v-if="statusActionFeedback" class="page-state">{{ statusActionFeedback }}</div>

    <section class="incidents-grid">
      <article class="surface-card incident-list-card">
        <div class="card-header">
          <div>
            <h2 class="card-title">攻击链列表</h2>
            <p class="card-caption">Incident 必须来自关联链，不把单条普通事件升级为 Incident</p>
          </div>
          <span class="status-badge info">{{ filteredIncidents.length }} 条</span>
        </div>

        <div v-if="!loading && filteredIncidents.length === 0" class="table-state" data-testid="incidents-empty-state">暂无匹配 Incident</div>
        <button
          v-for="incident in filteredIncidents"
          :key="incident.id"
          type="button"
          class="incident-row"
          :class="{ active: selectedIncident?.id === incident.id }"
          data-testid="incident-row"
          @click="selectIncident(incident)"
        >
          <span class="risk-badge" :class="incident.severity">{{ severityText(incident.severity) }}</span>
          <span class="incident-main">
            <strong>{{ incident.title }}</strong>
            <em v-if="incidentSubtitle(incident)">{{ incidentSubtitle(incident) }}</em>
          </span>
          <span class="status-badge" :class="statusClass(incident.status)">{{ statusText(incident.status) }}</span>
        </button>
      </article>

      <article class="surface-card incident-detail-card" data-testid="incident-detail">
        <template v-if="selectedIncident">
          <div class="card-header">
            <div>
              <h2 class="card-title">{{ selectedIncident.title }}</h2>
              <p class="card-caption">{{ detailCaption(selectedIncident) }}</p>
            </div>
            <div class="detail-badges">
              <span class="risk-badge" :class="selectedIncident.severity">{{ severityText(selectedIncident.severity) }}</span>
              <span class="status-badge" :class="statusClass(selectedIncident.status)">{{ statusText(selectedIncident.status) }}</span>
            </div>
          </div>

          <div class="response-actions">
            <button type="button" class="response-action" :disabled="statusUpdating" @click="updateIncidentStatus('triaged')">标记已分诊</button>
            <button type="button" class="response-action" :disabled="statusUpdating" @click="updateIncidentStatus('processing')">进入处置</button>
            <button type="button" class="response-action critical" :disabled="statusUpdating" @click="updateIncidentStatus('resolved')">标记解决</button>
          </div>

          <section class="detail-section">
            <h3>攻击链阶段</h3>
            <div v-if="stageEvidenceGroups(selectedIncident).length === 0" class="table-state">暂无阶段证据，等待 XDR 关联输出。</div>
            <div v-else class="stage-list" data-testid="incident-stage-list">
              <div v-for="stage in stageEvidenceGroups(selectedIncident)" :key="stage.id" class="stage-item">
                <span class="stage-index">{{ stage.shortCode || 'XDR' }}</span>
                <div class="stage-copy">
                  <small>{{ stage.tactic || 'XDR Detection' }}</small>
                  <strong>{{ stage.name }}</strong>
                  <div class="stage-evidence-list">
                    <p v-for="item in stage.evidence" :key="item.id" class="stage-evidence-item">
                      <time>{{ formatEvidenceTime(item) }}</time>
                      <span>{{ item.summary || item.title || '暂无证据说明' }}</span>
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </template>
        <div v-else class="table-state" data-testid="incident-detail-empty">请选择左侧 Incident 查看攻击链与证据。</div>
      </article>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { isRequestCanceled } from '../api'
import { incidentsAPI } from '../api/events'
import { normalizeIncident, normalizeIncidents, summarizeIncidents } from '../domain/incidents'
import { formatChinaDateTime } from '../shared/time'

const incidents = ref([])
const selectedIncident = ref(null)
const loading = ref(false)
const error = ref('')
const statusUpdating = ref(false)
const statusActionError = ref('')
const statusActionFeedback = ref('')
const statusActionRetry = ref(null)
const searchQuery = ref('')
const filters = ref({ severity: '', status: '' })

const severityMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const statusMap = { new: '新发', open: '待确认', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭' }

const summary = computed(() => summarizeIncidents(incidents.value))
const filteredIncidents = computed(() => {
  const query = searchQuery.value.trim().toLowerCase()
  return incidents.value.filter((incident) => {
    if (filters.value.severity && incident.severity !== filters.value.severity) return false
    if (filters.value.status && incident.status !== filters.value.status) return false
    if (!query) return true
    return [incident.title, incident.affectedAsset, incident.entityId, incident.recommendedAction]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query))
  })
})

const severityText = (severity) => severityMap[severity] || severity || '未知'
const statusText = (status) => statusMap[status] || status || '未知'
const statusClass = (status) => ['new', 'open'].includes(status) ? 'critical' : status === 'resolved' || status === 'closed' ? 'success' : 'info'

const isUnknownAsset = (value) => {
  const text = String(value || '').trim()
  return !text || text === 'unknown' || text === '未知资产' || text.startsWith('inc-') || text.startsWith('chain-')
}

const incidentSubtitle = (incident) => [incident.affectedAsset, incident.entityId].find((item) => !isUnknownAsset(item)) || ''

const detailCaption = (incident) => {
  const asset = incidentSubtitle(incident)
  const created = incident.createdAt ? formatChinaDateTime(incident.createdAt) : ''
  const updated = incident.updatedAt ? formatChinaDateTime(incident.updatedAt) : ''
  const timeText = created ? `首次发现 ${created}${updated ? ` · 最近更新 ${updated}` : ''}` : 'XDR 关联链事件'
  return [asset, timeText].filter(Boolean).join(' · ')
}

const fallbackStageGroups = (incident) => incident.stages.map((stage) => ({
  ...stage,
  evidence: incident.evidence.filter((item) => item.stage && item.stage === stage.id),
})).filter((stage) => stage.evidence.length)

const stageEvidenceGroups = (incident) => {
  if (!incident) return []
  if (incident.stageGroups?.length) return incident.stageGroups
  return fallbackStageGroups(incident)
}

const formatEvidenceTime = (item) => item.time ? formatChinaDateTime(item.time) : '时间待补全'

const selectIncident = async (incident) => {
  selectedIncident.value = incident
  try {
    const detail = await incidentsAPI.detail(incident.id)
    selectedIncident.value = normalizeIncident({
      ...incident,
      ...(detail.incident || {}),
      evidence: detail.evidence.length > 0 ? detail.evidence : incident.evidence,
      stages: detail.stages.length > 0 ? detail.stages : incident.stages,
      stage_groups: detail.stageGroups?.length > 0 ? detail.stageGroups : incident.stageGroups,
    })
  } catch (err) {
    if (!isRequestCanceled(err)) {
      statusActionError.value = err?.message || 'Incident 详情加载失败，已保留列表摘要。'
    }
  }
}

const loadIncidents = async () => {
  loading.value = true
  error.value = ''
  statusActionError.value = ''
  try {
    const { items } = await incidentsAPI.list({
      severity: filters.value.severity || undefined,
      status: filters.value.status || undefined,
      limit: 20,
      offset: 0,
    })
    incidents.value = normalizeIncidents(items)
    if (incidents.value.length === 0) {
      selectedIncident.value = null
    } else if (!selectedIncident.value || !incidents.value.some((item) => item.id === selectedIncident.value.id)) {
      selectedIncident.value = incidents.value[0]
      window.requestIdleCallback?.(() => selectIncident(incidents.value[0]))
    }
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err?.message || 'Incidents 加载失败'
      incidents.value = []
      selectedIncident.value = null
    }
  } finally {
    loading.value = false
  }
}

const statusActionMessage = (err) => `Operation failed: ${err?.message || 'Incident 状态更新失败'}`

const updateIncidentStatus = async (nextStatus) => {
  if (!selectedIncident.value?.id || selectedIncident.value.status === nextStatus) return
  const incidentId = selectedIncident.value.id
  const previousStatus = selectedIncident.value.status
  statusUpdating.value = true
  statusActionError.value = ''
  statusActionFeedback.value = ''
  statusActionRetry.value = null
  selectedIncident.value.status = nextStatus
  const listTarget = incidents.value.find((item) => item.id === incidentId)
  if (listTarget) listTarget.status = nextStatus

  try {
    await incidentsAPI.updateStatus(incidentId, nextStatus)
    statusActionFeedback.value = `状态已更新：${statusText(previousStatus)} → ${statusText(nextStatus)}`
  } catch (err) {
    selectedIncident.value.status = previousStatus
    if (listTarget) listTarget.status = previousStatus
    statusActionError.value = statusActionMessage(err)
    statusActionRetry.value = { id: incidentId, status: nextStatus }
  } finally {
    statusUpdating.value = false
  }
}

const retryStatusAction = async () => {
  if (!statusActionRetry.value) return
  await updateIncidentStatus(statusActionRetry.value.status)
}

onMounted(async () => {
  await loadIncidents()
})
</script>

<style scoped>
.incidents-workbench { display: flex; flex-direction: column; gap: 18px; }
.incidents-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; }
.incident-summary, .detail-badges, .filter-row, .response-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.auto-load-note { color: #94a3b8; font-size: 12px; }
.incident-summary span { padding: 9px 12px; border: 1px solid var(--border-color); border-radius: 999px; background: rgba(15, 23, 42, 0.58); color: var(--text-secondary); font-weight: 850; }
.filter-card { padding: 16px; }
.incidents-grid { display: grid; grid-template-columns: minmax(320px, 0.9fr) minmax(0, 1.4fr); gap: 18px; }
.incident-list-card, .incident-detail-card { min-width: 0; }
.incident-row { width: 100%; display: grid; grid-template-columns: 84px minmax(0, 1fr) 96px; align-items: center; gap: 12px; margin-bottom: 10px; padding: 14px; border: 1px solid var(--border-light); border-radius: 16px; background: rgba(8, 18, 32, 0.58); color: var(--text-primary); text-align: left; cursor: pointer; transition: all var(--transition-fast); }
.incident-row:hover, .incident-row.active { transform: translateX(4px); border-color: var(--border-glow); background: rgba(56, 189, 248, 0.08); }
.incident-main { min-width: 0; display: flex; flex-direction: column; gap: 5px; }
.incident-main strong, .incident-main em { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.incident-main em { color: var(--text-muted); font-size: 12px; font-style: normal; }
.detail-section { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--border-light); }
.detail-section h3 { margin: 0 0 10px; color: var(--text-primary); }
.detail-section p { margin: 0; color: var(--text-secondary); }
.stage-list { display: flex; flex-direction: column; gap: 10px; }
.stage-item { display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 12px; align-items: stretch; padding: 14px; border: 1px solid rgba(56,189,248,.22); border-radius: 16px; background: linear-gradient(135deg, rgba(8,18,32,.78), rgba(15,23,42,.56)); }
.stage-index { display:flex; align-items:center; justify-content:center; min-height:64px; border-radius:14px; background:rgba(56,189,248,.12); border:1px solid rgba(56,189,248,.22); color:#7dd3fc; font-size:13px; font-weight:950; letter-spacing:.08em; }
.stage-copy { min-width:0; display:flex; flex-direction:column; justify-content:center; gap:5px; }
.stage-copy small { color:#38bdf8; font-size:12px; font-weight:900; letter-spacing:.08em; text-transform:uppercase; }
.stage-copy strong { color:var(--text-primary); font-size:16px; }
.stage-evidence-list { display: grid; gap: 8px; margin-top: 8px; }
.stage-evidence-item { display: grid; grid-template-columns: 154px minmax(0, 1fr); gap: 10px; align-items: start; padding: 10px 12px; border: 1px solid rgba(125,211,252,.14); border-radius: 12px; background: rgba(2, 6, 23, .34); }
.stage-evidence-item time { color:#7dd3fc; font-size:12px; font-weight:850; white-space:nowrap; }
.stage-evidence-item span { color:var(--text-secondary); font-size:13px; line-height:1.55; }
.response-action { padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 999px; background: rgba(15, 23, 42, 0.76); color: var(--text-secondary); cursor: pointer; }
.response-action.critical { border-color: var(--risk-critical-border); color: var(--risk-critical); }
.response-action:disabled { opacity: 0.55; cursor: not-allowed; }
@media (max-width: 1120px) { .incidents-hero { align-items: flex-start; flex-direction: column; } .incidents-grid { grid-template-columns: 1fr; } }
</style>
