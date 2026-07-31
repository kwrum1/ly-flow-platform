<template>
  <div class="page-shell incidents-workbench">
    <section class="incidents-hero">
      <div>
        <span class="page-kicker">Incident Workbench</span>
        <h1 class="page-title" data-testid="incidents-title">Incidents 事件</h1>
      </div>
      <div class="incident-summary">
        <span class="critical">{{ summary.critical }} 严重</span>
        <span class="high">{{ summary.high }} 高危</span>
        <span class="open">{{ summary.open }} 待闭环</span>
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

          <div class="route-summary">
            <div><span>攻击 IP</span><strong>{{ incidentSourceIPs(selectedIncident) }}</strong></div>
            <i>→</i>
            <div><span>受害 IP / 资产</span><strong>{{ incidentVictims(selectedIncident) }}</strong></div>
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
                    <div v-for="item in stage.evidence" :key="item.id" class="stage-evidence-item">
                      <time>{{ formatEvidenceTime(item) }}</time>
                      <span class="evidence-engine">{{ detectionSurfaceText(item) }}</span>
                      <span class="evidence-route">{{ evidenceRoute(item) }}</span>
                      <span class="evidence-summary">{{ item.summary || item.title || '暂无证据说明' }}</span>
                      <details>
                        <summary>原始日志</summary>
                        <pre>{{ rawEvidence(item) }}</pre>
                      </details>
                    </div>
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
const incidentSourceIPs = (incident) => incident?.sourceIPs?.filter(Boolean).join('、') || incident?.evidence?.map((item) => item.sourceIP).filter(Boolean).join('、') || '待补全'
const incidentVictims = (incident) => incident?.victimIPs?.filter(Boolean).join('、') || incidentSubtitle(incident) || incident?.evidence?.map((item) => item.targetIP).filter(Boolean).join('、') || '待补全'
const detectionSurfaceText = (item) => ({ suricata: '流量 DPI', wazuh: '日志审计', runtime: '运行时审计', yara: '病毒/文件检测', rasp: 'RASP 审计', xdr: 'XDR 关联' }[String(item?.detectionSurface || '').toLowerCase()] || item?.detectionSurface || 'XDR 关联')
const evidenceRoute = (item) => [item?.sourceIP, item?.targetIP].filter(Boolean).join(' → ') || '主机侧事件'
const rawEvidence = (item) => JSON.stringify(item?.raw || item || {}, null, 2)

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
.auto-load-note { color: #758195; font-size: 12px; }
.incident-summary span { padding: 8px 12px; border: 1px solid #dce4ef; border-radius: 4px; background: #fff; color: #445168; font-weight: 850; }
.incident-summary .critical { border-color:#f0b7b5; background:#fff2f1; color:#b42318; }
.incident-summary .high { border-color:#f4c695; background:#fff7ed; color:#b54708; }
.incident-summary .open { border-color:#a9cdf3; background:#edf6ff; color:#1769d2; }
.filter-card { padding: 16px; }
.incidents-grid { display: grid; grid-template-columns: minmax(320px, 0.9fr) minmax(0, 1.4fr); gap: 18px; }
.incident-list-card, .incident-detail-card { min-width: 0; }
.incident-row { width: 100%; display: grid; grid-template-columns: 84px minmax(0, 1fr) 96px; align-items: center; gap: 12px; margin-bottom: 8px; padding: 12px; border: 1px solid #e0e7f0; border-radius: 5px; background: #fff; color: #253148; text-align: left; cursor: pointer; transition: all var(--transition-fast); }
.incident-row:hover, .incident-row.active { transform: translateX(2px); border-color: #83b8ee; background: #f2f8ff; }
.incident-main { min-width: 0; display: flex; flex-direction: column; gap: 5px; }
.incident-main strong, .incident-main em { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.incident-main em { color: var(--text-muted); font-size: 12px; font-style: normal; }
.detail-section { margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--border-light); }
.detail-section h3 { margin: 0 0 10px; color: var(--text-primary); }
.detail-section p { margin: 0; color: var(--text-secondary); }
.stage-list { display: flex; flex-direction: column; gap: 10px; }
.stage-item { display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 12px; align-items: stretch; padding: 12px; border: 1px solid #dce6f2; border-radius: 5px; background: #f8fbff; }
.stage-index { display:flex; align-items:center; justify-content:center; min-height:64px; border-radius:4px; background:#e5f2ff; border:1px solid #b8d7f5; color:#1769d2; font-size:13px; font-weight:950; }
.stage-copy { min-width:0; display:flex; flex-direction:column; justify-content:center; gap:5px; }
.stage-copy small { color:#1769d2; font-size:12px; font-weight:900; text-transform:uppercase; }
.stage-copy strong { color:var(--text-primary); font-size:16px; }
.stage-evidence-list { display: grid; gap: 8px; margin-top: 8px; }
.stage-evidence-item { display: grid; grid-template-columns: 145px 92px minmax(120px,.7fr) minmax(180px,1.3fr); gap: 8px; align-items: center; padding: 9px 10px; border: 1px solid #e0e7f0; border-radius: 4px; background: #fff; }
.stage-evidence-item time { color:#53627a; font-size:11px; font-weight:750; white-space:nowrap; }
.stage-evidence-item span { color:#445168; font-size:12px; line-height:1.45; }
.stage-evidence-item .evidence-engine{display:inline-flex;align-items:center;justify-content:center;padding:3px 6px;border-radius:3px;background:#e8f3ff;color:#1769d2;font-weight:750}.stage-evidence-item .evidence-route{font-family:ui-monospace,monospace;color:#334155}.stage-evidence-item details{grid-column:1/-1}.stage-evidence-item summary{width:max-content;color:#1769d2;font-size:11px;cursor:pointer}.stage-evidence-item pre{max-height:180px;margin:8px 0 0;padding:10px;overflow:auto;border:1px solid #dce4ef;border-radius:4px;background:#f5f7fa;color:#273449;font-size:11px;white-space:pre-wrap;word-break:break-all}
.response-action { padding: 8px 12px; border: 1px solid #d6dfeb; border-radius: 4px; background: #fff; color: #40506a; cursor: pointer; }
.route-summary{display:grid;grid-template-columns:minmax(0,1fr) 28px minmax(0,1fr);align-items:center;margin-top:14px;padding:11px 14px;border:1px solid #cfe0f2;border-radius:5px;background:#f3f8fe}.route-summary>div{display:grid;gap:4px}.route-summary>div:last-child{text-align:right}.route-summary span{color:#758195;font-size:11px}.route-summary strong{overflow:hidden;text-overflow:ellipsis;color:#243149;font-family:ui-monospace,monospace;font-size:12px}.route-summary i{text-align:center;color:#2782e8;font-style:normal;font-weight:900}
.response-action.critical { border-color: var(--risk-critical-border); color: var(--risk-critical); }
.response-action:disabled { opacity: 0.55; cursor: not-allowed; }
@media (max-width: 1120px) { .incidents-hero { align-items: flex-start; flex-direction: column; } .incidents-grid { grid-template-columns: 1fr; } }
</style>
