<template>
  <div class="page-shell event-detail">
    <section class="detail-hero surface-card" v-loading="loading">
      <div v-if="event" class="detail-heading">
        <span class="page-kicker">Evidence Packet</span>
        <h1 class="page-title">{{ eventTitle }}</h1>
        <p class="page-subtitle">
          {{ event.srcIp || '未知源' }} → {{ event.dstIp || event.domain || '业务资产' }}，用于确认影响面、攻击路径和下一步处置。
        </p>
      </div>
      <div v-else class="detail-heading">
        <span class="page-kicker">Evidence Packet</span>
        <h1 class="page-title">事件详情</h1>
        <p class="page-subtitle">加载事件上下文与关联证据。</p>
      </div>
      <div v-if="event" class="detail-status">
        <span class="risk-badge" :class="event.severity">{{ severityText(event.severity) }}</span>
        <span class="status-badge source" :class="`source-${sourceClass(event.source)}`">source_module={{ sourceLabel(event.source) }}</span>
        <span class="status-badge" :class="statusClass(event.status)">{{ statusText(event.status) }}</span>
        <span class="status-badge info">管线 {{ incidentLifecycle.stageLabel }}</span>
        <span class="status-badge info">MTTA {{ incidentLifecycle.mttaLabel }}</span>
        <span class="status-badge info">MTTR {{ incidentLifecycle.mttrLabel }}</span>
      </div>
    </section>

    <div
      v-if="error"
      class="page-state error"
      data-testid="error-state"
    >
      <span>{{ error }}</span>
      <el-button
        type="primary"
        plain
        data-testid="retry-button"
        @click="loadDetail"
      >重试加载</el-button>
    </div>

    <div
      v-if="statusActionError"
      class="page-state error"
    >
      <span>{{ statusActionError }}</span>
      <el-button
        v-if="statusActionRetry"
        type="primary"
        plain
        @click="retryStatusAction"
      >重试操作</el-button>
    </div>

    <div
      v-if="statusActionFeedback"
      class="page-state"
    >{{ statusActionFeedback }}</div>
    <div
      v-else-if="!event && !loading"
      class="page-state"
      data-testid="detail-empty"
    >
      <p>未找到事件详情，可能是后端未返回详情数据。</p>
      <el-button
        type="primary"
        plain
        @click="go('/events')"
      >返回攻击队列</el-button>
    </div>

    <template v-if="event">
      <section class="detail-grid">
        <article class="surface-card evidence-card">
          <div class="card-header">
            <div>
              <h2 class="card-title">关键证据</h2>
              <p class="card-caption">安全分析师首先需要确认的信息</p>
            </div>
          </div>
          <div class="card-body evidence-list">
            <div
              v-for="item in evidenceItems"
              :key="item.label"
              class="evidence-item"
            >
              <span>{{ item.label }}</span>
              <strong>{{ item.value }}</strong>
            </div>
          </div>
        </article>

        <article class="surface-card response-card">
          <div class="card-header">
            <div>
              <h2 class="card-title">处置建议</h2>
              <p class="card-caption">保持路由稳定，动作指向已有页面</p>
            </div>
          </div>
          <div class="card-body action-stack">
            <div
              v-if="canOperateStatus"
              class="status-pipeline-actions"
            >
              <button
                v-if="canMarkOpen"
                type="button"
                class="response-action"
                :disabled="statusUpdating"
                @click="updateCurrentStatus('open')"
              >确认事件</button>
              <button
                v-if="canMarkProcessing"
                type="button"
                class="response-action"
                :disabled="statusUpdating"
                @click="updateCurrentStatus('processing')"
              >标记处理中</button>
              <button
                v-if="canClose"
                type="button"
                class="response-action critical"
                :disabled="statusUpdating"
                @click="updateCurrentStatus('closed')"
              >关闭事件</button>
            </div>
            <div
              v-else
              class="table-state detail-note"
            >仅管理员可执行处置状态变更。</div>
            <button
              type="button"
              class="response-action critical"
              @click="go('/assets')"
            >定位受影响资产</button>
            <button
              type="button"
              class="response-action"
              @click="go('/xdr')"
            >查看 XDR 关联</button>
            <button
              type="button"
              class="response-action"
              @click="go('/control')"
            >检查防护控制</button>
          </div>
        </article>
      </section>

      <section class="surface-card narrative-card">
        <div class="card-header">
          <div>
            <h2 class="card-title">事件叙事</h2>
            <p class="card-caption">把原始详情以可读证据呈现</p>
          </div>
          <span
            v-if="detailMasked"
            class="status-badge warning"
            data-testid="event-detail-mask-hint"
          >敏感字段已脱敏显示</span>
        </div>
        <div class="card-body narrative-body">
          <pre>{{ detailText }}</pre>
        </div>
      </section>

      <section
        class="surface-card audit-card"
        data-testid="event-detail-audit"
      >
        <div class="card-header">
          <div>
            <h2 class="card-title">审计轨迹</h2>
            <p class="card-caption">展示最近操作类型、时间与结果</p>
          </div>
          <span class="status-badge info">{{ recentAuditEntries.length }} 条</span>
        </div>
        <div class="timeline-list">
          <article
            v-for="entry in recentAuditEntries"
            :key="entry.id"
            class="timeline-item"
            data-testid="event-detail-audit-item"
          >
            <div class="timeline-meta">
              <span class="time-cell">{{ entry.time }}</span>
              <span class="status-badge info">{{ entry.typeLabel }}</span>
              <span class="status-badge" :class="entry.resultClass">{{ entry.resultLabel }}</span>
            </div>
            <strong class="timeline-title">{{ entry.message }}</strong>
          </article>
          <div
            v-if="recentAuditEntries.length === 0"
            class="table-state"
            data-testid="event-detail-audit-empty"
          >暂无审计轨迹。</div>
        </div>
      </section>

      <section class="surface-card related-card">
        <div class="card-header">
          <div>
            <h2 class="card-title">证据链时间线</h2>
            <p class="card-caption">按时间稳定排序，串联来源标签与上下文字段</p>
          </div>
          <span class="status-badge info">{{ timelineEntries.length }} 条</span>
        </div>
        <div
          v-if="relatedEvents.length === 0"
          class="table-state detail-note"
          data-testid="correlation-empty"
        >
          后端未提供关联事件数据，当前仅展示主事件证据；可返回攻击队列刷新或稍后重试。
        </div>
        <div
          class="timeline-list"
          data-testid="event-detail-timeline"
        >
          <article
            v-for="entry in timelineEntries"
            :key="entry.id || `${entry.timestamp}-${entry.source}-${entry.srcIp}`"
            class="timeline-item"
            data-testid="event-detail-timeline-item"
          >
            <div class="timeline-meta">
              <span class="time-cell">{{ formatTime(entry.timestamp) }}</span>
              <span
                class="status-badge source"
                :class="`source-${sourceClass(entry.source)}`"
                data-testid="event-detail-source-badge"
              >{{ sourceLabel(entry.source) }}</span>
              <span class="risk-badge" :class="entry.severity">{{ severityText(entry.severity) }}</span>
              <span class="status-badge" :class="statusClass(entry.status)">{{ statusText(entry.status) }}</span>
            </div>
            <strong class="timeline-title">{{ entry.title || entry.ruleName || entry.eventType || '-' }}</strong>
            <div class="timeline-context mono">
              <span><em>SRC</em>{{ entry.srcIp || '-' }}</span>
              <span><em>DST</em>{{ entry.dstIp || '-' }}</span>
              <span><em>DOMAIN</em>{{ entry.domain || '-' }}</span>
              <span><em>RULE</em>{{ entry.ruleName || '-' }}</span>
              <span><em>TYPE</em>{{ entry.eventType || '-' }}</span>
            </div>
          </article>
          <div
            v-if="timelineEntries.length === 0"
            class="table-state"
            data-testid="timeline-empty"
          >后端未提供可展示的时间线数据，请稍后重试或返回攻击队列。</div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { isRequestCanceled } from '../api'
import { eventsAPI } from '../api/events'
import {
  computePriorityInputs,
  dedupeAttackQueueItems,
  normalizeAttackQueueItems,
} from '../domain/attack-queue'
import { computeLifecycleDurations, formatDurationLabel, normalizePipelineStage, stageLabel } from '../domain/ops-metrics'
import { formatChinaDateTime } from '../shared/time'
import { formatMaskedJson } from '../utils/security-display'

const route = useRoute()
const router = useRouter()
const event = ref(null)
const relatedEvents = ref([])
const loading = ref(false)
const error = ref('')
const statusUpdating = ref(false)
const statusActionError = ref('')
const statusActionFeedback = ref('')
const statusActionRetry = ref(null)
const currentUserRole = ref(localStorage.getItem('role') || 'viewer')
const auditEntries = ref([])

const severityMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const statusMap = {
  new: '新发',
  open: '待确认',
  processing: '处理中',
  blocked: '已拦截',
  allowed: '已放行',
  closed: '已关闭',
  resolved: '已解决'
}
const sourceMetaMap = {
  events: { label: 'Events', className: 'events' },
  unified: { label: 'Unified', className: 'unified' },
  xdr: { label: 'XDR', className: 'xdr' },
  rasp: { label: 'RASP', className: 'rasp' },
}
const sourceOrder = { events: 0, unified: 1, xdr: 2, rasp: 3 }
const auditTypeMap = {
  load_detail: '详情加载',
  status_update: '状态变更',
}
const auditResultMap = {
  success: { label: '成功', className: 'success' },
  failed: { label: '失败', className: 'critical' },
}

const pushAuditEntry = ({ type, result, message }) => {
  const resultMeta = auditResultMap[result] || { label: result || '未知', className: 'info' }
  auditEntries.value = [
    {
      id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      typeLabel: auditTypeMap[type] || type || '操作',
      resultLabel: resultMeta.label,
      resultClass: resultMeta.className,
      message: message || '-',
      time: formatTime(new Date().toISOString()),
    },
    ...auditEntries.value,
  ].slice(0, 8)
}

const formatTime = (value) => {
  if (!value) return '-'
  const normalized = typeof value === 'number' && value < 1000000000000 ? value * 1000 : value
  const text = formatChinaDateTime(normalized)
  return text === '暂无时间' || text === '时间格式异常' ? '-' : text
}

const toTimestampValue = (value) => {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 0
  return date.getTime()
}

const sourceLabel = (source) => sourceMetaMap[source]?.label || String(source || 'Events').toUpperCase()
const sourceClass = (source) => sourceMetaMap[source]?.className || 'events'

const normalizeItemsBySource = (items = [], fallbackSource = 'events') => {
  const rawBySource = {
    '/events': [],
    '/unified/events': [],
    '/xdr/events': [],
    '/rasp/events': [],
  }

  items.forEach((item) => {
    const source = String(item?.source || item?.provider || fallbackSource || 'events').toLowerCase()
    if (source === 'unified') {
      rawBySource['/unified/events'].push(item)
      return
    }
    if (source === 'xdr') {
      rawBySource['/xdr/events'].push(item)
      return
    }
    if (source === 'rasp') {
      rawBySource['/rasp/events'].push(item)
      return
    }
    rawBySource['/events'].push(item)
  })

  return dedupeAttackQueueItems(normalizeAttackQueueItems(rawBySource)).map((item) => ({
    ...item,
    priorityInputs: computePriorityInputs(item),
  }))
}

const compareTimelineEntries = (a, b) => {
  const timestampDiff = toTimestampValue(a.timestamp) - toTimestampValue(b.timestamp)
  if (timestampDiff !== 0) return timestampDiff

  const sourceDiff = (sourceOrder[a.source] ?? 99) - (sourceOrder[b.source] ?? 99)
  if (sourceDiff !== 0) return sourceDiff

  const priorityDiff = (b.priorityInputs?.severityScore || 0) - (a.priorityInputs?.severityScore || 0)
  if (priorityDiff !== 0) return priorityDiff

  const aTail = `${a.id}:${a.ruleName}:${a.srcIp}:${a.dstIp}:${a.domain}:${a.eventType}`
  const bTail = `${b.id}:${b.ruleName}:${b.srcIp}:${b.dstIp}:${b.domain}:${b.eventType}`
  return aTail.localeCompare(bTail)
}

const eventTitle = computed(() => event.value?.title || event.value?.eventType || event.value?.ruleName || '安全事件')
const detailSecurityState = computed(() => {
  const detailSource = event.value?.detail
    ?? event.value?.payload
    ?? event.value?.commandLine
    ?? event.value?.message
    ?? '暂无详情'
  return formatMaskedJson(detailSource)
})
const detailText = computed(() => detailSecurityState.value.text)
const detailMasked = computed(() => detailSecurityState.value.masked)
const recentAuditEntries = computed(() => auditEntries.value)

const incidentLifecycle = computed(() => {
  const metrics = computeLifecycleDurations(event.value || {})
  const stage = normalizePipelineStage(event.value?.status)
  return {
    stage,
    stageLabel: stageLabel(stage),
    mttaLabel: formatDurationLabel(metrics.mttaMs),
    mttrLabel: formatDurationLabel(metrics.mttrMs),
  }
})

const timelineEntries = computed(() => {
  if (relatedEvents.value.length === 0) return []

  const chain = []
  if (event.value) chain.push(event.value)
  chain.push(...relatedEvents.value)

  return dedupeAttackQueueItems(chain)
    .map((item) => ({
      ...item,
      priorityInputs: item.priorityInputs || computePriorityInputs(item),
    }))
    .sort(compareTimelineEntries)
})

const evidenceItems = computed(() => [
  { label: '事件 ID', value: event.value?.id || route.params.id || '-' },
  { label: '发现时间', value: formatTime(event.value?.timestamp) },
  { label: '来源标签', value: sourceLabel(event.value?.source) },
  { label: 'Entity ID', value: event.value?.entityId || '-' },
  { label: 'Raw Reference', value: event.value?.rawReference || '-' },
  { label: '攻击源', value: event.value?.srcIp || '-' },
  { label: '目标资产', value: event.value?.dstIp || event.value?.domain || '-' },
  { label: '规则/类型', value: event.value?.ruleName || event.value?.eventType || '-' },
  { label: '处置状态', value: statusText(event.value?.status) },
  { label: '管线阶段', value: incidentLifecycle.value.stageLabel },
  { label: 'MTTA', value: incidentLifecycle.value.mttaLabel },
  { label: 'MTTR', value: incidentLifecycle.value.mttrLabel }
])

const severityText = (severity) => severityMap[severity] || severity || '未知'
const statusText = (status) => statusMap[status] || status || '未知'
const statusClass = (status) => ['new', 'open'].includes(status) ? 'critical' : status === 'closed' || status === 'resolved' || status === 'blocked' ? 'success' : 'info'

const canOperateStatus = computed(() => currentUserRole.value === 'admin')
const canMarkOpen = computed(() => canOperateStatus.value && ['new'].includes(event.value?.status))
const canMarkProcessing = computed(() => canOperateStatus.value && ['new', 'open'].includes(event.value?.status))
const canClose = computed(() => canOperateStatus.value && !['closed', 'resolved'].includes(event.value?.status || ''))

const statusActionMessage = (err) => {
  if (err?.status === 409 || /conflict|冲突/i.test(err?.message || '')) {
    return '状态冲突：事件状态已被其他操作更新，请刷新后重试。'
  }
  return `Operation failed: ${err?.message || '状态更新失败'}`
}

const updateCurrentStatus = async (nextStatus) => {
  if (!event.value?.id || event.value.status === nextStatus) return

  const previousStatus = event.value.status
  const previousUpdatedAt = event.value.updated_at
  statusUpdating.value = true
  statusActionError.value = ''
  statusActionFeedback.value = ''
  statusActionRetry.value = null

  event.value.status = nextStatus
  event.value.updated_at = new Date().toISOString()

  try {
    await eventsAPI.updateStatus(event.value.id, nextStatus)
    statusActionFeedback.value = `状态已更新：${statusText(previousStatus)} → ${statusText(nextStatus)}`
    pushAuditEntry({
      type: 'status_update',
      result: 'success',
      message: `状态 ${statusText(previousStatus)} → ${statusText(nextStatus)}`,
    })
    await loadDetail()
  } catch (err) {
    event.value.status = previousStatus
    event.value.updated_at = previousUpdatedAt
    statusActionError.value = statusActionMessage(err)
    statusActionRetry.value = { status: nextStatus }
    pushAuditEntry({
      type: 'status_update',
      result: 'failed',
      message: statusActionMessage(err),
    })
  } finally {
    statusUpdating.value = false
  }
}

const retryStatusAction = async () => {
  if (!statusActionRetry.value) return
  await updateCurrentStatus(statusActionRetry.value.status)
}

const go = (path) => router.push(path)

const loadDetail = async () => {
  loading.value = true
  error.value = ''
  try {
    const data = await eventsAPI.detail(route.params.id)
    const normalizedDetail = normalizeItemsBySource(data?.event ? [data.event] : [], 'events')
    event.value = normalizedDetail[0] || null

    relatedEvents.value = normalizeItemsBySource(
      Array.isArray(data?.related) ? data.related : [],
      event.value?.source || 'events'
    )

    pushAuditEntry({
      type: 'load_detail',
      result: 'success',
      message: `详情加载成功：${event.value?.id || route.params.id}`,
    })
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '事件详情加载失败'
      event.value = null
      relatedEvents.value = []
      pushAuditEntry({
        type: 'load_detail',
        result: 'failed',
        message: error.value,
      })
    }
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadDetail()
})
</script>

<style scoped>
.event-detail {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.detail-hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 20px;
  padding: 28px;
}

.detail-heading {
  min-width: 0;
}

.detail-status {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 10px;
}

.detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 18px;
}

.evidence-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.evidence-item {
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: 14px;
  background: rgba(8, 18, 32, 0.52);
}

.evidence-item span {
  display: block;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 800;
}

.evidence-item strong {
  display: block;
  overflow: hidden;
  margin-top: 6px;
  color: var(--text-primary);
  font-size: 14px;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.action-stack {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.status-pipeline-actions {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.response-action {
  min-height: 46px;
  border: 1px solid var(--border-color);
  border-radius: 14px;
  background: rgba(8, 18, 32, 0.62);
  color: var(--text-primary);
  font-weight: 850;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.response-action.critical {
  border-color: var(--risk-critical-border);
  background: var(--risk-critical-bg);
  color: var(--risk-critical);
}

.response-action:hover {
  transform: translateY(-1px);
  border-color: var(--border-glow);
}

pre {
  max-height: 360px;
  overflow: auto;
  padding: 18px;
  border: 1px solid var(--border-light);
  border-radius: 16px;
  background: rgba(3, 8, 18, 0.72);
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
}

.detail-note {
  margin: 0 18px;
  border: 1px dashed var(--border-light);
  border-radius: 14px;
  background: rgba(56, 189, 248, 0.08);
  color: var(--text-secondary);
}

.status-badge.source {
  font-weight: 800;
}

.status-badge.source-events,
.status-badge.source-unified {
  background: rgba(56, 189, 248, 0.16);
  color: #93c5fd;
}

.status-badge.source-xdr {
  background: rgba(168, 85, 247, 0.16);
  color: #d8b4fe;
}

.status-badge.source-rasp {
  background: rgba(250, 204, 21, 0.16);
  color: #fde68a;
}

.timeline-list {
  padding: 0 18px 18px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.timeline-item {
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: 14px;
  background: rgba(8, 18, 32, 0.52);
}

.timeline-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.timeline-title {
  display: block;
  margin-top: 10px;
  color: var(--text-primary);
}

.timeline-context {
  margin-top: 10px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 12px;
  color: var(--text-secondary);
  font-size: 12px;
}

.timeline-context span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.timeline-context em {
  margin-right: 8px;
  color: var(--text-muted);
  font-style: normal;
}

@media (max-width: 980px) {
  .detail-hero,
  .detail-grid {
    grid-template-columns: 1fr;
  }

  .detail-hero {
    align-items: flex-start;
    flex-direction: column;
  }

  .evidence-list,
  .timeline-context,
  .status-pipeline-actions {
    grid-template-columns: 1fr;
  }
}
</style>
