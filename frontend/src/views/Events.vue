<template>
  <div class="page-shell events-workbench">
    <section class="events-hero">
      <div>
        <span class="page-kicker">Attack Queue</span>
        <h1
          class="page-title"
          data-testid="attack-queue-title"
        >攻击队列</h1>
        <p class="page-subtitle">
          将统一事件改造成可执行工作台：先处理严重/高危/新发事件，再进入详情页查看证据链。
        </p>
      </div>
      <div class="queue-summary">
        <span>{{ summary.critical }} 严重</span>
        <span>{{ summary.high }} 高危</span>
        <span>{{ summary.open }} 待确认</span>
      </div>
    </section>

    <section class="surface-card metrics-card">
      <div class="metrics-row">
        <div class="metric-pill">
          <span>MTTA</span>
          <strong>{{ lifecycleMetrics.mttaLabel }}</strong>
          <em>{{ lifecycleMetrics.mttaSamples }} 条有效样本</em>
        </div>
        <div class="metric-pill">
          <span>MTTR</span>
          <strong>{{ lifecycleMetrics.mttrLabel }}</strong>
          <em>{{ lifecycleMetrics.mttrSamples }} 条有效样本</em>
        </div>
        <div class="metric-pill metric-pipeline">
          <span>处置状态管线</span>
          <strong>{{ lifecycleMetrics.pipelineLabel }}</strong>
          <em>按事件状态自动归档，缺失状态归入待确认</em>
        </div>
      </div>
    </section>

    <section class="surface-card filter-card">
      <div class="filter-row">
        <button
          v-for="preset in presets"
          :key="preset.key"
          type="button"
          class="ghost-button"
          :class="{ active: activePreset === preset.key }"
          @click="applyPreset(preset.key)"
        >{{ preset.label }}</button>
        <el-select
          v-model="filters.severity"
          clearable
          placeholder="严重度"
          style="width: 140px"
          @change="loadEvents"
        >
          <el-option label="严重" value="critical" />
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
          <el-option label="低危" value="low" />
        </el-select>
        <el-select
          v-model="filters.sourceModule"
          clearable
          placeholder="source_module"
          style="width: 150px"
          @change="loadEvents"
        >
          <el-option label="DPI" value="dpi" />
          <el-option label="Runtime" value="runtime" />
          <el-option label="RASP" value="rasp" />
          <el-option label="XDR" value="xdr" />
        </el-select>
        <el-input
          v-model="searchQuery"
          clearable
          placeholder="搜索 IP、域名、规则、实体"
          style="max-width: 260px"
        />
        <el-button
          type="primary"
          @click="loadEvents"
        >刷新队列</el-button>
      </div>
    </section>

    <div
      v-if="error"
      class="page-state error"
      data-testid="attack-queue-error-state"
    >
      <span>{{ error }}</span>
      <el-button
        type="primary"
        plain
        data-testid="attack-queue-retry"
        @click="loadEvents"
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

    <section class="surface-card queue-card">
      <div class="card-header">
        <div>
          <h2 class="card-title">处置优先级</h2>
          <p class="card-caption">点击行进入 /events/:id，保留原有路由习惯</p>
        </div>
        <div class="header-statuses">
          <RealtimeStatus :status="realtimeStatus" />
          <span
            v-if="newEventCount > 0"
            class="status-badge warning"
          >{{ newEventCount }} 条新增</span>
          <span class="status-badge info">{{ pagination.total }} 条</span>
        </div>
      </div>

      <div
        class="queue-table"
        data-testid="attack-queue-list"
      >
        <div class="queue-head">
          <span>优先级</span>
          <span>事件与证据</span>
          <span>source_module</span>
          <span>Entity / Raw Ref</span>
          <span>攻击路径</span>
          <span>状态</span>
          <span>时间</span>
        </div>
        <button
          v-for="event in visibleEvents"
          :key="event.id || `${event.timestamp}-${event.srcIp || event.src_ip}`"
          type="button"
          class="queue-row"
          data-testid="attack-queue-row"
          :data-priority="priorityOf(event)"
          @click="handleRowClick(event)"
        >
          <span class="priority-cell">
            <strong data-testid="attack-queue-priority">{{ priorityOf(event) }}</strong>
            <em class="risk-badge" :class="event.severity">{{ severityText(event.severity) }}</em>
          </span>
          <span class="event-cell">
            <strong>{{ eventTitle(event) }}</strong>
            <em>
              {{ maskedDetail(event).value || event.ruleName || event.rule_name || '等待分析确认' }}
              <small v-if="maskedDetail(event).masked">（已脱敏）</small>
            </em>
          </span>
          <span class="source-cell">
            <span class="status-badge source" :class="`source-${sourceClass(event.source)}`">{{ sourceLabel(event.source) }}</span>
          </span>
          <span class="entity-cell mono">
            <strong>{{ event.entityId || '-' }}</strong>
            <em>{{ event.rawReference || 'raw_reference: -' }}</em>
          </span>
          <span class="path-cell mono">{{ event.srcIp || event.src_ip || '-' }} → {{ event.dstIp || event.dst_ip || event.domain || '-' }}</span>
          <span class="status-cell">
            <span class="status-badge" :class="statusClass(event.status)">{{ statusText(event.status) }}</span>
            <span class="status-actions">
              <span
                v-if="canMarkOpen(event)"
                class="status-action"
                :class="{ disabled: isStatusUpdating(event.id) }"
                role="button"
                tabindex="0"
                @click.stop="!isStatusUpdating(event.id) && updateEventStatus(event, 'open')"
              >确认</span>
              <span
                v-if="canMarkProcessing(event)"
                class="status-action"
                :class="{ disabled: isStatusUpdating(event.id) }"
                role="button"
                tabindex="0"
                @click.stop="!isStatusUpdating(event.id) && updateEventStatus(event, 'processing')"
              >处理中</span>
              <span
                v-if="canClose(event)"
                class="status-action danger"
                :class="{ disabled: isStatusUpdating(event.id) }"
                role="button"
                tabindex="0"
                @click.stop="!isStatusUpdating(event.id) && updateEventStatus(event, 'closed')"
              >关闭</span>
            </span>
          </span>
          <span class="time-cell">{{ formatTime(event.timestamp) }}</span>
        </button>
        <div
          v-if="loading"
          class="table-state"
        >加载攻击队列中...</div>
        <div
          v-else-if="visibleEvents.length === 0"
          class="table-state"
          data-testid="attack-queue-empty-state"
        >暂无匹配事件</div>
      </div>

      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @size-change="loadEvents"
        @current-change="loadEvents"
      />
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { isRequestCanceled } from '../api'
import { eventsAPI } from '../api/events'
import RealtimeStatus from '../components/RealtimeStatus.vue'
import {
  normalizeAttackQueueItems,
  dedupeAttackQueueItems,
  computePriorityInputs,
} from '../domain/attack-queue'
import { aggregateLifecycleMetrics, aggregateStatusPipeline, formatDurationLabel } from '../domain/ops-metrics'
import { CONNECTION_STATUS, createRealtimeGateway } from '../realtime'
import { sanitizeSensitiveValue } from '../utils/security-display'
import { formatChinaDateTime } from '../shared/time'

const router = useRouter()
const events = ref([])
const loading = ref(false)
const error = ref('')
const statusActionError = ref('')
const statusActionFeedback = ref('')
const statusActionRetry = ref(null)
const statusUpdatingMap = ref({})
const searchQuery = ref('')
const activePreset = ref('p1')
const filters = ref({ severity: '', sourceModule: '', dateRange: null })
const pagination = ref({ page: 1, size: 20, total: 0 })
const realtimeStatus = ref(CONNECTION_STATUS.IDLE)
const newEventCount = ref(0)
let realtimeGateway = null
let disposeRealtimeMessage = null

const presets = [
  { key: 'p1', label: 'P1/P2 优先' },
  { key: 'new', label: '新发待确认' },
  { key: 'all', label: '全部事件' }
]

const severityMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const statusMap = { new: '新发', open: '待确认', processing: '处理中', closed: '已关闭', resolved: '已解决' }
const sourceMetaMap = {
  events: { label: 'DPI', className: 'events' },
  unified: { label: 'Runtime', className: 'unified' },
  xdr: { label: 'XDR', className: 'xdr' },
  rasp: { label: 'RASP', className: 'rasp' },
}

const unwrapEvents = (payload) => {
  if (payload == null) return []
  if (Array.isArray(payload)) return payload
  const body = payload?.data ?? payload
  if (Array.isArray(body)) return body
  if (Array.isArray(body?.items)) return body.items
  if (Array.isArray(body?.events)) return body.events
  if (Array.isArray(body?.list)) return body.list
  return []
}

const toTimestampValue = (value) => {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 0
  return date.getTime()
}

const withPriorityInputs = (event) => ({
  ...event,
  priorityInputs: computePriorityInputs(event)
})

const compareByPriority = (a, b) => {
  const aPriority = a.priorityInputs || computePriorityInputs(a)
  const bPriority = b.priorityInputs || computePriorityInputs(b)

  if (bPriority.severityScore !== aPriority.severityScore) {
    return bPriority.severityScore - aPriority.severityScore
  }

  if (bPriority.isUnresolved !== aPriority.isUnresolved) {
    return Number(bPriority.isUnresolved) - Number(aPriority.isUnresolved)
  }

  if (bPriority.sourceWeight !== aPriority.sourceWeight) {
    return bPriority.sourceWeight - aPriority.sourceWeight
  }

  const timestampDiff = toTimestampValue(b.timestamp) - toTimestampValue(a.timestamp)
  if (timestampDiff !== 0) return timestampDiff

  const aTail = `${a.source}:${a.id}:${a.ruleName}:${a.srcIp}:${a.dstIp}`
  const bTail = `${b.source}:${b.id}:${b.ruleName}:${b.srcIp}:${b.dstIp}`
  return aTail.localeCompare(bTail)
}

const normalizeQueueItems = (rawBySource) => dedupeAttackQueueItems(normalizeAttackQueueItems(rawBySource))
  .map(withPriorityInputs)
  .sort(compareByPriority)

const toRawBySource = (payload) => {
  const rawBySource = {
    '/events': [],
    '/unified/events': [],
    '/xdr/events': [],
    '/rasp/events': [],
  }

  if (payload == null) return rawBySource

  if (Array.isArray(payload)) {
    rawBySource['/events'] = payload
    return rawBySource
  }

  if (typeof payload !== 'object') return rawBySource

  const sourceCandidates = [
    ['/events', payload['/events'] ?? payload.events],
    ['/unified/events', payload['/unified/events'] ?? payload.unified],
    ['/xdr/events', payload['/xdr/events'] ?? payload.xdr],
    ['/rasp/events', payload['/rasp/events'] ?? payload.rasp],
  ]

  let hasSourceBatch = false
  for (const [sourceKey, sourcePayload] of sourceCandidates) {
    const sourceItems = unwrapEvents(sourcePayload)
    if (sourceItems.length > 0) {
      rawBySource[sourceKey] = sourceItems
      hasSourceBatch = true
    }
  }

  if (hasSourceBatch) return rawBySource

  const sourceToken = String(payload.source || payload.provider || payload.stream || payload.channel || '').toLowerCase()
  const sourcePathMap = {
    unified: '/unified/events',
    xdr: '/xdr/events',
    rasp: '/rasp/events',
    events: '/events',
    event: '/events',
    dpi: '/events',
    runtime: '/events',
  }

  const sourcePath = sourcePathMap[sourceToken] || '/events'
  const fallbackItems = unwrapEvents(payload)
  rawBySource[sourcePath] = fallbackItems.length > 0 ? fallbackItems : [payload]
  return rawBySource
}

const matchesCurrentFilters = (event) => {
  if (activePreset.value === 'p1') {
    const priority = event.priorityInputs || computePriorityInputs(event)
    if (!(priority.severityScore >= 3 && priority.isUnresolved)) return false
  }

  if (activePreset.value === 'new' && !['new', 'open'].includes(event.status)) {
    return false
  }

  if (filters.value.severity && event.severity !== filters.value.severity) {
    return false
  }

  if (filters.value.sourceModule) {
    const typeFilter = String(filters.value.sourceModule).toLowerCase()
    const sourceToken = String(event.source || '').toLowerCase()
    const eventTypeToken = String(event.eventType || '').toLowerCase()
    if (typeFilter !== sourceToken && typeFilter !== eventTypeToken) {
      return false
    }
  }

  const query = searchQuery.value.trim().toLowerCase()
  if (!query) return true

  return [event.title, event.detail, event.ruleName, event.eventType, event.srcIp, event.dstIp, event.domain, event.entityId, event.rawReference]
    .filter(Boolean)
    .some(value => String(value).toLowerCase().includes(query))
}

const visibleEvents = computed(() => events.value
  .filter(matchesCurrentFilters)
  .slice()
  .sort(compareByPriority))

const summary = computed(() => ({
  critical: events.value.filter(event => event.severity === 'critical').length,
  high: events.value.filter(event => event.severity === 'high').length,
  open: events.value.filter(event => ['new', 'open'].includes(event.status)).length
}))

const lifecycleMetrics = computed(() => {
  const metrics = aggregateLifecycleMetrics(events.value)
  const pipeline = aggregateStatusPipeline(events.value)
  return {
    mttaLabel: formatDurationLabel(metrics.mttaMs),
    mttrLabel: formatDurationLabel(metrics.mttrMs),
    mttaSamples: metrics.mttaSampleCount,
    mttrSamples: metrics.mttrSampleCount,
    pipelineLabel: `${pipeline.queued} 待确认 → ${pipeline.handling} 处理中 → ${pipeline.resolved} 已闭环`,
  }
})

const eventTitle = (event) => event.title || event.eventType || event.ruleName || '安全事件'
const maskedDetail = (event) => sanitizeSensitiveValue('payload', event.detail || event.message || event.ruleName || event.rule_name || '')
const severityText = (severity) => severityMap[severity] || severity || '未知'
const statusText = (status) => statusMap[status] || status || '未知'
const statusClass = (status) => ['new', 'open'].includes(status) ? 'critical' : status === 'closed' || status === 'resolved' ? 'success' : 'info'
const sourceLabel = (source) => sourceMetaMap[source]?.label || String(source || 'DPI').toUpperCase()
const sourceClass = (source) => sourceMetaMap[source]?.className || 'events'

const isStatusUpdating = (eventId) => Boolean(statusUpdatingMap.value[eventId])
const canMarkOpen = (event) => ['new'].includes(event.status)
const canMarkProcessing = (event) => ['new', 'open'].includes(event.status)
const canClose = (event) => !['closed', 'resolved'].includes(event.status)

const statusActionMessage = (err) => {
  if (err?.status === 409 || /conflict|冲突/i.test(err?.message || '')) {
    return '状态冲突：事件状态已被其他操作更新，请刷新后重试。'
  }
  return `Operation failed: ${err?.message || '状态更新失败'}`
}

const updateEventStatus = async (event, nextStatus) => {
  if (!event?.id || event.status === nextStatus) return

  statusActionError.value = ''
  statusActionFeedback.value = ''
  statusActionRetry.value = null

  const target = events.value.find(item => item.id === event.id)
  if (!target) return

  const previousStatus = target.status
  const previousUpdatedAt = target.updated_at
  statusUpdatingMap.value = { ...statusUpdatingMap.value, [event.id]: true }

  target.status = nextStatus
  target.updated_at = new Date().toISOString()

  try {
    await eventsAPI.updateStatus(event.id, nextStatus)
    statusActionFeedback.value = `状态已更新：${statusText(previousStatus)} → ${statusText(nextStatus)}`
    await loadEvents({ preserveNotice: true })
  } catch (err) {
    target.status = previousStatus
    target.updated_at = previousUpdatedAt
    statusActionError.value = statusActionMessage(err)
    statusActionRetry.value = { eventId: event.id, nextStatus }
  } finally {
    const nextMap = { ...statusUpdatingMap.value }
    delete nextMap[event.id]
    statusUpdatingMap.value = nextMap
  }
}

const retryStatusAction = async () => {
  const retry = statusActionRetry.value
  if (!retry) return
  const event = events.value.find(item => item.id === retry.eventId)
  if (!event) {
    statusActionError.value = '状态冲突：事件已不在当前列表，请刷新后重试。'
    statusActionRetry.value = null
    return
  }
  await updateEventStatus(event, retry.nextStatus)
}

const priorityOf = (event) => {
  const priority = event.priorityInputs || computePriorityInputs(event)
  if (priority.isUnresolved && priority.severityScore >= 4) return 'P1'
  if (priority.isUnresolved && priority.severityScore >= 3) return 'P2'
  if (priority.severityScore >= 3) return 'P3'
  return 'P4'
}

const formatTime = (value) => {
  if (!value) return '-'
  const normalized = typeof value === 'number' && value < 1000000000000 ? value * 1000 : value
  const text = formatChinaDateTime(normalized)
  return text === '暂无时间' || text === '时间格式异常' ? '-' : text
}

const applyPreset = (key) => {
  activePreset.value = key
}

const handleRowClick = (row) => {
  router.push(`/events/${row.id}`)
}

const countUniqueNewItems = (incomingItems) => {
  const merged = dedupeAttackQueueItems([...events.value, ...incomingItems])
  return Math.max(0, merged.length - events.value.length)
}

const mergeEventsForView = (incomingItems) => dedupeAttackQueueItems([...incomingItems, ...events.value])
  .map(withPriorityInputs)
  .sort(compareByPriority)

const applyRealtimePayload = (payload) => {
  const incomingItems = normalizeQueueItems(toRawBySource(payload))
  if (incomingItems.length === 0) return

  const uniqueNewCount = countUniqueNewItems(incomingItems)
  if (uniqueNewCount <= 0) return

  const matchedIncoming = incomingItems.filter(matchesCurrentFilters)
  const uniqueMatchedCount = matchedIncoming.length > 0 ? countUniqueNewItems(matchedIncoming) : 0
  const uniqueHiddenCount = Math.max(0, uniqueNewCount - uniqueMatchedCount)

  if (pagination.value.page === 1 && uniqueMatchedCount > 0) {
    events.value = mergeEventsForView(matchedIncoming).slice(0, pagination.value.size)
  } else if (uniqueMatchedCount > 0) {
    newEventCount.value += uniqueMatchedCount
  }

  if (uniqueHiddenCount > 0) {
    newEventCount.value += uniqueHiddenCount
  }

  pagination.value.total += uniqueNewCount
}

const loadEvents = async ({ preserveNotice = false } = {}) => {
  loading.value = true
  error.value = ''

  try {
    const { items, total } = await eventsAPI.list({
      limit: pagination.value.size,
      offset: (pagination.value.page - 1) * pagination.value.size,
      severity: filters.value.severity || undefined,
      source_module: filters.value.sourceModule || undefined,
      event_type: filters.value.sourceModule || undefined
    })

    events.value = normalizeQueueItems({ '/events': items })
    pagination.value.total = Number.isFinite(total) ? total : events.value.length

    if (!preserveNotice) {
      newEventCount.value = 0
    }
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err?.message || '事件加载失败'
      events.value = []
      pagination.value.total = 0
    }
  } finally {
    loading.value = false
  }
}

const setupRealtime = () => {
  const realtimePath = import.meta.env.VITE_EVENTS_REALTIME_PATH || '/ws/events'
  const realtimeBase = import.meta.env.VITE_REALTIME_BASE_URL || window.location.origin
  const wsUrl = realtimePath.startsWith('ws')
    ? realtimePath
    : `${realtimeBase.replace(/^http/, 'ws').replace(/\/$/, '')}${realtimePath.startsWith('/') ? '' : '/'}${realtimePath}`

  realtimeGateway = createRealtimeGateway({
    wsUrl,
    pollingIntervalMs: 15000,
    onPoll: async () => {
      await loadEvents({ preserveNotice: true })
    },
  })

  realtimeStatus.value = realtimeGateway.getStatus()
  realtimeGateway.onStatusChange((nextStatus) => {
    realtimeStatus.value = nextStatus
  })

  disposeRealtimeMessage = realtimeGateway.onMessage((payload) => {
    applyRealtimePayload(payload)
  })

  realtimeGateway.connect()
}

onMounted(async () => {
  await loadEvents()
  setupRealtime()
})

onUnmounted(() => {
  disposeRealtimeMessage?.()
  disposeRealtimeMessage = null
  realtimeGateway?.close('view_unmounted')
  realtimeGateway = null
})
</script>

<style scoped>
.events-workbench {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.events-hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 20px;
}

.queue-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.queue-summary span {
  padding: 9px 12px;
  border: 1px solid var(--border-color);
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.58);
  color: var(--text-secondary);
  font-weight: 850;
}

.metrics-card {
  padding: 14px 16px;
}

.metrics-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.metric-pill {
  padding: 10px 12px;
  border: 1px solid var(--border-light);
  border-radius: 12px;
  background: rgba(8, 18, 32, 0.52);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.metric-pill span {
  color: var(--text-muted);
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.metric-pill strong {
  color: var(--text-primary);
  font-size: 18px;
}

.metric-pill em {
  color: var(--text-secondary);
  font-size: 12px;
  font-style: normal;
}

.metric-pill.metric-pipeline {
  grid-column: 1 / -1;
}

.metric-pill.metric-pipeline strong {
  font-size: 14px;
}

.filter-card {
  padding: 16px;
}

.filter-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}

.queue-card {
  overflow: hidden;
}

.header-statuses {
  display: flex;
  align-items: center;
  gap: 10px;
}

.queue-table {
  padding: 0 18px 18px;
}

.queue-head,
.queue-row {
  display: grid;
  grid-template-columns: 110px minmax(220px, 1.25fr) 120px minmax(180px, 0.85fr) minmax(180px, 0.85fr) 110px 130px;
  gap: 14px;
  align-items: center;
}

.queue-head {
  padding: 12px 14px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 900;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.queue-row {
  width: 100%;
  margin-bottom: 10px;
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: 16px;
  background: rgba(8, 18, 32, 0.58);
  color: var(--text-primary);
  text-align: left;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.queue-row:hover {
  transform: translateX(4px);
  border-color: var(--border-glow);
  background: rgba(56, 189, 248, 0.08);
}

.priority-cell,
.event-cell,
.entity-cell,
.source-cell {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.priority-cell strong {
  font-size: 22px;
  font-weight: 950;
  letter-spacing: -0.05em;
}

.event-cell strong {
  overflow: hidden;
  font-size: 14px;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.event-cell em,
.entity-cell em,
.time-cell {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 12px;
  font-style: normal;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.entity-cell strong {
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 12px;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.path-cell {
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 12px;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.status-cell {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}

.status-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.status-action {
  padding: 2px 6px;
  border: 1px solid var(--border-color);
  border-radius: 999px;
  font-size: 11px;
  color: var(--text-secondary);
  cursor: pointer;
}

.status-action.danger {
  border-color: var(--risk-critical-border);
  color: var(--risk-critical);
}

.status-action.disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

@media (max-width: 1120px) {
  .events-hero {
    align-items: flex-start;
    flex-direction: column;
  }

  .metrics-row {
    grid-template-columns: 1fr;
  }

  .queue-head {
    display: none;
  }

  .queue-row {
    grid-template-columns: 1fr;
  }
}
</style>
