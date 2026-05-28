const ACKNOWLEDGED_STATUSES = new Set(['open', 'processing', 'resolved', 'closed', 'blocked', 'allowed'])
const RESOLVED_STATUSES = new Set(['resolved', 'closed', 'blocked', 'allowed'])
const PIPELINE_STAGE_LABELS = {
  queued: '待确认',
  handling: '处理中',
  resolved: '已闭环',
}
const HANDLING_STATUSES = new Set(['processing'])

const toTimestamp = (value) => {
  if (!value) return 0
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 0
  return date.getTime()
}

const pickTimestamp = (source, keys = []) => {
  for (const key of keys) {
    const ts = toTimestamp(source?.[key])
    if (ts > 0) return ts
  }
  return 0
}

const normalizeStatus = (value) => String(value || '').toLowerCase()

export function computeLifecycleDurations(event = {}) {
  const status = normalizeStatus(event.status)
  const createdAt = pickTimestamp(event, ['created_at', 'timestamp', 'time', 'occurred_at'])

  const acknowledgedAt = pickTimestamp(event, [
    'acknowledged_at',
    'ack_at',
    'first_response_at',
    'triaged_at',
    'processing_at',
    'opened_at',
  ]) || (ACKNOWLEDGED_STATUSES.has(status) ? pickTimestamp(event, ['updated_at']) : 0)

  const resolvedAt = pickTimestamp(event, [
    'resolved_at',
    'closed_at',
    'handled_at',
    'completed_at',
  ]) || (RESOLVED_STATUSES.has(status) ? pickTimestamp(event, ['updated_at']) : 0)

  const mttaMs = createdAt > 0 && acknowledgedAt >= createdAt
    ? acknowledgedAt - createdAt
    : null

  const mttrMs = createdAt > 0 && resolvedAt >= createdAt
    ? resolvedAt - createdAt
    : null

  return {
    createdAt,
    acknowledgedAt,
    resolvedAt,
    mttaMs,
    mttrMs,
    hasAcknowledgement: mttaMs !== null,
    hasResolution: mttrMs !== null,
  }
}

const average = (values) => {
  if (!Array.isArray(values) || values.length === 0) return null
  const total = values.reduce((sum, value) => sum + value, 0)
  return total / values.length
}

export function aggregateLifecycleMetrics(events = []) {
  const mttaSamples = []
  const mttrSamples = []

  events.forEach((event) => {
    const metrics = computeLifecycleDurations(event)
    if (metrics.mttaMs !== null) mttaSamples.push(metrics.mttaMs)
    if (metrics.mttrMs !== null) mttrSamples.push(metrics.mttrMs)
  })

  return {
    mttaMs: average(mttaSamples),
    mttrMs: average(mttrSamples),
    mttaSampleCount: mttaSamples.length,
    mttrSampleCount: mttrSamples.length,
  }
}

export function normalizePipelineStage(status) {
  const normalizedStatus = normalizeStatus(status)
  if (RESOLVED_STATUSES.has(normalizedStatus)) return 'resolved'
  if (HANDLING_STATUSES.has(normalizedStatus)) return 'handling'
  return 'queued'
}

export function stageLabel(stage) {
  return PIPELINE_STAGE_LABELS[stage] || PIPELINE_STAGE_LABELS.queued
}

export function aggregateStatusPipeline(events = []) {
  const summary = {
    queued: 0,
    handling: 0,
    resolved: 0,
  }

  events.forEach((event) => {
    const stage = normalizePipelineStage(event?.status)
    summary[stage] += 1
  })

  return summary
}

export function formatDurationLabel(durationMs) {
  if (durationMs === null || durationMs === undefined || !Number.isFinite(durationMs)) return '不可得'
  if (durationMs <= 0) return '0分钟'

  const totalMinutes = Math.round(durationMs / 60000)
  if (totalMinutes < 60) return `${totalMinutes}分钟`

  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  if (hours < 24) return `${hours}小时${minutes}分钟`

  const days = Math.floor(hours / 24)
  const remainingHours = hours % 24
  return `${days}天${remainingHours}小时`
}
