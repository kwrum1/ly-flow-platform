export const API_ERROR_CODES = {
  UNAUTHORIZED: 'API_UNAUTHORIZED',
  PASSWORD_CHANGE_REQUIRED: 'API_PASSWORD_CHANGE_REQUIRED',
  ACCOUNT_LOCKED: 'API_ACCOUNT_LOCKED',
  TIMEOUT: 'API_TIMEOUT',
  ENVELOPE_INVALID: 'API_ENVELOPE_INVALID',
  REQUEST_CANCELED: 'API_REQUEST_CANCELED',
  NETWORK: 'API_NETWORK_ERROR',
  UNKNOWN: 'API_UNKNOWN_ERROR',
}

export function createAPIError({ code = API_ERROR_CODES.UNKNOWN, message = '请求失败', status, details, cause } = {}) {
  const error = new Error(message)
  error.name = 'APIError'
  error.code = code
  if (status !== undefined) error.status = status
  if (details !== undefined) error.details = details
  if (cause !== undefined) error.cause = cause
  return error
}

export function isAPIError(error) {
  return Boolean(error && error.name === 'APIError' && typeof error.code === 'string')
}

export function toAPIError(error) {
  if (isAPIError(error)) return error
  return createAPIError({
    code: API_ERROR_CODES.UNKNOWN,
    message: error?.message || '请求失败',
    cause: error,
  })
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function isSuccessCode(code) {
  return code === 0 || code === 200 || code === '0' || code === '200'
}

export function unwrapAPIEnvelope(payload) {
  if (payload == null) return {}
  if (typeof payload !== 'object') return payload

  const hasCode = hasOwn(payload, 'code')
  const hasData = hasOwn(payload, 'data')

  if (!hasCode) {
    if (hasData) return payload.data
    return payload
  }

  if (isSuccessCode(payload.code)) {
    if (hasData) return payload.data
    return {}
  }

  throw createAPIError({
    code: `API_BUSINESS_${String(payload.code)}`,
    message: payload.message || payload.msg || '业务请求失败',
    details: { payload },
  })
}

export function normalizeList(payload, aliases = ['items', 'events', 'list']) {
  const body = unwrapAPIEnvelope(payload)
  if (Array.isArray(body)) return { items: body, total: body.length }

  const items = aliases.reduce((found, key) => {
    if (found.length > 0) return found
    return Array.isArray(body?.[key]) ? body[key] : found
  }, [])
  const total = Number.isFinite(body?.total) ? body.total : items.length
  return { items, total }
}

export function normalizeEventList(payload) {
  return normalizeList(payload, ['items', 'events', 'list'])
}

export function normalizeEventDetail(payload) {
  const body = unwrapAPIEnvelope(payload)
  const event = body?.event || body?.item || body || null
  const relatedRaw = body?.related || body?.related_events || []
  const related = Array.isArray(relatedRaw) ? relatedRaw : []
  return { event, related }
}

export function normalizeIncidentList(payload) {
  return normalizeList(payload, ['items', 'incidents', 'list'])
}

export function normalizeIncidentDetail(payload) {
  const body = unwrapAPIEnvelope(payload)
  const incident = body?.incident || body?.item || body || null
  const evidenceRaw = body?.evidence || incident?.evidence || []
  const stagesRaw = body?.stages || incident?.stages || incident?.attack_chain || incident?.chain || []
  const stageGroupsRaw = body?.stage_groups || incident?.stage_groups || []

  return {
    incident,
    evidence: Array.isArray(evidenceRaw) ? evidenceRaw : [],
    stages: Array.isArray(stagesRaw) ? stagesRaw : [],
    stageGroups: Array.isArray(stageGroupsRaw) ? stageGroupsRaw : [],
  }
}

export function normalizeAuthPayload(payload) {
  const body = unwrapAPIEnvelope(payload)
  const user = body?.user || null
  return {
    token: body?.token || '',
    expiresAt: body?.expires_at || body?.expiresAt || null,
    needsPasswordChange: Boolean(body?.needs_password_change || body?.needsPasswordChange || user?.needs_password_change || user?.needsPasswordChange),
    locked: Boolean(body?.locked || body?.account_locked || body?.accountLocked || user?.locked || user?.account_locked || user?.accountLocked),
    user,
  }
}

export function normalizeEmptyStateList(payload, aliases = ['items', 'events', 'list']) {
  const body = unwrapAPIEnvelope(payload)
  const normalized = normalizeList(body, aliases)
  const emptyState = body?.empty_state || body?.emptyState || null

  return {
    ...normalized,
    emptyState: normalized.items.length === 0 ? emptyState : null,
  }
}

function numberOrNull(value) {
  if (value === undefined || value === null || value === '') return null
  const number = Number(value)
  return Number.isFinite(number) ? number : null
}

function firstValue(source, keys) {
  for (const key of keys) {
    if (source?.[key] !== undefined && source?.[key] !== null && source?.[key] !== '') return source[key]
  }
  return null
}

export function normalizeAssetOpsMetrics(asset = {}, now = Date.now()) {
  const lastUpdatedAt = firstValue(asset, ['metrics_updated_at', 'last_metrics_at', 'last_heartbeat', 'last_seen'])
  const timestamp = lastUpdatedAt ? new Date(lastUpdatedAt).getTime() : 0
  const stale = timestamp > 0 ? now - timestamp > 5 * 60 * 1000 : true

  return {
    cpuModel: firstValue(asset, ['cpu_model', 'cpu']) || null,
    cpuUsagePercent: numberOrNull(firstValue(asset, ['cpu_usage_percent', 'cpu_percent'])),
    memoryTotalMb: numberOrNull(firstValue(asset, ['memory_total_mb', 'memory_mb'])),
    memoryUsedMb: numberOrNull(firstValue(asset, ['memory_used_mb'])),
    memoryUsagePercent: numberOrNull(firstValue(asset, ['memory_usage_percent', 'memory_percent'])),
    diskTotalGb: numberOrNull(firstValue(asset, ['disk_total_gb', 'disk_gb'])),
    diskUsedGb: numberOrNull(firstValue(asset, ['disk_used_gb'])),
    diskUsagePercent: numberOrNull(firstValue(asset, ['disk_usage_percent', 'disk_percent'])),
    os: firstValue(asset, ['os']) || null,
    arch: firstValue(asset, ['arch']) || null,
    agentVersion: firstValue(asset, ['agent_version']) || null,
    lastUpdatedAt: lastUpdatedAt || null,
    stale,
  }
}
