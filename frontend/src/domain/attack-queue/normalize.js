import { DEFAULT_ATTACK_QUEUE_ITEM, normalizeSeverity, normalizeStatus } from './model'

function unwrapEnvelope(payload) {
  if (payload == null) return []
  if (Array.isArray(payload)) return payload
  const body = payload?.data ?? payload
  if (Array.isArray(body)) return body
  if (Array.isArray(body?.items)) return body.items
  if (Array.isArray(body?.events)) return body.events
  if (Array.isArray(body?.list)) return body.list
  return []
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === 0) return '0'
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value)
    }
  }
  return ''
}

function toIsoTimestamp(value) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return date.toISOString()
}

function buildStableId(event) {
  return firstNonEmpty(event.id, event.uuid, event.event_id, event.alert_id, event.trace_id, event.log_id)
}

function rawReferenceOf(event) {
  const rawReference = event.raw_reference || event.rawReference || event.raw_ref || event.rawRef || event.evidence_ref || event.evidenceRef || ''
  if (typeof rawReference === 'string') return rawReference
  if (rawReference && typeof rawReference === 'object') {
    return firstNonEmpty(rawReference.capture_ref, rawReference.captureRef, rawReference.file_path, rawReference.filePath, rawReference.key, rawReference.id)
  }
  return ''
}

function mapEventToAttackQueueItem(event, source) {
  const timestamp = toIsoTimestamp(firstNonEmpty(event.timestamp, event.created_at, event.time, event.occurred_at))
  const ruleName = firstNonEmpty(event.rule_name, event.ruleName, event.attack_type, event.signature, event.risk_name)
  const title = firstNonEmpty(event.title, event.name, event.message, event.event_type, event.type, ruleName)

  return {
    ...DEFAULT_ATTACK_QUEUE_ITEM,
    id: buildStableId(event),
    source,
    timestamp,
    severity: normalizeSeverity(event.severity || event.level || event.risk_level),
    status: normalizeStatus(event.status || (event.blocked ? 'blocked' : event.allowed ? 'allowed' : 'new')),
    eventType: firstNonEmpty(event.event_type, event.type, event.attack_type, event.module, 'unknown'),
    title,
    detail: firstNonEmpty(event.detail, event.message, event.payload, event.description),
    srcIp: firstNonEmpty(event.src_ip, event.srcIp, event.source_ip, event.client_ip),
    dstIp: firstNonEmpty(event.dst_ip, event.dstIp, event.destination_ip, event.server_ip),
    domain: firstNonEmpty(event.domain, event.host, event.hostname, event.target_domain),
    ruleName,
    entityId: firstNonEmpty(event.entity_id, event.entityId, event.asset_id, event.assetId, event.agent_id, event.agentId, event.host_id, event.hostId, event.process_id, event.processId, event.session_id, event.sessionId, event.chain_id, event.chainId),
    rawReference: rawReferenceOf(event),
  }
}

function toTimeBucket(timestamp) {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return '0'
  return String(Math.floor(date.getTime() / 60000))
}

function dedupeKey(item) {
  const id = firstNonEmpty(item.id)
  if (id) return `id:${id}`

  const signature = [
    firstNonEmpty(item.ruleName),
    firstNonEmpty(item.severity),
    firstNonEmpty(item.title),
  ].join('|')

  return [
    'composite',
    firstNonEmpty(item.source),
    toTimeBucket(item.timestamp),
    firstNonEmpty(item.srcIp),
    firstNonEmpty(item.dstIp),
    firstNonEmpty(item.eventType),
    signature,
  ].join(':')
}

export function dedupeAttackQueueItems(items = []) {
  const result = []
  const seen = new Set()

  for (const item of items) {
    const key = dedupeKey(item)
    if (seen.has(key)) continue
    seen.add(key)
    result.push(item)
  }

  return result
}

export function computePriorityInputs(item = {}) {
  const severityScoreMap = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  }

  const severity = normalizeSeverity(item.severity)
  const severityScore = severityScoreMap[severity] || 1
  const hasNetworkContext = Boolean(item.srcIp || item.dstIp || item.domain)
  const isUnresolved = !['closed', 'allowed'].includes(normalizeStatus(item.status))

  return {
    severityScore,
    isUnresolved,
    hasNetworkContext,
    sourceWeight: item.source === 'xdr' || item.source === 'rasp' ? 2 : 1,
  }
}

export function normalizeAttackQueueItems(rawBySource = {}) {
  const bySource = {
    events: unwrapEnvelope(rawBySource.events ?? rawBySource['/events']),
    unified: unwrapEnvelope(rawBySource.unified ?? rawBySource['/unified/events']),
    xdr: unwrapEnvelope(rawBySource.xdr ?? rawBySource['/xdr/events']),
    rasp: unwrapEnvelope(rawBySource.rasp ?? rawBySource['/rasp/events']),
  }

  const items = []
  for (const [source, rawItems] of Object.entries(bySource)) {
    for (const event of rawItems) {
      items.push(mapEventToAttackQueueItem(event || {}, source))
    }
  }

  return dedupeAttackQueueItems(items)
}
