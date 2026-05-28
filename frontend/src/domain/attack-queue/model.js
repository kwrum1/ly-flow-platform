export const ATTACK_QUEUE_SOURCES = {
  EVENTS: 'events',
  UNIFIED: 'unified',
  XDR: 'xdr',
  RASP: 'rasp',
}

export const DEFAULT_ATTACK_QUEUE_ITEM = {
  id: '',
  source: 'events',
  timestamp: '',
  severity: 'low',
  status: 'new',
  eventType: 'unknown',
  title: '',
  detail: '',
  srcIp: '',
  dstIp: '',
  domain: '',
  ruleName: '',
  entityId: '',
  rawReference: '',
}

export function normalizeSeverity(input) {
  const level = String(input || '').toLowerCase()
  if (level === 'critical' || level === 'high' || level === 'medium' || level === 'low') {
    return level
  }
  return 'low'
}

export function normalizeStatus(input) {
  const status = String(input || '').toLowerCase()
  if (status === 'new' || status === 'open' || status === 'blocked' || status === 'allowed' || status === 'closed') {
    return status
  }
  return 'new'
}
