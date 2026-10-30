/**
 * Data-quality math for the LyFlow console.
 *
 * Contract (see plan R-01 / R-03 / R-11):
 * - a missing value is never coerced to 0;
 * - `dst_port === 0` is reported as "unknown", not as a real port;
 * - every rate carries the sample size it was computed from;
 * - when the sample is empty the result is `null`, not 0%.
 */

export const NETWORK_FIELDS = Object.freeze([
  { key: 'src_ip', label: '源地址', kind: 'identity' },
  { key: 'dst_ip', label: '目的地址', kind: 'identity' },
  { key: 'dst_port', label: '目的端口', kind: 'port' },
  { key: 'protocol', label: '协议', kind: 'protocol' },
  { key: 'event_at', label: '事件时间', kind: 'time' },
])

export function isBlank(value) {
  return value === null || value === undefined || value === ''
}

/**
 * A port is known only when it is a finite integer in 1..65535.
 * 0 is the legacy "missing" sentinel and is treated as unknown.
 */
export function isKnownPort(value) {
  const port = Number(value)
  return Number.isInteger(port) && port > 0 && port <= 65535
}

function rate(count, total) {
  if (!total) return null
  return Math.round((count / total) * 1000) / 10
}

/**
 * @param {Array<Record<string, unknown>>} items
 * @returns {{
 *   sample: number,
 *   fields: Array<{key:string,label:string,missing:number,rate:number|null}>,
 *   complete: number,
 *   completeRate: number|null,
 *   occurrence: number,
 *   occurrencesWithAddress: number,
 *   occurrenceAddressRate: number|null
 * }}
 */
export function computeFieldQuality(items = []) {
  const list = Array.isArray(items) ? items : []
  const sample = list.length

  const fields = NETWORK_FIELDS.map((field) => {
    let missing = 0
    for (const item of list) {
      if (field.kind === 'port') {
        if (!isKnownPort(item?.[field.key])) missing += 1
      } else if (isBlank(item?.[field.key])) {
        missing += 1
      }
    }
    return { key: field.key, label: field.label, missing, rate: rate(missing, sample) }
  })

  // A record is "complete" only when both addresses and the port are known.
  let complete = 0
  for (const item of list) {
    if (!isBlank(item?.src_ip) && !isBlank(item?.dst_ip) && isKnownPort(item?.dst_port)) complete += 1
  }

  let occurrence = 0
  let occurrencesWithAddress = 0
  for (const item of list) {
    const weight = occurrenceWeight(item)
    occurrence += weight
    if (!isBlank(item?.src_ip) && !isBlank(item?.dst_ip)) occurrencesWithAddress += weight
  }

  return {
    sample,
    fields,
    complete,
    completeRate: rate(complete, sample),
    occurrence,
    occurrencesWithAddress,
    occurrenceAddressRate: rate(occurrencesWithAddress, occurrence),
  }
}

export function occurrenceWeight(item) {
  const count = Number(item?.count)
  return Number.isFinite(count) && count > 0 ? count : 1
}

/**
 * Per-source quality, so a single noisy sensor cannot hide behind the
 * platform-wide average.
 */
export function computeSourceQuality(items = []) {
  const list = Array.isArray(items) ? items : []
  const groups = new Map()

  for (const item of list) {
    const key = String(item?.source || item?.source_engine || 'unknown')
    if (!groups.has(key)) groups.set(key, { key, sample: 0, occurrence: 0, missing: 0, portUnknown: 0 })
    const group = groups.get(key)
    group.sample += 1
    group.occurrence += occurrenceWeight(item)
    if (isBlank(item?.src_ip) || isBlank(item?.dst_ip)) group.missing += 1
    if (!isKnownPort(item?.dst_port)) group.portUnknown += 1
  }

  return [...groups.values()]
    .map((group) => ({
      ...group,
      missingRate: rate(group.missing, group.sample),
      portUnknownRate: rate(group.portUnknown, group.sample),
    }))
    .sort((a, b) => b.occurrence - a.occurrence)
}

/**
 * Daily volume based on `first_seen` so aggregates are attributed to the
 * day they started rather than the day they last fired.
 */
export function computeDailyVolume(items = []) {
  const list = Array.isArray(items) ? items : []
  const map = new Map()
  for (const item of list) {
    const stamp = item?.first_seen || item?.event_at || item?.timestamp
    if (!stamp) continue
    const day = String(stamp).slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue
    map.set(day, (map.get(day) || 0) + occurrenceWeight(item))
  }
  return [...map.entries()]
    .map(([day, count]) => ({ day, count }))
    .sort((a, b) => a.day.localeCompare(b.day))
}

/**
 * Queryable span for the sample. Returns nulls when the sample is empty so
 * the UI can render "unknown" instead of a fake 0-day retention.
 */
export function queryableSpan(items = []) {
  const list = Array.isArray(items) ? items : []
  const stamps = []
  for (const item of list) {
    const value = item?.first_seen || item?.event_at || item?.timestamp
    const ms = new Date(value).getTime()
    if (Number.isFinite(ms)) stamps.push(ms)
  }
  if (!stamps.length) return { earliest: null, latest: null, days: null }
  const earliest = Math.min(...stamps)
  const latest = Math.max(...stamps)
  return {
    earliest: new Date(earliest).toISOString(),
    latest: new Date(latest).toISOString(),
    days: Math.round(((latest - earliest) / 86400000) * 10) / 10,
  }
}

/**
 * Classifies a clock source honestly. `manual` is not "healthy" even when
 * the offset happens to be small, because it never re-syncs.
 */
export function classifyClockSource(source) {
  const value = String(source || '').toLowerCase()
  if (value === 'ntp' || value === 'chrony' || value === 'system') {
    return { key: 'synced', label: '已同步', tone: 'success' }
  }
  if (value === 'manual') return { key: 'manual', label: '手动', tone: 'warning' }
  if (!value || value === 'unknown') return { key: 'unknown', label: '未知', tone: 'unknown' }
  return { key: 'other', label: value, tone: 'unknown' }
}
