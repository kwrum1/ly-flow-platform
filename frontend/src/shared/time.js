import { productIdentity } from '../contracts/backend-contracts'

const dateTimeFormatter = new Intl.DateTimeFormat(productIdentity.locale, {
  timeZone: productIdentity.timeZone,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

const timeFormatter = new Intl.DateTimeFormat(productIdentity.locale, {
  timeZone: productIdentity.timeZone,
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

let platformTimeOffsetMs = 0
let platformTimeVersion = 0

function withPlatformOffset(date) {
  if (!platformTimeOffsetMs) return date
  return new Date(date.getTime() + platformTimeOffsetMs)
}

export const PLATFORM_TIME_UPDATED_EVENT = 'lyflow:platform-time-updated'

export function setPlatformTimeOffset(offsetMs = 0) {
  const next = Number(offsetMs)
  const normalized = Number.isFinite(next) ? next : 0
  if (normalized === platformTimeOffsetMs && platformTimeVersion > 0) return
  platformTimeOffsetMs = normalized
  platformTimeVersion += 1
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(PLATFORM_TIME_UPDATED_EVENT, {
      detail: { offsetMs: platformTimeOffsetMs, version: platformTimeVersion },
    }))
  }
}

export function getPlatformTimeOffset() {
  return platformTimeOffsetMs
}

export function getPlatformTimeVersion() {
  return platformTimeVersion
}

export function formatChinaDateTime(value) {
  if (!value) return '暂无时间'
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '时间格式异常'
  return dateTimeFormatter.format(withPlatformOffset(date))
}

export function formatChinaTime(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '时间格式异常'
  return timeFormatter.format(withPlatformOffset(date))
}

export function platformNow() {
  return withPlatformOffset(new Date())
}

export async function refreshPlatformTimeOffset(loader) {
  if (typeof loader !== 'function') return null
  const data = await loader()
  setPlatformTimeOffset(data?.offset_ms || 0)
  return data
}
