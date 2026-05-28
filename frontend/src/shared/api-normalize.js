export function normalizeItems(payload) {
  if (Array.isArray(payload)) return { items: payload, total: payload.length }
  const data = payload || {}
  const items = data.items || data.events || data.list || []
  return {
    items: Array.isArray(items) ? items : [],
    total: Number.isFinite(data.total) ? data.total : Array.isArray(items) ? items.length : 0,
  }
}

export function pickText(value, fallback = '未上报') {
  if (value === null || value === undefined || value === '') return fallback
  return String(value)
}

export function pickNumber(value, fallback = 0) {
  const number = Number(value)
  return Number.isFinite(number) ? number : fallback
}
