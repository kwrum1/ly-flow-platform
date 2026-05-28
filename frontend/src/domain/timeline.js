import { dedupeAttackQueueItems, normalizeAttackQueueItems } from './attack-queue'

function timeValue(item) {
  const date = new Date(item?.timestamp || item?.time || item?.created_at || item?.occurred_at || 0)
  if (Number.isNaN(date.getTime())) return 0
  return date.getTime()
}

export function normalizeTimelineItems(items = [], fallbackSource = 'events') {
  const rawBySource = { '/events': [], '/unified/events': [], '/xdr/events': [], '/rasp/events': [] }
  items.forEach((item) => {
    const source = String(item?.source_module || item?.sourceModule || item?.source || fallbackSource).toLowerCase()
    if (source === 'xdr') rawBySource['/xdr/events'].push(item)
    else if (source === 'rasp') rawBySource['/rasp/events'].push(item)
    else if (source === 'runtime' || source === 'unified') rawBySource['/unified/events'].push(item)
    else rawBySource['/events'].push(item)
  })

  return dedupeAttackQueueItems(normalizeAttackQueueItems(rawBySource))
    .sort((a, b) => timeValue(a) - timeValue(b) || `${a.source}:${a.id}`.localeCompare(`${b.source}:${b.id}`))
}

export function groupTimelineBySource(items = []) {
  return items.reduce((groups, item) => {
    const source = item.source || 'events'
    groups[source] = groups[source] || []
    groups[source].push(item)
    return groups
  }, {})
}
