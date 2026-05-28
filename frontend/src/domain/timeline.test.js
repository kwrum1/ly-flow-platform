import { describe, expect, it } from 'vitest'
import { groupTimelineBySource, normalizeTimelineItems } from './timeline'

describe('timeline domain', () => {
  it('orders timeline items by event timestamp instead of input order', () => {
    const items = normalizeTimelineItems([
      { id: 'late', timestamp: '2026-01-02T00:02:00Z', source_module: 'rasp', message: 'late' },
      { id: 'early', timestamp: '2026-01-02T00:01:00Z', source_module: 'runtime', message: 'early' },
    ])

    expect(items.map((item) => item.id)).toEqual(['early', 'late'])
  })

  it('groups ordered items by source module', () => {
    const groups = groupTimelineBySource(normalizeTimelineItems([
      { id: 'dpi-1', timestamp: '2026-01-02T00:01:00Z', source_module: 'dpi' },
      { id: 'xdr-1', timestamp: '2026-01-02T00:02:00Z', source_module: 'xdr' },
    ]))

    expect(groups.events).toHaveLength(1)
    expect(groups.xdr).toHaveLength(1)
  })
})
