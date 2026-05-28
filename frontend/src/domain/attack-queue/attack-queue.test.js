import { describe, expect, it } from 'vitest'

import {
  computePriorityInputs,
  dedupeAttackQueueItems,
  normalizeAttackQueueItems,
} from './index'

describe('attack queue domain', () => {
  it('normalizes multi-source payloads from endpoint-mapped sources to AttackQueueItem fields', () => {
    const items = normalizeAttackQueueItems({
      '/events': { data: { items: [{ id: 'e1', timestamp: '2026-01-01T00:00:00Z', severity: 'high', event_type: 'scan', message: 'event', src_ip: '1.1.1.1', dst_ip: '2.2.2.2', domain: 'a.com', rule_name: 'r1' }] } },
      '/unified/events': { data: { events: [{ uuid: 'u1', created_at: '2026-01-01T00:01:00Z', level: 'critical', type: 'dpi', detail: 'u', source_ip: '3.3.3.3', destination_ip: '4.4.4.4', host: 'b.com', signature: 'sig' }] } },
      '/xdr/events': [],
      '/rasp/events': [],
    })

    expect(items).toHaveLength(2)
    expect(items[0]).toMatchObject({
      id: 'e1',
      source: 'events',
      severity: 'high',
      eventType: 'scan',
      srcIp: '1.1.1.1',
      dstIp: '2.2.2.2',
      domain: 'a.com',
      ruleName: 'r1',
    })
    expect(items[1]).toMatchObject({
      id: 'u1',
      source: 'unified',
      severity: 'critical',
      eventType: 'dpi',
      srcIp: '3.3.3.3',
      dstIp: '4.4.4.4',
      domain: 'b.com',
      ruleName: 'sig',
    })
  })

  it('computes predictable priority inputs for P1/P2 ordering', () => {
    const criticalNew = computePriorityInputs({ severity: 'critical', status: 'new', source: 'events' })
    const highOpen = computePriorityInputs({ severity: 'high', status: 'open', source: 'events' })
    const highClosed = computePriorityInputs({ severity: 'high', status: 'closed', source: 'events' })
    const highOpenXdr = computePriorityInputs({ severity: 'high', status: 'open', source: 'xdr' })

    expect(criticalNew.severityScore).toBeGreaterThan(highOpen.severityScore)
    expect(highOpen.isUnresolved).toBe(true)
    expect(highClosed.isUnresolved).toBe(false)
    expect(highOpen.sourceWeight).toBe(1)
    expect(highOpenXdr.sourceWeight).toBe(2)
  })

  it('dedupes by stable id across sources', () => {
    const deduped = dedupeAttackQueueItems([
      { id: 'same-id', source: 'events', timestamp: '2026-01-01T00:00:00Z', srcIp: '1', dstIp: '2', eventType: 'scan', ruleName: 'r', severity: 'high', title: 't' },
      { id: 'same-id', source: 'xdr', timestamp: '2026-01-01T00:01:00Z', srcIp: '9', dstIp: '8', eventType: 'other', ruleName: 'x', severity: 'low', title: 'x' },
    ])

    expect(deduped).toHaveLength(1)
    expect(deduped[0].id).toBe('same-id')
  })

  it('dedupes by fallback composite key within same minute bucket', () => {
    const deduped = dedupeAttackQueueItems([
      { id: '', source: 'rasp', timestamp: '2026-01-01T00:10:20Z', srcIp: '5', dstIp: '6', eventType: 'exec', ruleName: 'rule', severity: 'medium', title: 'A' },
      { id: '', source: 'rasp', timestamp: '2026-01-01T00:10:45Z', srcIp: '5', dstIp: '6', eventType: 'exec', ruleName: 'rule', severity: 'medium', title: 'A' },
    ])

    expect(deduped).toHaveLength(1)
  })

  it('does not over-collapse fallback keys when ruleName or network tuple differs', () => {
    const deduped = dedupeAttackQueueItems([
      { id: '', source: 'rasp', timestamp: '2026-01-01T00:10:20Z', srcIp: '5', dstIp: '6', eventType: 'exec', ruleName: 'rule-a', severity: 'medium', title: 'A' },
      { id: '', source: 'rasp', timestamp: '2026-01-01T00:10:40Z', srcIp: '5', dstIp: '6', eventType: 'exec', ruleName: 'rule-b', severity: 'medium', title: 'A' },
      { id: '', source: 'rasp', timestamp: '2026-01-01T00:10:50Z', srcIp: '5', dstIp: '7', eventType: 'exec', ruleName: 'rule-a', severity: 'medium', title: 'A' },
    ])

    expect(deduped).toHaveLength(3)
  })
})
