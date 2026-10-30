import { describe, expect, it } from 'vitest'
import {
  classifyClockSource,
  computeDailyVolume,
  computeFieldQuality,
  computeSourceQuality,
  isKnownPort,
  queryableSpan,
} from './data-quality'

describe('data quality — 缺失值不得伪装成真实 0', () => {
  it('空样本返回 null 比率，而不是 0%', () => {
    const result = computeFieldQuality([])
    expect(result.sample).toBe(0)
    expect(result.completeRate).toBeNull()
    expect(result.fields.every((field) => field.rate === null)).toBe(true)
  })

  it('端口 0 视为未知，只有 1..65535 才算已知端口', () => {
    expect(isKnownPort(0)).toBe(false)
    expect(isKnownPort('0')).toBe(false)
    expect(isKnownPort(null)).toBe(false)
    expect(isKnownPort(undefined)).toBe(false)
    expect(isKnownPort(443)).toBe(true)
    expect(isKnownPort('8080')).toBe(true)
    expect(isKnownPort(65535)).toBe(true)
    expect(isKnownPort(65536)).toBe(false)
  })

  it('只有地址和端口都已知才算完整五元组', () => {
    const result = computeFieldQuality([
      { src_ip: '10.0.0.1', dst_ip: '10.0.0.2', dst_port: 443 },
      { src_ip: '10.0.0.1', dst_ip: '10.0.0.2', dst_port: 0 },
      { src_ip: '', dst_ip: '10.0.0.2', dst_port: 80 },
    ])
    expect(result.sample).toBe(3)
    expect(result.complete).toBe(1)
    expect(result.completeRate).toBe(33.3)
    expect(result.fields.find((field) => field.key === 'dst_port').missing).toBe(1)
    expect(result.fields.find((field) => field.key === 'src_ip').missing).toBe(1)
  })

  it('按命中次数加权统计，并单独给出地址覆盖率', () => {
    const result = computeFieldQuality([
      { src_ip: 'a', dst_ip: 'b', dst_port: 80, count: 10 },
      { src_ip: '', dst_ip: '', dst_port: 0, count: 5 },
    ])
    expect(result.occurrence).toBe(15)
    expect(result.occurrencesWithAddress).toBe(10)
    expect(result.occurrenceAddressRate).toBe(66.7)
  })
})

describe('data quality — 按来源拆分', () => {
  it('按来源聚合，序列化缺失率与端口未知率', () => {
    const rows = computeSourceQuality([
      { source: 'suricata', src_ip: 'a', dst_ip: 'b', dst_port: 80, count: 3 },
      { source: 'suricata', src_ip: '', dst_ip: 'b', dst_port: 0 },
      { source: 'wazuh', count: 1 },
    ])
    const suricata = rows.find((row) => row.key === 'suricata')
    expect(suricata.sample).toBe(2)
    expect(suricata.occurrence).toBe(4)
    expect(suricata.missingRate).toBe(50)
    expect(suricata.portUnknownRate).toBe(50)

    const wazuh = rows.find((row) => row.key === 'wazuh')
    expect(wazuh.missingRate).toBe(100)

    // Sorted by occurrence weight, so the busiest source is first.
    expect(rows[0].key).toBe('suricata')
  })
})

describe('data quality — 留存与时间', () => {
  it('按 first_seen 归属日期，避免聚合记录全部落到最后一天', () => {
    const rows = computeDailyVolume([
      { first_seen: '2026-10-21T10:00:00Z', count: 2 },
      { first_seen: '2026-10-21T23:00:00Z', count: 3 },
      { first_seen: '2026-10-22T01:00:00Z', count: 1 },
      { first_seen: 'not-a-date' },
    ])
    expect(rows).toEqual([
      { day: '2026-10-21', count: 5 },
      { day: '2026-10-22', count: 1 },
    ])
  })

  it('空样本的可查询跨度是 null，而不是 0 天', () => {
    expect(queryableSpan([])).toEqual({ earliest: null, latest: null, days: null })
    const span = queryableSpan([
      { first_seen: '2026-10-21T00:00:00Z' },
      { first_seen: '2026-10-28T00:00:00Z' },
    ])
    expect(span.days).toBe(7)
  })

  it('手动时间源不会被判为已同步', () => {
    expect(classifyClockSource('manual').tone).toBe('warning')
    expect(classifyClockSource('ntp').tone).toBe('success')
    expect(classifyClockSource('').tone).toBe('unknown')
    expect(classifyClockSource(undefined).tone).toBe('unknown')
  })
})
