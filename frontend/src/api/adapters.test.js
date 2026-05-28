import { describe, it, expect } from 'vitest'
import {
  API_ERROR_CODES,
  createAPIError,
  isAPIError,
  normalizeAuthPayload,
  normalizeAssetOpsMetrics,
  normalizeEmptyStateList,
  normalizeEventDetail,
  normalizeEventList,
  normalizeList,
  toAPIError,
  unwrapAPIEnvelope,
} from './adapters'

describe('API adapters', () => {
  it('unwrapAPIEnvelope handles code/data envelope', () => {
    const payload = { code: 0, data: { ok: true } }
    expect(unwrapAPIEnvelope(payload)).toEqual({ ok: true })
    expect(unwrapAPIEnvelope({ code: 200, data: { ok: true } })).toEqual({ ok: true })
  })

  it('unwrapAPIEnvelope accepts success envelopes without data as empty success', () => {
    expect(unwrapAPIEnvelope({ code: 0 })).toEqual({})
    expect(unwrapAPIEnvelope({ code: 200, message: 'ok' })).toEqual({})
  })

  it('unwrapAPIEnvelope throws identifiable errors for business failures', () => {
    expect(() => unwrapAPIEnvelope({ code: 500, message: 'boom' })).toThrow(/boom/)
  })

  it('error helpers normalize unknown errors', () => {
    const base = createAPIError({ code: API_ERROR_CODES.TIMEOUT, message: 'timeout' })
    expect(isAPIError(base)).toBe(true)
    expect(toAPIError(base)).toBe(base)

    const unknown = toAPIError(new Error('raw'))
    expect(isAPIError(unknown)).toBe(true)
    expect(unknown.code).toBe(API_ERROR_CODES.UNKNOWN)
  })

  it('normalizeEventList supports items/events/list and total fallback', () => {
    expect(normalizeEventList({ code: 0, data: { items: [{ id: 1 }], total: 10 } })).toEqual({
      items: [{ id: 1 }],
      total: 10,
    })

    expect(normalizeEventList({ data: { events: [{ id: 2 }] } })).toEqual({
      items: [{ id: 2 }],
      total: 1,
    })

    expect(normalizeEventList([{ id: 3 }, { id: 4 }])).toEqual({
      items: [{ id: 3 }, { id: 4 }],
      total: 2,
    })
  })

  it('normalizeList supports custom list aliases', () => {
    expect(normalizeList({ code: 0, data: { hosts: [{ id: 'h1' }], total: 3 } }, ['hosts', 'items'])).toEqual({
      items: [{ id: 'h1' }],
      total: 3,
    })
  })

  it('normalizeEventDetail supports event/item/body and related aliases', () => {
    expect(normalizeEventDetail({ code: 0, data: { event: { id: 1 }, related: [{ id: 11 }] } })).toEqual({
      event: { id: 1 },
      related: [{ id: 11 }],
    })

    expect(normalizeEventDetail({ data: { item: { id: 2 }, related_events: [{ id: 22 }] } })).toEqual({
      event: { id: 2 },
      related: [{ id: 22 }],
    })

    expect(normalizeEventDetail({ id: 3 })).toEqual({
      event: { id: 3 },
      related: [],
    })
  })

  it('normalizeAuthPayload exposes password-change and lockout state', () => {
    expect(normalizeAuthPayload({
      code: 0,
      data: {
        token: 'abc',
        expires_at: '2026-05-12T10:30:00Z',
        needs_password_change: true,
        account_locked: false,
        user: { username: 'admin' },
      },
    })).toEqual({
      token: 'abc',
      expiresAt: '2026-05-12T10:30:00Z',
      needsPasswordChange: true,
      locked: false,
      user: { username: 'admin' },
    })

    expect(normalizeAuthPayload({ data: { user: { accountLocked: true } } }).locked).toBe(true)
  })

  it('normalizeEmptyStateList preserves honest empty-state metadata', () => {
    expect(normalizeEmptyStateList({
      code: 0,
      data: {
        items: [],
        total: 0,
        empty_state: {
          reason: 'NO_AGENTS',
          message: '暂无 Agent 数据',
        },
      },
    })).toEqual({
      items: [],
      total: 0,
      emptyState: {
        reason: 'NO_AGENTS',
        message: '暂无 Agent 数据',
      },
    })
  })

  it('normalizeAssetOpsMetrics keeps missing telemetry unknown instead of fake zeroes', () => {
    expect(normalizeAssetOpsMetrics({}, Date.parse('2026-05-12T10:00:00Z'))).toEqual({
      cpuModel: null,
      cpuUsagePercent: null,
      memoryTotalMb: null,
      memoryUsedMb: null,
      memoryUsagePercent: null,
      diskTotalGb: null,
      diskUsedGb: null,
      diskUsagePercent: null,
      os: null,
      arch: null,
      agentVersion: null,
      lastUpdatedAt: null,
      stale: true,
    })
  })

  it('normalizeAssetOpsMetrics exposes real reported utilization and freshness', () => {
    expect(normalizeAssetOpsMetrics({
      cpu_model: 'Intel Xeon',
      cpu_usage_percent: 35,
      memory_total_mb: 8192,
      memory_used_mb: 4096,
      memory_usage_percent: 50,
      disk_total_gb: 500,
      disk_used_gb: 250,
      disk_usage_percent: 50,
      os: 'linux',
      arch: 'amd64',
      agent_version: '1.0.0',
      metrics_updated_at: '2026-05-12T09:59:00Z',
    }, Date.parse('2026-05-12T10:00:00Z'))).toEqual({
      cpuModel: 'Intel Xeon',
      cpuUsagePercent: 35,
      memoryTotalMb: 8192,
      memoryUsedMb: 4096,
      memoryUsagePercent: 50,
      diskTotalGb: 500,
      diskUsedGb: 250,
      diskUsagePercent: 50,
      os: 'linux',
      arch: 'amd64',
      agentVersion: '1.0.0',
      lastUpdatedAt: '2026-05-12T09:59:00Z',
      stale: false,
    })
  })
})
