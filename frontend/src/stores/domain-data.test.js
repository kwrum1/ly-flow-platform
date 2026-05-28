import { describe, expect, it, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

const failingOverviewStats = vi.fn(async () => ({ total: 1 }))

vi.mock('../api/domain', () => ({
  overviewClient: {
    health: vi.fn(async () => ({ status: 'healthy' })),
    stats: failingOverviewStats,
  },
  attackWorkbenchClient: {
    stats: vi.fn(async () => ({ total_events: 2 })),
    events: vi.fn(async () => ({ items: [] })),
    incidents: vi.fn(async () => ({ items: [] })),
    timeline: vi.fn(async () => ({ items: [] })),
  },
  assetAgentClient: {
    assets: vi.fn(async () => ({ items: [] })),
    agents: vi.fn(async () => ({ items: [] })),
  },
  ruleClient: {
    list: vi.fn(async () => ({ items: [] })),
    stats: vi.fn(async () => ({ total: 0 })),
    categories: vi.fn(async () => ([])),
  },
  signalClient: {
    xdrStats: vi.fn(async () => ({ total: 0 })),
    raspStats: vi.fn(async () => ({ total_events: 0 })),
    traceStats: vi.fn(async () => ({ total_sessions: 0 })),
  },
}))

const { useDomainDataStore } = await import('./domain-data')

describe('领域数据状态', () => {
  it('加载攻击链工作台数据时不生成前端假数据', async () => {
    setActivePinia(createPinia())
    const store = useDomainDataStore()

    await store.loadAttackWorkbench()

    expect(store.attackStats.data).toEqual({ total_events: 2 })
    expect(store.attackEvents.data).toEqual({ items: [] })
    expect(store.incidents.data).toEqual({ items: [] })
    expect(store.timeline.data).toEqual({ items: [] })
  })

  it('接口失败时保留错误状态而不是伪造成功', async () => {
    setActivePinia(createPinia())
    const store = useDomainDataStore()
    failingOverviewStats.mockRejectedValueOnce(new Error('真实接口不可用'))

    await expect(store.loadOverview()).rejects.toThrow('真实接口不可用')
    expect(store.overview.data).toBe(null)
    expect(store.overview.error).toBe('真实接口不可用')
  })
})
