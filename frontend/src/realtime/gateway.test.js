import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CONNECTION_STATUS, createRealtimeGateway } from './gateway'

class MockWebSocket {
  constructor(url) {
    this.url = url
    this.onopen = null
    this.onmessage = null
    this.onerror = null
    this.onclose = null
    this.close = vi.fn(() => {
      this.onclose?.()
    })
  }
}

describe('realtime gateway', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  it('prefers websocket and emits status and messages', () => {
    const ws = new MockWebSocket('/ws')
    const factory = vi.fn(() => ws)
    const gateway = createRealtimeGateway({ wsUrl: '/ws', createWebSocket: factory })

    const statuses = []
    const messages = []

    gateway.onStatusChange((status) => statuses.push(status))
    gateway.onMessage((payload, source) => messages.push({ payload, source }))

    const transport = gateway.connect()
    expect(transport).toBe('websocket')
    expect(factory).toHaveBeenCalledWith('/ws')
    expect(statuses).toEqual([CONNECTION_STATUS.CONNECTING])

    ws.onopen()
    expect(gateway.getStatus()).toBe(CONNECTION_STATUS.OPEN)

    ws.onmessage({ data: '{"type":"attack","id":1}' })
    expect(messages).toEqual([{ payload: { type: 'attack', id: 1 }, source: 'websocket' }])

    gateway.close()
    expect(gateway.getStatus()).toBe(CONNECTION_STATUS.CLOSED)
  })

  it('degrades to polling when websocket url is missing', async () => {
    const onPoll = vi.fn().mockResolvedValue({ type: 'polling_tick' })
    const gateway = createRealtimeGateway({ pollingIntervalMs: 1000, onPoll })

    const statuses = []
    const messages = []
    gateway.onStatusChange((status) => statuses.push(status))
    gateway.onMessage((payload, source) => messages.push({ payload, source }))

    const transport = gateway.connect()
    expect(transport).toBe('polling')
    expect(statuses[0]).toBe(CONNECTION_STATUS.DEGRADED)

    await vi.advanceTimersByTimeAsync(1000)
    expect(onPoll).toHaveBeenCalledTimes(1)
    expect(messages).toEqual([{ payload: { type: 'polling_tick' }, source: 'polling' }])
  })

  it('degrades to polling if websocket closes unexpectedly', async () => {
    const ws = new MockWebSocket('/ws')
    const onPoll = vi.fn().mockResolvedValue({ ok: true })
    const gateway = createRealtimeGateway({
      wsUrl: '/ws',
      createWebSocket: vi.fn(() => ws),
      onPoll,
      pollingIntervalMs: 500,
    })

    const statuses = []
    gateway.onStatusChange((status) => statuses.push(status))

    gateway.connect()
    ws.onopen()
    ws.onclose()

    expect(gateway.getStatus()).toBe(CONNECTION_STATUS.DEGRADED)

    await vi.advanceTimersByTimeAsync(500)
    expect(onPoll).toHaveBeenCalledTimes(1)
    expect(statuses).toContain(CONNECTION_STATUS.OPEN)
    expect(statuses).toContain(CONNECTION_STATUS.DEGRADED)
  })

  it('reconnects with websocket after a degraded cycle', () => {
    const firstWs = new MockWebSocket('/ws')
    const secondWs = new MockWebSocket('/ws')
    const factory = vi.fn()
      .mockReturnValueOnce(firstWs)
      .mockReturnValueOnce(secondWs)

    const gateway = createRealtimeGateway({
      wsUrl: '/ws',
      createWebSocket: factory,
    })

    const statuses = []
    gateway.onStatusChange((status) => statuses.push(status))

    gateway.connect()
    firstWs.onopen()
    firstWs.onclose()

    gateway.connect()
    secondWs.onopen()

    expect(factory).toHaveBeenCalledTimes(2)
    expect(gateway.getStatus()).toBe(CONNECTION_STATUS.OPEN)
    expect(statuses).toContain(CONNECTION_STATUS.DEGRADED)
    expect(statuses.at(-1)).toBe(CONNECTION_STATUS.OPEN)
  })

  it('supports abort cleanup through AbortController', () => {
    const ws = new MockWebSocket('/ws')
    const controller = new AbortController()
    const gateway = createRealtimeGateway({
      wsUrl: '/ws',
      createWebSocket: vi.fn(() => ws),
      signal: controller.signal,
    })

    gateway.connect()
    ws.onopen()
    controller.abort()

    expect(gateway.getStatus()).toBe(CONNECTION_STATUS.CLOSED)
    expect(ws.close).toHaveBeenCalledTimes(1)
  })
})
