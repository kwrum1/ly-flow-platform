import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createExponentialBackoff } from './backoff'
import { createPollingScheduler } from './scheduler'

describe('polling scheduler', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('starts task and runs on interval', async () => {
    const run = vi.fn().mockResolvedValue(undefined)
    const scheduler = createPollingScheduler()

    scheduler.start({ id: 'task-1', intervalMs: 1000, run })
    await vi.runAllTicks()

    expect(run).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(1000)
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('retries with exponential backoff after failure', async () => {
    const run = vi
      .fn()
      .mockRejectedValueOnce(new Error('fail-1'))
      .mockRejectedValueOnce(new Error('fail-2'))
      .mockResolvedValue(undefined)

    const backoff = createExponentialBackoff({ initialDelayMs: 100, factor: 2, maxDelayMs: 500 })
    const scheduler = createPollingScheduler()

    scheduler.start({ id: 'task-retry', intervalMs: 1000, run, backoff })
    await vi.runAllTicks()

    expect(run).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(99)
    expect(run).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(1)
    expect(run).toHaveBeenCalledTimes(2)

    await vi.advanceTimersByTimeAsync(200)
    expect(run).toHaveBeenCalledTimes(3)

    await vi.advanceTimersByTimeAsync(1000)
    expect(run).toHaveBeenCalledTimes(4)
  })

  it('supports stop and stopAll with cancellation-safe cleanup', async () => {
    const signals = []
    const runA = vi.fn(async ({ signal }) => {
      signals.push(signal)
      await new Promise(() => {})
    })
    const runB = vi.fn().mockResolvedValue(undefined)

    const scheduler = createPollingScheduler()

    scheduler.start({ id: 'a', intervalMs: 1000, run: runA })
    scheduler.start({ id: 'b', intervalMs: 1000, run: runB })
    await vi.runAllTicks()

    expect(scheduler.size()).toBe(2)
    expect(signals).toHaveLength(1)
    expect(signals[0].aborted).toBe(false)

    expect(scheduler.stop('a')).toBe(true)
    expect(signals[0].aborted).toBe(true)

    scheduler.stopAll()
    expect(scheduler.size()).toBe(0)

    await vi.advanceTimersByTimeAsync(5000)
    expect(runB).toHaveBeenCalledTimes(1)
  })
})
