import { describe, expect, it, vi } from 'vitest'
import { createPollingFreshnessTracker } from './freshness'

describe('polling freshness tracker', () => {
  it('enters stale state by failure threshold and recovers on success', () => {
    let now = 0
    const tracker = createPollingFreshnessTracker({
      staleAfterMs: 60000,
      staleFailureThreshold: 2,
      now: () => now,
    })

    expect(tracker.getSnapshot().stale).toBe(false)

    tracker.markFailure()
    expect(tracker.getSnapshot().stale).toBe(false)

    tracker.markFailure()
    expect(tracker.getSnapshot().stale).toBe(true)

    now = 1000
    tracker.markSuccess(now)
    expect(tracker.getSnapshot().stale).toBe(false)
    expect(tracker.getSnapshot().failureCount).toBe(0)
  })

  it('enters stale state after timeout and recovers with newer update', () => {
    vi.useFakeTimers()
    let now = 0
    const tracker = createPollingFreshnessTracker({
      staleAfterMs: 5000,
      staleFailureThreshold: 3,
      now: () => now,
    })

    tracker.markSuccess(1)
    expect(tracker.getSnapshot().stale).toBe(false)

    now = 5002
    tracker.refresh()
    expect(tracker.getSnapshot().stale).toBe(true)

    now = 7000
    tracker.markSuccess(now)
    expect(tracker.getSnapshot().stale).toBe(false)

    vi.useRealTimers()
  })
})
