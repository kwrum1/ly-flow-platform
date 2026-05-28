export function createPollingFreshnessTracker(options = {}) {
  const {
    staleAfterMs = 90000,
    staleFailureThreshold = 2,
    now = () => Date.now(),
  } = options

  const safeStaleAfterMs = Math.max(0, Number(staleAfterMs) || 0)
  const safeFailureThreshold = Math.max(1, Number(staleFailureThreshold) || 1)

  let lastUpdatedAt = 0
  let failureCount = 0
  let stale = false

  const snapshot = () => ({
    lastUpdatedAt,
    failureCount,
    stale,
  })

  const recomputeStale = () => {
    const staleByFailures = failureCount >= safeFailureThreshold
    const staleByTime = lastUpdatedAt > 0 && safeStaleAfterMs > 0 && now() - lastUpdatedAt > safeStaleAfterMs
    stale = staleByFailures || staleByTime
    return snapshot()
  }

  const markSuccess = (timestamp = now()) => {
    lastUpdatedAt = timestamp
    failureCount = 0
    return recomputeStale()
  }

  const markFailure = () => {
    failureCount += 1
    return recomputeStale()
  }

  return {
    markSuccess,
    markFailure,
    refresh: recomputeStale,
    getSnapshot: snapshot,
  }
}
