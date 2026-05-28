export function createExponentialBackoff(options = {}) {
  const {
    initialDelayMs = 1000,
    maxDelayMs = 30000,
    factor = 2,
    jitterRatio = 0,
  } = options

  const safeInitial = Math.max(0, Number(initialDelayMs) || 0)
  const safeMax = Math.max(safeInitial, Number(maxDelayMs) || safeInitial)
  const safeFactor = Math.max(1, Number(factor) || 1)
  const safeJitter = Math.min(1, Math.max(0, Number(jitterRatio) || 0))

  return (attempt) => {
    const safeAttempt = Math.max(1, Number(attempt) || 1)
    const raw = safeInitial * safeFactor ** (safeAttempt - 1)
    const capped = Math.min(safeMax, raw)

    if (safeJitter === 0 || capped === 0) return capped

    const offset = capped * safeJitter
    const min = capped - offset
    const max = capped + offset
    return Math.round(min + Math.random() * (max - min))
  }
}

export function createSteppedBackoff(steps = [1000, 3000, 5000]) {
  const normalized = Array.isArray(steps)
    ? steps.map((value) => Math.max(0, Number(value) || 0))
    : [1000]

  return (attempt) => {
    const index = Math.max(0, Math.min(normalized.length - 1, (Number(attempt) || 1) - 1))
    return normalized[index]
  }
}
