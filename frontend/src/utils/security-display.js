const SENSITIVE_FIELD_PATTERN = /(payload|command[_-]?line|token|authorization|secret|password|cookie|apikey|api[_-]?key)/i

const MASKED_PLACEHOLDER = '*** 已脱敏 ***'

const isPlainObject = (value) => Object.prototype.toString.call(value) === '[object Object]'

export const isSensitiveFieldName = (fieldName = '') => SENSITIVE_FIELD_PATTERN.test(String(fieldName || ''))

const maskPrimitive = (value) => {
  const raw = String(value ?? '')
  if (!raw) return MASKED_PLACEHOLDER
  if (raw.length <= 8) return `${raw.slice(0, 1)}***`
  return `${raw.slice(0, 3)}***${raw.slice(-3)}`
}

const maskStringByPattern = (text) => {
  const normalized = String(text || '')
  let masked = false

  const bearerMasked = normalized.replace(/(bearer\s+)([^\s]+)/ig, (_, prefix, token) => {
    masked = true
    return `${prefix}${maskPrimitive(token)}`
  })

  const kvMasked = bearerMasked.replace(/(token|password|secret|authorization|cookie|api[_-]?key|command[_-]?line)\s*[:=]\s*([^\s,;]+)/ig, (_, key, val) => {
    masked = true
    return `${key}= ${maskPrimitive(val)}`
  })

  return {
    value: masked ? kvMasked : normalized,
    masked,
  }
}

export const sanitizeSensitiveValue = (fieldName, value) => {
  const sensitiveField = isSensitiveFieldName(fieldName)

  if (value == null) {
    return { value, masked: false }
  }

  if (typeof value === 'string') {
    if (sensitiveField) {
      return { value: maskPrimitive(value), masked: true }
    }
    return maskStringByPattern(value)
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    if (sensitiveField) {
      return { value: MASKED_PLACEHOLDER, masked: true }
    }
    return { value, masked: false }
  }

  if (Array.isArray(value)) {
    let hasMasked = false
    const sanitized = value.map((item) => {
      const result = sanitizeSensitiveValue(fieldName, item)
      hasMasked = hasMasked || result.masked
      return result.value
    })
    return { value: sanitized, masked: hasMasked || sensitiveField }
  }

  if (isPlainObject(value)) {
    let hasMasked = false
    const sanitized = Object.entries(value).reduce((acc, [key, item]) => {
      const result = sanitizeSensitiveValue(key, item)
      hasMasked = hasMasked || result.masked
      acc[key] = result.value
      return acc
    }, {})
    return { value: sanitized, masked: hasMasked || sensitiveField }
  }

  if (sensitiveField) {
    return { value: MASKED_PLACEHOLDER, masked: true }
  }

  return { value, masked: false }
}

export const formatMaskedJson = (value) => {
  const result = sanitizeSensitiveValue('detail', value)
  const display = typeof result.value === 'string' ? result.value : JSON.stringify(result.value, null, 2)
  return {
    text: display || '暂无详情',
    masked: result.masked,
  }
}
