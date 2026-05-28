const CONNECTION_STATUS = {
  IDLE: 'idle',
  CONNECTING: 'connecting',
  OPEN: 'open',
  DEGRADED: 'degraded',
  CLOSED: 'closed',
  ERROR: 'error',
}

function isWebSocketSupported() {
  return typeof WebSocket !== 'undefined'
}

function normalizeMessage(data) {
  if (typeof data !== 'string') return data
  try {
    return JSON.parse(data)
  } catch {
    return data
  }
}

export function createRealtimeGateway(options = {}) {
  const {
    wsUrl = '',
    pollingIntervalMs = 5000,
    onPoll,
    createWebSocket = (url) => new WebSocket(url),
    signal,
  } = options

  let status = CONNECTION_STATUS.IDLE
  let websocket = null
  let pollTimer = null
  let abortListener = null
  let activeAbortSignal = signal || null
  let manuallyClosed = false

  const messageHandlers = new Set()
  const statusHandlers = new Set()

  const notifyStatus = (nextStatus, detail) => {
    status = nextStatus
    statusHandlers.forEach((handler) => handler(nextStatus, detail))
  }

  const emitMessage = (payload, source = 'unknown') => {
    messageHandlers.forEach((handler) => handler(payload, source))
  }

  const clearPolling = () => {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  const clearWebSocket = () => {
    if (websocket) {
      websocket.onopen = null
      websocket.onmessage = null
      websocket.onerror = null
      websocket.onclose = null
      try {
        websocket.close()
      } catch {
        // Ignore close errors from already-closed sockets.
      }
      websocket = null
    }
  }

  const detachAbortSignal = () => {
    if (activeAbortSignal && abortListener) {
      activeAbortSignal.removeEventListener('abort', abortListener)
    }
    abortListener = null
    activeAbortSignal = null
  }

  const startPolling = (reason) => {
    clearWebSocket()
    clearPolling()

    notifyStatus(CONNECTION_STATUS.DEGRADED, { reason, transport: 'polling' })

    if (typeof onPoll !== 'function' || pollingIntervalMs <= 0) return

    pollTimer = setInterval(async () => {
      try {
        const nextPayload = await onPoll()
        if (nextPayload !== undefined) {
          emitMessage(nextPayload, 'polling')
        }
      } catch {
        notifyStatus(CONNECTION_STATUS.ERROR, { reason: 'polling_error' })
      }
    }, pollingIntervalMs)
  }

  const bindAbortSignal = (abortSignal) => {
    if (!abortSignal) return

    activeAbortSignal = abortSignal
    abortListener = () => {
      gateway.close('aborted')
    }

    if (abortSignal.aborted) {
      abortListener()
      return
    }

    abortSignal.addEventListener('abort', abortListener, { once: true })
  }

  const connect = ({ signal: nextSignal } = {}) => {
    manuallyClosed = false
    clearPolling()
    clearWebSocket()
    detachAbortSignal()

    const abortSignal = nextSignal || signal
    bindAbortSignal(abortSignal)

    if (!wsUrl || !isWebSocketSupported()) {
      startPolling('ws_unavailable')
      return 'polling'
    }

    notifyStatus(CONNECTION_STATUS.CONNECTING, { transport: 'websocket' })

    try {
      websocket = createWebSocket(wsUrl)
    } catch {
      startPolling('ws_init_failed')
      return 'polling'
    }

    websocket.onopen = () => {
      notifyStatus(CONNECTION_STATUS.OPEN, { transport: 'websocket' })
    }

    websocket.onmessage = (event) => {
      emitMessage(normalizeMessage(event?.data), 'websocket')
    }

    websocket.onerror = () => {
      notifyStatus(CONNECTION_STATUS.ERROR, { reason: 'ws_error' })
    }

    websocket.onclose = () => {
      if (manuallyClosed) {
        notifyStatus(CONNECTION_STATUS.CLOSED, { reason: 'manual_close' })
        return
      }
      startPolling('ws_closed')
    }

    return 'websocket'
  }

  const close = (reason = 'manual_close') => {
    manuallyClosed = true
    clearPolling()
    clearWebSocket()
    detachAbortSignal()
    notifyStatus(CONNECTION_STATUS.CLOSED, { reason })
  }

  const onMessage = (handler) => {
    messageHandlers.add(handler)
    return () => messageHandlers.delete(handler)
  }

  const onStatusChange = (handler) => {
    statusHandlers.add(handler)
    return () => statusHandlers.delete(handler)
  }

  const gateway = {
    connect,
    close,
    onMessage,
    onStatusChange,
    getStatus: () => status,
  }

  return gateway
}

export { CONNECTION_STATUS }
