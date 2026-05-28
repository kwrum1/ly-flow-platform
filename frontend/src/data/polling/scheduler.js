import { createExponentialBackoff } from './backoff'

export function createPollingScheduler(options = {}) {
  const {
    createSignal = () => new AbortController(),
    defaultBackoff = createExponentialBackoff(),
  } = options

  const tasks = new Map()

  const clearTaskTimers = (state) => {
    if (state.timerId) {
      clearTimeout(state.timerId)
      state.timerId = null
    }
  }

  const cleanupTask = (state) => {
    clearTaskTimers(state)
    if (state.abortController) {
      state.abortController.abort()
      state.abortController = null
    }
  }

  const stop = (taskId) => {
    const state = tasks.get(taskId)
    if (!state) return false

    state.active = false
    cleanupTask(state)
    tasks.delete(taskId)
    return true
  }

  const runTask = async (state) => {
    if (!state.active) return

    const controller = createSignal()
    state.abortController = controller

    try {
      await state.task.run({ signal: controller.signal, attempt: state.attempt + 1 })
      if (!state.active) return
      state.attempt = 0
      state.timerId = setTimeout(() => runTask(state), state.task.intervalMs)
    } catch (error) {
      if (!state.active) return

      if (controller.signal.aborted || error?.name === 'AbortError') {
        return
      }

      state.attempt += 1
      const backoffMs = Math.max(0, state.task.backoff(state.attempt, error))
      state.timerId = setTimeout(() => runTask(state), backoffMs)
    }
  }

  const start = (task) => {
    if (!task || typeof task !== 'object') {
      throw new Error('Polling task is required')
    }

    const { id, run, intervalMs = 5000, backoff = defaultBackoff } = task

    if (!id) throw new Error('Polling task id is required')
    if (typeof run !== 'function') throw new Error('Polling task run must be a function')
    if (tasks.has(id)) stop(id)

    const state = {
      task: {
        ...task,
        intervalMs: Math.max(0, Number(intervalMs) || 0),
        backoff,
      },
      attempt: 0,
      timerId: null,
      abortController: null,
      active: true,
    }

    tasks.set(id, state)
    runTask(state)
    return id
  }

  const stopAll = () => {
    Array.from(tasks.keys()).forEach((taskId) => {
      stop(taskId)
    })
  }

  return {
    start,
    stop,
    stopAll,
    size: () => tasks.size,
  }
}
