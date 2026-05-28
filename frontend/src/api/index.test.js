import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockRequestUse = vi.fn()
const mockResponseUse = vi.fn()
const mockIsCancel = vi.fn(() => false)

vi.mock('axios', () => {
  const instance = {
    interceptors: {
      request: { use: mockRequestUse },
      response: { use: mockResponseUse },
    },
  }

  return {
    default: {
      create: vi.fn(() => instance),
      isCancel: mockIsCancel,
    },
  }
})

const mockMessageError = vi.fn()
vi.mock('element-plus', () => ({
  ElMessage: {
    error: mockMessageError,
  },
}))

describe('API client interceptor behavior', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    mockRequestUse.mockImplementation(() => 0)
    mockResponseUse.mockImplementation(() => 0)
    mockIsCancel.mockReturnValue(false)

    const store = new Map()
    vi.stubGlobal('localStorage', {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
      removeItem: (key) => store.delete(key),
      clear: () => store.clear(),
    })

    vi.stubGlobal('window', {
      location: { href: '/dashboard', pathname: '/dashboard' },
    })
  })

  it('normalizes 401, timeout, envelope errors and cancellation support', async () => {
    const module = await import('./index')
    const { API_ERROR_CODES, createRequestController, isRequestCanceled } = module

    expect(mockRequestUse).toHaveBeenCalledTimes(1)
    expect(mockResponseUse).toHaveBeenCalledTimes(1)

    const requestOnFulfilled = mockRequestUse.mock.calls[0][0]
    const responseOnFulfilled = mockResponseUse.mock.calls[0][0]
    const responseOnRejected = mockResponseUse.mock.calls[0][1]

    localStorage.setItem('token', 'abc-token')
    const config = requestOnFulfilled({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer abc-token')

    await expect(responseOnRejected({ response: { status: 401 } })).rejects.toMatchObject({
      code: API_ERROR_CODES.UNAUTHORIZED,
    })
    expect(localStorage.getItem('token')).toBeNull()
    expect(window.location.href).toBe('/login')

    await expect(
      responseOnRejected({ code: 'ECONNABORTED', message: 'timeout of 30000ms exceeded' })
    ).rejects.toMatchObject({ code: API_ERROR_CODES.TIMEOUT })

    expect(responseOnFulfilled({ data: { code: 0 } })).toEqual({})

    await expect(responseOnRejected({ code: 'ERR_CANCELED', message: 'canceled' })).rejects.toMatchObject({
      code: API_ERROR_CODES.REQUEST_CANCELED,
    })

    const controller = createRequestController()
    expect(controller).toBeInstanceOf(AbortController)
    expect(controller.signal.aborted).toBe(false)
    controller.abort()
    expect(controller.signal.aborted).toBe(true)

    expect(isRequestCanceled({ code: 'ERR_CANCELED' })).toBe(true)
    expect(isRequestCanceled({ code: API_ERROR_CODES.REQUEST_CANCELED })).toBe(true)
  })

  it('does not clear session or redirect for login and password-change validation failures', async () => {
    await import('./index')
    const responseOnRejected = mockResponseUse.mock.calls[0][1]
    localStorage.setItem('token', 'keep-token')

    await expect(responseOnRejected({ config: { url: '/auth/login' }, response: { status: 401, data: { message: 'invalid username or password' } } })).rejects.toMatchObject({
      code: 'API_LOGIN_FAILED',
      message: '账号或密码不正确',
    })
    expect(localStorage.getItem('token')).toBe('keep-token')
    expect(window.location.href).toBe('/dashboard')

    await expect(responseOnRejected({ config: { url: '/auth/change-password' }, response: { status: 401, data: { message: 'incorrect old password' } } })).rejects.toMatchObject({
      code: 'API_PASSWORD_CHANGE_FAILED',
      message: '当前密码不正确',
    })
    expect(localStorage.getItem('token')).toBe('keep-token')
    expect(window.location.href).toBe('/dashboard')
  })
})
