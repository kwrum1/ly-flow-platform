import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const { mockAuthAPI } = vi.hoisted(() => ({
  mockAuthAPI: {
    login: vi.fn(),
    logout: vi.fn(),
    profile: vi.fn(),
    changePassword: vi.fn(),
  },
}))

vi.mock('../api/auth', () => ({
  authAPI: mockAuthAPI,
}))

import { useAuthStore } from './auth'

function createStorage(initial = {}) {
  const store = new Map(Object.entries(initial).map(([key, value]) => [key, String(value)]))
  return {
    getItem: vi.fn((key) => (store.has(key) ? store.get(key) : null)),
    setItem: vi.fn((key, value) => {
      store.set(key, String(value))
    }),
    removeItem: vi.fn((key) => {
      store.delete(key)
    }),
  }
}

describe('auth store session lifecycle', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    vi.stubGlobal('localStorage', createStorage())
  })

  it('login persists token/user and password-change flag', async () => {
    mockAuthAPI.login.mockResolvedValue({
      token: 'tok-1',
      expires_at: '2026-01-01T00:00:00Z',
      needs_password_change: true,
      user: { id: 7, username: 'alice', role: 'admin' },
    })

    const store = useAuthStore()

    await store.login({ username: 'alice', password: 'password' })

    expect(store.token).toBe('tok-1')
    expect(store.needsPasswordChange).toBe(true)
    expect(store.user.username).toBe('alice')
    expect(localStorage.setItem).toHaveBeenCalledWith('token', 'tok-1')
    expect(localStorage.setItem).toHaveBeenCalledWith('needs_password_change', 'true')
  })

  it('login uses backend password-change flag rather than guessing from password', async () => {
    mockAuthAPI.login.mockResolvedValue({
      token: 'tok-plain',
      expires_at: '2026-01-01T00:00:00Z',
      needs_password_change: false,
      user: { id: 8, username: 'bob', role: 'viewer' },
    })

    const store = useAuthStore()
    await store.login({ username: 'bob', password: 'password' })

    expect(store.needsPasswordChange).toBe(false)
    expect(localStorage.setItem).not.toHaveBeenCalledWith('needs_password_change', 'true')
  })

  it('login rejects locked account responses and stores no token', async () => {
    mockAuthAPI.login.mockResolvedValue({
      token: '',
      account_locked: true,
      user: { username: 'locked', account_locked: true },
    })

    const store = useAuthStore()
    await expect(store.login({ username: 'locked', password: 'password' })).rejects.toThrow(/锁定/)

    expect(store.accountLocked).toBe(true)
    expect(store.token).toBe('')
    expect(localStorage.setItem).not.toHaveBeenCalledWith('token', expect.any(String))
  })

  it('initializeSession refreshes profile and clears unauthorized session', async () => {
    vi.stubGlobal('localStorage', createStorage({
      token: 'tok-x',
      username: 'bob',
      role: 'viewer',
      user_id: '99',
    }))

    mockAuthAPI.profile.mockRejectedValue({ code: 'API_UNAUTHORIZED', message: 'expired' })

    const store = useAuthStore()
    await store.initializeSession()

    expect(store.token).toBe('')
    expect(localStorage.removeItem).toHaveBeenCalledWith('token')
  })

  it('changePassword clears auth state but keeps password_changed marker', async () => {
    mockAuthAPI.changePassword.mockResolvedValue({ ok: true })

    const store = useAuthStore()
    store.token = 'tok-2'
    store.needsPasswordChange = true

    await store.changePassword({ oldPassword: 'password', newPassword: 'NewPass1!' })

    expect(store.token).toBe('')
    expect(store.needsPasswordChange).toBe(false)
    expect(store.passwordChanged).toBe(true)
    expect(localStorage.setItem).toHaveBeenCalledWith('password_changed', 'true')
  })
})
