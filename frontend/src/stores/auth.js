import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { authAPI } from '../api/auth'
import { API_ERROR_CODES, normalizeAuthPayload } from '../api/adapters'

const STORAGE_KEYS = {
  token: 'token',
  username: 'username',
  role: 'role',
  userId: 'user_id',
  user: 'user',
  userInfo: 'userInfo',
  needsPasswordChange: 'needs_password_change',
  passwordChanged: 'password_changed',
  accountLocked: 'account_locked',
}

function safeGetItem(key) {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function safeSetItem(key, value) {
  try {
    localStorage.setItem(key, String(value))
  } catch {
    // Storage can be unavailable in private mode or tests.
  }
}

function safeRemoveItem(key) {
  try {
    localStorage.removeItem(key)
  } catch {
    // Storage can be unavailable in private mode or tests.
  }
}

function toBoolean(value) {
  return value === true || value === 'true'
}

function normalizeUser(user = {}) {
  return {
    id: user.id,
    username: user.username || 'Admin',
    role: user.role || 'admin',
    is_active: user.is_active ?? user.isActive,
    needs_password_change: user.needs_password_change ?? user.needsPasswordChange,
  }
}

function parseJSON(value) {
  if (!value) return null
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref('')
  const user = ref(null)
  const expiresAt = ref('')
  const needsPasswordChange = ref(false)
  const passwordChanged = ref(false)
  const accountLocked = ref(false)

  const isAuthenticated = computed(() => Boolean(token.value))

  const hydrateFromStorage = () => {
    token.value = safeGetItem(STORAGE_KEYS.token) || ''
    const storedUser = parseJSON(safeGetItem(STORAGE_KEYS.user))
    const fallbackUser = {
      id: safeGetItem(STORAGE_KEYS.userId) || undefined,
      username: safeGetItem(STORAGE_KEYS.username) || 'Admin',
      role: safeGetItem(STORAGE_KEYS.role) || 'admin',
    }
    user.value = normalizeUser(storedUser || fallbackUser)
    expiresAt.value = safeGetItem('session_expires_at') || ''
    needsPasswordChange.value = toBoolean(safeGetItem(STORAGE_KEYS.needsPasswordChange))
    passwordChanged.value = toBoolean(safeGetItem(STORAGE_KEYS.passwordChanged))
    accountLocked.value = toBoolean(safeGetItem(STORAGE_KEYS.accountLocked))
  }

  const syncUserStorage = (nextUser) => {
    const normalized = normalizeUser(nextUser)
    user.value = normalized
    safeSetItem(STORAGE_KEYS.username, normalized.username)
    safeSetItem(STORAGE_KEYS.role, normalized.role)
    if (normalized.id !== undefined && normalized.id !== null) {
      safeSetItem(STORAGE_KEYS.userId, normalized.id)
    }
    safeSetItem(STORAGE_KEYS.user, JSON.stringify(normalized))
    safeSetItem(STORAGE_KEYS.userInfo, JSON.stringify(normalized))
  }

  const clearSession = ({ preservePasswordChanged = false } = {}) => {
    token.value = ''
    user.value = null
    expiresAt.value = ''
    needsPasswordChange.value = false
    accountLocked.value = false

    safeRemoveItem(STORAGE_KEYS.token)
    safeRemoveItem(STORAGE_KEYS.username)
    safeRemoveItem(STORAGE_KEYS.role)
    safeRemoveItem(STORAGE_KEYS.userId)
    safeRemoveItem(STORAGE_KEYS.user)
    safeRemoveItem(STORAGE_KEYS.userInfo)
    safeRemoveItem(STORAGE_KEYS.needsPasswordChange)
    safeRemoveItem(STORAGE_KEYS.accountLocked)
    safeRemoveItem('session_expires_at')

    if (preservePasswordChanged) {
      passwordChanged.value = true
      safeSetItem(STORAGE_KEYS.passwordChanged, 'true')
      return
    }

    passwordChanged.value = false
    safeRemoveItem(STORAGE_KEYS.passwordChanged)
  }

  const login = async (credentials) => {
    const payload = normalizeAuthPayload(await authAPI.login(credentials))
    accountLocked.value = payload.locked
    if (payload.locked) {
      safeSetItem(STORAGE_KEYS.accountLocked, 'true')
      throw new Error('账号已锁定')
    }

    const nextToken = payload.token || ''
    if (!nextToken) {
      throw new Error('登录响应缺少 token')
    }

    token.value = nextToken
    expiresAt.value = payload.expiresAt || ''
    safeSetItem(STORAGE_KEYS.token, nextToken)
    if (expiresAt.value) safeSetItem('session_expires_at', expiresAt.value)

    const requirePasswordChange = payload.needsPasswordChange
    needsPasswordChange.value = requirePasswordChange
    if (requirePasswordChange) {
      safeSetItem(STORAGE_KEYS.needsPasswordChange, 'true')
    } else {
      safeRemoveItem(STORAGE_KEYS.needsPasswordChange)
    }

    passwordChanged.value = false
    safeRemoveItem(STORAGE_KEYS.passwordChanged)

    syncUserStorage(payload.user || {})
    return payload
  }

  const logout = async () => {
    try {
      if (token.value) await authAPI.logout()
    } finally {
      clearSession()
    }
  }

  const fetchProfile = async () => {
    const payload = await authAPI.profile()
    syncUserStorage(payload || {})
    const nextNeedsPasswordChange = Boolean(payload?.needs_password_change || payload?.needsPasswordChange)
    needsPasswordChange.value = nextNeedsPasswordChange
    if (nextNeedsPasswordChange) {
      safeSetItem(STORAGE_KEYS.needsPasswordChange, 'true')
    } else {
      safeRemoveItem(STORAGE_KEYS.needsPasswordChange)
    }
    return user.value
  }

  const changePassword = async ({ oldPassword, newPassword }) => {
    const payload = await authAPI.changePassword({
      old_password: oldPassword,
      new_password: newPassword,
    })
    clearSession({ preservePasswordChanged: true })
    return payload
  }

  const initializeSession = async () => {
    hydrateFromStorage()
    if (!token.value) return

    try {
      await fetchProfile()
    } catch (error) {
      if (error?.code === API_ERROR_CODES.UNAUTHORIZED) {
        clearSession({ preservePasswordChanged: passwordChanged.value })
        return
      }
      throw error
    }
  }

  return {
    token,
    user,
    expiresAt,
    needsPasswordChange,
    passwordChanged,
    accountLocked,
    isAuthenticated,
    hydrateFromStorage,
    initializeSession,
    clearSession,
    login,
    logout,
    fetchProfile,
    changePassword,
  }
})
