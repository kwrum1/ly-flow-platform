import axios from 'axios'
import { ElMessage } from 'element-plus'
import { API_ERROR_CODES, createAPIError, toAPIError, unwrapAPIEnvelope } from './adapters'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

function clearSession() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  localStorage.removeItem('userInfo')
  localStorage.removeItem('username')
  localStorage.removeItem('role')
  localStorage.removeItem('user_id')
  localStorage.removeItem('needs_password_change')
  localStorage.removeItem('session_expires_at')
}

function redirectToLogin() {
  if (typeof window === 'undefined') return
  if (window.location?.pathname === '/login') return
  window.location.href = '/login'
}

function normalizeAxiosError(error) {
  const requestUrl = String(error?.config?.url || '')
  if (error?.code === 'ERR_CANCELED' || axios.isCancel(error)) {
    return createAPIError({
      code: API_ERROR_CODES.REQUEST_CANCELED,
      message: '请求已取消',
      cause: error,
    })
  }

  const status = error?.response?.status
  if (status === 401) {
    const serverMessage = error?.response?.data?.message || error?.response?.data?.msg || ''
    if (requestUrl.includes('/auth/login')) {
      return createAPIError({
        code: 'API_LOGIN_FAILED',
        message: '账号或密码不正确',
        status,
        cause: error,
      })
    }
    if (requestUrl.includes('/auth/change-password')) {
      return createAPIError({
        code: 'API_PASSWORD_CHANGE_FAILED',
        message: serverMessage === 'incorrect old password' ? '当前密码不正确' : '密码修改失败，请检查输入',
        status,
        cause: error,
      })
    }
    return createAPIError({
      code: API_ERROR_CODES.UNAUTHORIZED,
      message: '登录已过期，请重新登录',
      status,
      cause: error,
    })
  }

  if (error?.code === 'ECONNABORTED' || /timeout/i.test(error?.message || '')) {
    return createAPIError({
      code: API_ERROR_CODES.TIMEOUT,
      message: '请求超时，请稍后重试',
      status,
      cause: error,
    })
  }

  if (status) {
    const serverMessage = error?.response?.data?.message || error?.response?.data?.msg || ''
    const messageMap = {
      'new password must be at least 8 characters': '新密码至少 8 位',
      'new password must contain an uppercase letter': '新密码必须包含至少 1 个大写字母',
      'new password must contain a special character': '新密码必须包含特殊字符，例如 ， 。 / ! @ #',
      'username already exists': '账号已存在',
      'invalid username or password': '账号或密码不正确',
      'account is disabled': '账号已停用',
      'cannot delete yourself': '不能删除当前登录账号',
      'cannot disable yourself': '不能停用当前登录账号',
      'user not found': '用户不存在',
      'invalid role': '角色不合法',
    }
    return createAPIError({
      code: `HTTP_${status}`,
      message: messageMap[serverMessage] || serverMessage || `请求失败 (${status})`,
      status,
      cause: error,
    })
  }

  if (error?.request) {
    return createAPIError({
      code: API_ERROR_CODES.NETWORK,
      message: '网络异常，请检查连接',
      cause: error,
    })
  }

  return toAPIError(error)
}

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers = config.headers || {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  response => {
    try {
      return unwrapAPIEnvelope(response.data)
    } catch (error) {
      const normalized = toAPIError(error)
      ElMessage.error(normalized.message)
      return Promise.reject(normalized)
    }
  },
  error => {
    const normalized = normalizeAxiosError(error)

    if (normalized.code === API_ERROR_CODES.UNAUTHORIZED) {
      clearSession()
      redirectToLogin()
    }

    if (normalized.code !== API_ERROR_CODES.REQUEST_CANCELED) {
      ElMessage.error(normalized.message)
    }

    return Promise.reject(normalized)
  }
)

export function createRequestController() {
  return new AbortController()
}

export function isRequestCanceled(error) {
  return error?.code === API_ERROR_CODES.REQUEST_CANCELED || error?.code === 'ERR_CANCELED'
}

export { API_ERROR_CODES }

export default api
