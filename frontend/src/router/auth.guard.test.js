import { describe, expect, it } from 'vitest'
import { evaluateAuthGuard } from './guard'

describe('流影访问守卫', () => {
  it('允许未登录用户访问登录页', () => {
    const result = evaluateAuthGuard({
      toPath: '/login',
      requiresAuth: false,
      isAuthenticated: false,
      token: '',
      needsPasswordChange: false,
      passwordChanged: false,
    })

    expect(result).toBe(true)
  })

  it('未登录访问受保护页面时进入登录页', () => {
    const result = evaluateAuthGuard({
      toPath: '/xdr',
      requiresAuth: true,
      isAuthenticated: false,
      token: '',
      needsPasswordChange: false,
      passwordChanged: false,
    })

    expect(result).toBe('/login')
  })

  it('已完成认证且无需改密时登录页跳转攻击链工作台', () => {
    const result = evaluateAuthGuard({
      toPath: '/login',
      requiresAuth: false,
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: false,
      passwordChanged: false,
    })

    expect(result).toBe('/xdr')
  })

  it('首次登录必须先进入改密页面', () => {
    const result = evaluateAuthGuard({
      toPath: '/xdr',
      requiresAuth: true,
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: true,
      passwordChanged: false,
    })

    expect(result).toBe('/change-password')
  })

  it('普通查看用户不能进入管理员路由', () => {
    const result = evaluateAuthGuard({
      toPath: '/users',
      requiresAuth: true,
      roles: ['admin'],
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: false,
      passwordChanged: true,
      userRole: 'viewer',
    })

    expect(result).toBe('/forbidden')
  })
})
