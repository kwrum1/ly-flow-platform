import { describe, expect, it } from 'vitest'
import { evaluateAuthGuard } from './guard'

describe('商业化路由认证行为', () => {
  it('未认证用户进入受保护页面时跳转登录页', () => {
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

  it('首次登录改密流程保持强制', () => {
    const result = evaluateAuthGuard({
      toPath: '/overview',
      requiresAuth: true,
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: true,
      passwordChanged: false,
    })

    expect(result).toBe('/change-password')
  })

  it('完成改密后允许进入攻击链工作台', () => {
    const result = evaluateAuthGuard({
      toPath: '/xdr',
      requiresAuth: true,
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: false,
      passwordChanged: true,
    })

    expect(result).toBe(true)
  })

  it('管理员可以进入用户管理路由', () => {
    const result = evaluateAuthGuard({
      toPath: '/users',
      requiresAuth: true,
      roles: ['admin'],
      isAuthenticated: true,
      token: 'token',
      needsPasswordChange: false,
      passwordChanged: true,
      userRole: 'admin',
    })

    expect(result).toBe(true)
  })
})
