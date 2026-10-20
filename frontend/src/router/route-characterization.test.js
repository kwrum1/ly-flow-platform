import { beforeEach, describe, expect, it, vi } from 'vitest'

const routerCapture = vi.hoisted(() => ({ routes: [] }))

vi.mock('vue-router', () => ({
  createWebHistory: () => ({}),
  createRouter: ({ routes }) => {
    routerCapture.routes = routes
    return { beforeEach: vi.fn() }
  },
}))

describe('current route characterization', () => {
  beforeEach(async () => {
    routerCapture.routes = []
    vi.resetModules()
    await import('./index')
  })

  it('records the current route count and protected roles', () => {
    const shell = routerCapture.routes.find((route) => Array.isArray(route.children))
    const protectedRoutes = shell?.children ?? []
    const routeCount = routerCapture.routes.length + protectedRoutes.length

    expect(routeCount).toBe(31)
    expect(protectedRoutes).toHaveLength(26)
    expect(protectedRoutes.every((route) => route.meta?.roles?.join(',') === 'admin')).toBe(true)
  })

  it('records the current unknown-path dashboard fallback', () => {
    const fallback = routerCapture.routes.find((route) => route.path === '/:pathMatch(.*)*')

    expect(fallback).toEqual({
      path: '/:pathMatch(.*)*',
      redirect: '/dashboard',
    })
  })
})

