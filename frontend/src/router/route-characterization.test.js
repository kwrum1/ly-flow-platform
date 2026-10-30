import { beforeEach, describe, expect, it, vi } from 'vitest'

const routerCapture = vi.hoisted(() => ({ routes: [] }))

vi.mock('vue-router', () => ({
  createWebHistory: () => ({}),
  createRouter: ({ routes }) => {
    routerCapture.routes = routes
    return { beforeEach: vi.fn() }
  },
}))

describe('v4 route characterization', () => {
  beforeEach(async () => {
    routerCapture.routes = []
    vi.resetModules()
    await import('./index')
  })

  it('records the v4 route count and protected roles', () => {
    const shell = routerCapture.routes.find((route) => Array.isArray(route.children))
    const protectedRoutes = shell?.children ?? []
    const routeCount = routerCapture.routes.length + protectedRoutes.length

    expect(routeCount).toBe(35)
    expect(protectedRoutes).toHaveLength(30)
    expect(protectedRoutes.find((route) => route.path === 'overview')?.name).toBe('Overview')
    expect(protectedRoutes.find((route) => route.path === 'assets')?.name).toBe('Assets')
    const adminRoutes = protectedRoutes.filter((route) => route.meta?.roles?.length)
    expect(adminRoutes.every((route) => route.meta.roles.join(',') === 'admin')).toBe(true)
    expect(protectedRoutes.find((route) => route.path === 'forbidden')?.meta?.roles).toBeUndefined()
  })

  it('folds legacy routes into the v4 surfaces', () => {
    const shell = routerCapture.routes.find((route) => Array.isArray(route.children))
    const protectedRoutes = shell?.children ?? []
    const redirects = Object.fromEntries(
      protectedRoutes.filter((route) => route.redirect).map((route) => [route.path, route.redirect]),
    )

    expect(redirects).toMatchObject({
      dashboard: '/overview',
      'traffic-threats': '/threats',
      runtime: '/threats',
      rasp: '/threats',
      'data-quality': '/health',
      engines: '/health',
      'control-center': '/settings',
      users: '/settings',
      'install-config': '/settings',
      response: '/incidents',
      evidence: '/incidents',
      timeline: '/incidents',
      'situation/global': '/overview',
    })
  })

  it('records the unknown-path dashboard fallback', () => {
    const fallback = routerCapture.routes.find((route) => route.path === '/:pathMatch(.*)*')
    expect(fallback).toEqual({ path: '/:pathMatch(.*)*', redirect: '/dashboard' })
  })
})
