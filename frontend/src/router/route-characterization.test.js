import { beforeEach, describe, expect, it, vi } from 'vitest'

import { V4_NAVIGATION } from '../v4/navigation'
import { evaluateAuthGuard } from './guard'
import { ADMIN_ROLES, ALL_ROLES, OPERATOR_ROLES, ROLE_SETS } from './roles'

const routerCapture = vi.hoisted(() => ({ routes: [] }))

vi.mock('vue-router', () => ({
  createWebHistory: () => ({}),
  createRouter: ({ routes }) => {
    routerCapture.routes = routes
    return { beforeEach: vi.fn() }
  },
}))

const ALL = [...ALL_ROLES]
const OPERATOR = [...OPERATOR_ROLES]
const ADMIN = [...ADMIN_ROLES]

/**
 * Backend-derived expectation table.
 *
 * Source of truth: `server/cmd/route_registry.go` (`allRoles`,
 * `operatorRoles`, `adminRoles`) and the `adminOnly` set in
 * `server/cmd/route_registry_data.go`. Default read access is allRoles,
 * default write access is operatorRoles, and every path listed in
 * `adminOnly` is adminRoles for both read and write.
 *
 * Each entry lists the APIs the page actually calls, so a role is only
 * granted when the backend would answer every one of those calls:
 *
 *   overview        GET /unified/events, /incidents, /agents, /assets      -> allRoles
 *   events          GET /unified/events, /agents                          -> allRoles
 *   threats         GET /threats/{category}, /component-alerts/{category},
 *                       /unified/events, /agents                          -> allRoles
 *   incidents       GET /incidents + PUT /incidents/{id}/(status|assign)   -> read allRoles, write operatorRoles
 *   assets          GET /assets,/agents,/defense/* + writes to /agents/,
 *                   /agent/{capabilities,name,tags}/, /defense/*,
 *                   /rasp/policy/actions/*                               -> write operatorRoles
 *   health          GET /debug/components (adminOnly), /engine-health,
 *                       /system/time                                     -> adminRoles
 *   rules           /rules and /rule-platform/* are adminOnly             -> adminRoles
 *   settings        GET /auth/users is adminOnly                          -> adminRoles
 */
const EXPECTED_ROLES = {
  overview: ALL,
  incidents: OPERATOR,
  events: ALL,
  threats: ALL,
  assets: OPERATOR,
  health: ADMIN,
  rules: ADMIN,
  settings: ADMIN,

  // Legacy aliases keep the roles of the surface they land on.
  dashboard: ALL,
  'situation/global': ALL,
  'traffic-threats': ALL,
  'traffic-observe': ALL,
  runtime: ALL,
  rasp: ALL,
  'application-threats': ALL,
  'system-security-audit': ALL,
  'real-time-posture': ALL,
  'data-quality': ADMIN,
  engines: ADMIN,
  'control-center': ADMIN,
  'install-config': ADMIN,
  users: ADMIN,
  response: OPERATOR,
  evidence: OPERATOR,
  timeline: OPERATOR,
  xdr: OPERATOR,
  'host-ops': OPERATOR,
  'rule-visibility': ADMIN,
  'rule-updates': ADMIN,
}

function shellRoutes() {
  const shell = routerCapture.routes.find((route) => Array.isArray(route.children))
  return shell?.children ?? []
}

function rolesKey(roles) {
  return Array.isArray(roles) ? roles.join(',') : ''
}

beforeEach(async () => {
  routerCapture.routes = []
  vi.resetModules()
  await import('./index')
})

describe('v4 route characterization', () => {
  it('records the v4 route count and protected roles', () => {
    const protectedRoutes = shellRoutes()
    const routeCount = routerCapture.routes.length + protectedRoutes.length

    expect(routeCount).toBe(35)
    expect(protectedRoutes).toHaveLength(30)
    expect(protectedRoutes.find((route) => route.path === 'overview')?.name).toBe('Overview')
    expect(protectedRoutes.find((route) => route.path === 'assets')?.name).toBe('Assets')
    expect(protectedRoutes.find((route) => route.path === 'forbidden')?.meta?.roles).toBeUndefined()
  })

  it('only uses the three backend role groups', () => {
    const allowed = ROLE_SETS.map(rolesKey)
    const routes = shellRoutes()
    const withRoles = routes.filter((route) => Array.isArray(route.meta?.roles))

    // 30 children, 29 carry roles: only /forbidden is intentionally open.
    expect(withRoles).toHaveLength(29)
    expect(routes.filter((route) => !route.meta?.roles)).toHaveLength(1)

    for (const route of withRoles) {
      expect(allowed, `${route.path} has a non-backend role set`).toContain(rolesKey(route.meta.roles))
    }

    const fallback = routerCapture.routes.find((route) => route.path === '/:pathMatch(.*)*')
    expect(fallback.meta?.roles).toBeUndefined()
  })

  it('matches the backend policy group of every route', () => {
    const byPath = Object.fromEntries(shellRoutes().map((route) => [route.path, route]))
    expect(Object.keys(EXPECTED_ROLES).sort()).toEqual(
      Object.keys(byPath).filter((path) => path !== 'forbidden').sort(),
    )

    for (const [path, roles] of Object.entries(EXPECTED_ROLES)) {
      expect(byPath[path], `${path} is missing`).toBeTruthy()
      expect(byPath[path].meta?.roles, `${path} role mismatch`).toEqual(roles)
    }
  })

  it('keeps at least one viewer page and at least one admin-only page', () => {
    const routes = shellRoutes()
    const readableByViewer = routes.filter((route) => route.meta?.roles?.includes('viewer'))
    const adminOnly = routes.filter((route) => rolesKey(route.meta?.roles) === rolesKey(ADMIN))

    expect(readableByViewer.map((route) => route.path).sort()).toEqual(
      [
        'application-threats',
        'dashboard',
        'events',
        'overview',
        'rasp',
        'real-time-posture',
        'runtime',
        'situation/global',
        'system-security-audit',
        'threats',
        'traffic-observe',
        'traffic-threats',
      ].sort(),
    )
    expect(adminOnly.map((route) => route.path)).toEqual(
      expect.arrayContaining(['health', 'rules', 'settings', 'users', 'install-config', 'control-center']),
    )

    // viewer must never reach a page with a write action or admin-only config
    for (const blocked of ['incidents', 'assets', 'health', 'rules', 'settings']) {
      expect(routes.find((route) => route.path === blocked)?.meta?.roles).not.toContain('viewer')
    }
  })

  it('folds legacy routes into the v4 surfaces', () => {
    const redirects = Object.fromEntries(
      shellRoutes().filter((route) => route.redirect).map((route) => [route.path, route.redirect]),
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

  it('records the unknown-path dashboard fallback that every role can open', () => {
    const fallback = routerCapture.routes.find((route) => route.path === '/:pathMatch(.*)*')
    expect(fallback).toEqual({ path: '/:pathMatch(.*)*', redirect: '/dashboard' })

    const dashboard = shellRoutes().find((route) => route.path === 'dashboard')
    expect(dashboard?.meta?.roles).toEqual(ALL)
  })
})

describe('v4 route guard role decisions', () => {
  const base = {
    requiresAuth: true,
    isAuthenticated: true,
    token: 'token',
    needsPasswordChange: false,
    passwordChanged: true,
  }

  function routesFor(path) {
    const route = shellRoutes().find((item) => item.path === path)
    return route?.meta?.roles ?? []
  }

  it('lets a viewer open read-only posture pages', () => {
    for (const path of ['/overview', '/events', '/threats']) {
      expect(evaluateAuthGuard({ ...base, toPath: path, roles: routesFor(path.slice(1)), userRole: 'viewer' })).toBe(true)
    }
  })

  it('sends a viewer to the denial page for operator and admin pages', () => {
    for (const path of ['/incidents', '/assets', '/health', '/rules', '/settings']) {
      expect(evaluateAuthGuard({ ...base, toPath: path, roles: routesFor(path.slice(1)), userRole: 'viewer' })).toBe('/forbidden')
    }
  })

  it('lets an analyst operate but not configure', () => {
    for (const path of ['/overview', '/events', '/threats', '/incidents', '/assets']) {
      expect(evaluateAuthGuard({ ...base, toPath: path, roles: routesFor(path.slice(1)), userRole: 'analyst' })).toBe(true)
    }
    for (const path of ['/health', '/rules', '/settings']) {
      expect(evaluateAuthGuard({ ...base, toPath: path, roles: routesFor(path.slice(1)), userRole: 'analyst' })).toBe('/forbidden')
    }
  })

  it('keeps the denial page reachable for every signed-in role', () => {
    for (const role of ALL) {
      expect(evaluateAuthGuard({ ...base, toPath: '/forbidden', roles: [], userRole: role })).toBe(true)
    }
  })

  it('never advertises a rail entry the guard would deny', () => {
    const routes = shellRoutes()
    for (const item of V4_NAVIGATION.flatMap((group) => group.items)) {
      const path = item.path.slice(1)
      const route = routes.find((record) => record.path === path)
      expect(route, `rail entry ${item.path} has no route`).toBeTruthy()
      expect(item.roles, `rail entry ${item.path} drifted from its route`).toEqual(route.meta?.roles)
      for (const role of ALL) {
        const decision = evaluateAuthGuard({ ...base, toPath: item.path, roles: route.meta?.roles ?? [], userRole: role })
        expect(decision === true, `rail entry ${item.path} is denied to ${role}`).toBe(item.roles.includes(role))
      }
    }
  })

  it('still asks unauthenticated visitors to sign in before any role decision', () => {
    expect(evaluateAuthGuard({
      toPath: '/overview',
      requiresAuth: true,
      isAuthenticated: false,
      token: '',
      needsPasswordChange: false,
      passwordChanged: false,
      roles: routesFor('overview'),
      userRole: '',
    })).toBe('/login')
  })
})
