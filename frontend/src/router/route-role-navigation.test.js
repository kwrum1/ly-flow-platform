import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

// Exercise the real vue-router + real guard, with an in-memory history so the
// test does not need jsdom's history API.
vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, createWebHistory: () => actual.createMemoryHistory() }
})

const { default: router } = await import('./index')
const { useAuthStore } = await import('../stores/auth')

function createStorage(initial = {}) {
  const map = new Map(Object.entries(initial).map(([key, value]) => [key, String(value)]))
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => {
      map.set(key, String(value))
    },
    removeItem: (key) => {
      map.delete(key)
    },
  }
}

/** Every path the router knows about, used to prove each role's real landing page. */
const ALL_PATHS = [
  '/', '/overview', '/incidents', '/events', '/threats', '/assets', '/health', '/rules', '/settings',
  '/forbidden', '/dashboard', '/situation/global', '/traffic-threats', '/traffic-observe', '/runtime',
  '/rasp', '/application-threats', '/system-security-audit', '/data-quality', '/engines',
  '/control-center', '/install-config', '/users', '/response', '/evidence', '/timeline', '/xdr',
  '/host-ops', '/real-time-posture', '/rule-visibility', '/rule-updates',
]

async function landOn(role, path) {
  vi.stubGlobal('localStorage', createStorage({ token: 'token', role, needs_password_change: 'false', password_changed: 'true' }))
  setActivePinia(createPinia())
  const store = useAuthStore()
  store.token = 'token'
  store.user = { id: 1, username: role, role }

  await router.replace('/change-password')
  const failure = await router.push(path).catch((error) => error)
  if (failure && failure.name !== 'NavigationFailure') throw failure
  return router.currentRoute.value.path
}

const VIEWER_LANDING = {
  '/': '/overview',
  '/overview': '/overview',
  '/events': '/events',
  '/threats': '/threats',
  '/dashboard': '/overview',
  '/situation/global': '/overview',
  '/traffic-threats': '/threats',
  '/traffic-observe': '/threats',
  '/runtime': '/threats',
  '/rasp': '/threats',
  '/application-threats': '/threats',
  '/system-security-audit': '/threats',
  '/real-time-posture': '/overview',
  '/forbidden': '/forbidden',
}

const ANALYST_LANDING = {
  ...VIEWER_LANDING,
  '/incidents': '/incidents',
  '/assets': '/assets',
  '/response': '/incidents',
  '/evidence': '/incidents',
  '/timeline': '/incidents',
  '/xdr': '/incidents',
  '/host-ops': '/assets',
}

beforeEach(async () => {
  vi.stubGlobal('localStorage', createStorage({ token: 'token', role: 'admin', needs_password_change: 'false', password_changed: 'true' }))
  setActivePinia(createPinia())
  const store = useAuthStore()
  store.token = 'token'
  store.user = { id: 1, username: 'admin', role: 'admin' }
  await router.replace('/login')
})

describe('real router navigation per role', () => {
  it('lets a viewer reach exactly the read-only posture surfaces', async () => {
    const observed = {}
    for (const path of ALL_PATHS) observed[path] = await landOn('viewer', path)

    for (const [path, expected] of Object.entries(VIEWER_LANDING)) {
      expect(observed[path], `viewer on ${path}`).toBe(expected)
    }
    // Everything else must land on the denial page, never on a blank or 404 page.
    for (const path of ALL_PATHS) {
      if (path in VIEWER_LANDING) continue
      expect(observed[path], `viewer on ${path}`).toBe('/forbidden')
    }
  })

  it('lets an analyst operate but not touch admin-only configuration', async () => {
    const observed = {}
    for (const path of ALL_PATHS) observed[path] = await landOn('analyst', path)

    for (const [path, expected] of Object.entries(ANALYST_LANDING)) {
      expect(observed[path], `analyst on ${path}`).toBe(expected)
    }
    for (const path of ['/health', '/rules', '/settings', '/users', '/install-config', '/control-center', '/rule-visibility', '/rule-updates']) {
      expect(observed[path], `analyst on ${path}`).toBe('/forbidden')
    }
  })

  it('lets an admin reach every route without a denial bounce', async () => {
    for (const path of ALL_PATHS.filter((item) => item !== '/forbidden')) {
      expect(await landOn('admin', path), `admin on ${path}`).not.toBe('/forbidden')
    }
  })

  it('sends a signed-in viewer from an unknown path to a page they may open', async () => {
    expect(await landOn('viewer', '/does-not-exist')).toBe('/overview')
    expect(await landOn('analyst', '/does-not-exist')).toBe('/overview')
  })

  it('lands a viewer on /overview right after the login redirect', async () => {
    // Login.vue pushes '/dashboard'; the guard bounces authenticated off
    // /login to '/dashboard' too. Neither may dead-end on /forbidden.
    for (const entry of ['/dashboard', '/login']) {
      expect(await landOn('viewer', entry), `viewer entering via ${entry}`).toBe('/overview')
    }
  })
})
