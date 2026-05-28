const { test, expect } = require('@playwright/test')

const EVENTS_ENDPOINT_PATTERN = '**/api/v1/events**'

function makeAuthSeed(role) {
  return {
    token: 'e2e-token',
    role,
    username: `e2e-${role}`,
    user: JSON.stringify({ id: '1', username: `e2e-${role}`, role }),
    userInfo: JSON.stringify({ id: '1', username: `e2e-${role}`, role }),
    password_changed: 'true',
  }
}

const AUTH_SEED = makeAuthSeed('admin')

function fulfillEvents(route, items = [], total = items.length) {
  return route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      code: 0,
      data: {
        items,
        total,
      },
    }),
  })
}

async function seedAuth(page, role) {
  const seed = makeAuthSeed(role)
  await page.addInitScript((nextSeed) => {
    Object.entries(nextSeed).forEach(([key, value]) => {
      localStorage.setItem(key, value)
    })
  }, seed)

  await page.route('**/api/v1/auth/profile**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      code: 0,
      data: { id: '1', username: `e2e-${role}`, role },
    }),
  }))
}

test.beforeEach(async ({ page }) => {
  await seedAuth(page, AUTH_SEED.role)
})

test('shows attack queue title and keeps P1/P2 events first on initial screen', async ({ page }) => {
  await page.route(EVENTS_ENDPOINT_PATTERN, (route) => fulfillEvents(route, [
    {
      id: 'evt-medium',
      timestamp: '2026-01-02T00:00:00Z',
      severity: 'medium',
      status: 'new',
      event_type: 'runtime',
      message: 'medium event',
      src_ip: '10.0.0.2',
      dst_ip: '10.0.0.3',
    },
    {
      id: 'evt-high',
      timestamp: '2026-01-02T00:01:00Z',
      severity: 'high',
      status: 'open',
      event_type: 'dpi',
      message: 'high event',
      src_ip: '10.0.0.4',
      dst_ip: '10.0.0.5',
    },
    {
      id: 'evt-critical',
      timestamp: '2026-01-02T00:02:00Z',
      severity: 'critical',
      status: 'new',
      event_type: 'xdr',
      message: 'critical event',
      src_ip: '10.0.0.6',
      dst_ip: '10.0.0.7',
    },
  ]))

  await page.goto('/events')

  await expect(page.getByTestId('attack-queue-title')).toBeVisible()

  const rows = page.getByTestId('attack-queue-row')
  await expect(rows).toHaveCount(2)
  await expect(rows.nth(0)).toHaveAttribute('data-priority', 'P1')
  await expect(rows.nth(1)).toHaveAttribute('data-priority', 'P2')
})

test('shows empty state copy when no events are returned', async ({ page }) => {
  await page.route(EVENTS_ENDPOINT_PATTERN, (route) => fulfillEvents(route, []))

  await page.goto('/events')

  await expect(page.getByTestId('attack-queue-title')).toBeVisible()
  await expect(page.getByTestId('attack-queue-empty-state')).toBeVisible()
  await expect(page.getByTestId('attack-queue-empty-state')).toContainText('暂无匹配事件')
})

test('viewer hides admin-only navigation entries in sidebar', async ({ page }) => {
  await seedAuth(page, 'viewer')

  await page.route(EVENTS_ENDPOINT_PATTERN, (route) => fulfillEvents(route, []))

  await page.goto('/events')

  await expect(page.getByTestId('nav-item-intelligence-rules')).toHaveCount(0)
  await expect(page.getByTestId('nav-item-control')).toHaveCount(0)
})

test('admin sees admin-only navigation entries in sidebar', async ({ page }) => {
  await page.route(EVENTS_ENDPOINT_PATTERN, (route) => fulfillEvents(route, []))

  await page.goto('/events')

  await expect(page.getByTestId('nav-item-intelligence-rules')).toBeVisible()
  await expect(page.getByTestId('nav-item-control')).toBeVisible()
})

test('shows error copy and retry entry on request failure', async ({ page }) => {
  let requestCount = 0

  await page.route(EVENTS_ENDPOINT_PATTERN, (route) => {
    requestCount += 1

    if (requestCount === 1) {
      return route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ message: '事件加载失败-模拟错误' }),
      })
    }

    return fulfillEvents(route, [])
  })

  await page.goto('/events')

  const errorState = page.getByTestId('attack-queue-error-state')
  const retryButton = page.getByTestId('attack-queue-retry')

  await expect(page.getByTestId('attack-queue-title')).toBeVisible()
  await expect(errorState).toBeVisible()
  await expect(errorState).toContainText('事件加载失败-模拟错误')
  await expect(retryButton).toBeVisible()

  await retryButton.click()

  await expect.poll(() => requestCount).toBeGreaterThan(1)
  await expect(errorState).toHaveCount(0)
  await expect(page.getByTestId('attack-queue-empty-state')).toBeVisible()
})
