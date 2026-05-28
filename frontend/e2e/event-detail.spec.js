const { test, expect } = require('@playwright/test')

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

test('renders stable evidence timeline with source labels and readable context mapping', async ({ page }) => {
  await page.route('**/api/v1/events/evt-123**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      code: 0,
      data: {
        event: {
          id: 'evt-123',
          source: 'events',
          timestamp: '2026-01-02T00:02:00Z',
          severity: 'high',
          status: 'open',
          event_type: 'scan',
          src_ip: '10.0.0.10',
          dst_ip: '10.0.0.20',
          domain: 'main.local',
          rule_name: 'main-rule',
          message: 'main event',
        },
        related: [
          {
            id: 'rel-xdr',
            source: 'xdr',
            timestamp: '2026-01-02T00:00:00Z',
            severity: 'critical',
            status: 'new',
            event_type: 'xdr-alert',
            src_ip: '10.0.0.1',
            dst_ip: '10.0.0.2',
            domain: 'xdr.local',
            rule_name: 'xdr-rule',
            message: 'xdr related',
          },
          {
            id: 'rel-unified',
            source: 'unified',
            timestamp: '2026-01-02T00:00:00Z',
            severity: 'medium',
            status: 'open',
            event_type: 'dpi',
            src_ip: '10.0.0.3',
            dst_ip: '10.0.0.4',
            domain: 'unified.local',
            rule_name: 'unified-rule',
            message: 'unified related',
          },
          {
            id: 'rel-rasp',
            source: 'rasp',
            timestamp: '2026-01-02T00:03:00Z',
            severity: 'low',
            status: 'allowed',
            event_type: 'runtime',
            src_ip: '10.0.0.5',
            dst_ip: '10.0.0.6',
            domain: 'rasp.local',
            rule_name: 'rasp-rule',
            message: 'rasp related',
          },
        ],
      },
    }),
  }))

  await page.goto('/events/evt-123')

  await expect(page.getByTestId('event-detail-timeline')).toBeVisible()

  const timelineItems = page.getByTestId('event-detail-timeline-item')
  await expect(timelineItems).toHaveCount(4)

  await expect(timelineItems.nth(0).getByTestId('event-detail-source-badge')).toHaveText('Unified')
  await expect(timelineItems.nth(1).getByTestId('event-detail-source-badge')).toHaveText('XDR')
  await expect(timelineItems.nth(2).getByTestId('event-detail-source-badge')).toHaveText('Events')

  await expect(timelineItems.nth(0)).toContainText('SRC10.0.0.3')
  await expect(timelineItems.nth(0)).toContainText('DST10.0.0.4')
  await expect(timelineItems.nth(0)).toContainText('DOMAINunified.local')
  await expect(timelineItems.nth(0)).toContainText('RULEunified-rule')
  await expect(timelineItems.nth(0)).toContainText('TYPEdpi')
})

test('shows masked hint and audit trail when detail contains sensitive fields', async ({ page }) => {
  await page.route('**/api/v1/events/evt-sensitive**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      code: 0,
      data: {
        event: {
          id: 'evt-sensitive',
          source: 'events',
          timestamp: '2026-01-03T01:02:03Z',
          severity: 'high',
          status: 'open',
          event_type: 'probe',
          src_ip: '172.16.0.1',
          dst_ip: '172.16.0.2',
          domain: 'sensitive.local',
          rule_name: 'sensitive-rule',
          message: 'payload token=very-secret-token-value',
          detail: {
            command_line: 'curl -H "Authorization: Bearer abcdefghijklmnop" https://x',
          },
        },
        related: [],
      },
    }),
  }))

  await page.goto('/events/evt-sensitive')

  await expect(page.getByTestId('event-detail-audit')).toBeVisible()
  await expect(page.getByTestId('event-detail-audit-item').first()).toContainText('详情加载')
  await expect(page.locator('pre')).not.toContainText('very-secret-token-value')
})

test('shows actionable empty states when backend omits related correlation data', async ({ page }) => {
  await page.route('**/api/v1/events/evt-empty-rel**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      code: 0,
      data: {
        event: {
          id: 'evt-empty-rel',
          source: 'events',
          timestamp: '2026-01-03T01:02:03Z',
          severity: 'medium',
          status: 'open',
          event_type: 'probe',
          src_ip: '172.16.0.1',
          dst_ip: '172.16.0.2',
          domain: 'empty.local',
          rule_name: 'empty-rule',
          message: 'event without related correlation',
        },
        related: [],
      },
    }),
  }))

  await page.goto('/events/evt-empty-rel')

  await expect(page.getByTestId('detail-empty')).toHaveCount(0)
  await expect(page.getByTestId('correlation-empty')).toBeVisible()
  await expect(page.getByTestId('timeline-empty')).toBeVisible()
  await expect(page.getByTestId('correlation-empty')).toContainText('后端未提供关联事件数据')
  await expect(page.getByTestId('timeline-empty')).toContainText('后端未提供可展示的时间线数据')
})
