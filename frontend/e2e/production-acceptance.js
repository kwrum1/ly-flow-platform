const { chromium } = require('@playwright/test')
const fs = require('node:fs/promises')
const path = require('node:path')

const baseURL = process.env.LY_UI_BASE_URL
const username = process.env.LY_UI_USERNAME
const password = process.env.LY_UI_PASSWORD
const evidenceDir = process.env.LY_UI_EVIDENCE_DIR

if (!baseURL || !username || !password || !evidenceDir) throw new Error('Missing production acceptance environment')

const pages = [
  ['dashboard', '/dashboard'],
  ['global-situation', '/situation/global'],
  ['incidents', '/incidents'],
  ['timeline', '/timeline'],
  ['assets', '/assets'],
  ['events', '/events'],
  ['runtime', '/runtime'],
  ['rasp', '/rasp'],
  ['trace', '/trace'],
  ['rules', '/rules'],
  ['engines', '/engines'],
  ['control-center', '/control-center'],
  ['install-config', '/install-config'],
  ['users', '/users'],
  ['traffic-observe', '/traffic-observe'],
  ['traffic-threats', '/traffic-threats'],
  ['response', '/response'],
  ['evidence', '/evidence'],
]

const legacyRedirects = {
  '/application-threats': '/rasp',
  '/system-security-audit': '/runtime',
  '/host-ops': '/assets',
  '/real-time-posture': '/incidents',
  '/rule-visibility': '/rules',
  '/rule-updates': '/rules',
}

async function main() {
  await fs.mkdir(evidenceDir, { recursive: true })
  const browser = await chromium.launch({
    headless: true,
    args: ['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'],
  })
  const result = { generatedAt: new Date().toISOString(), pages: [], legacy: {}, checks: {}, errors: [] }
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } })
    const page = await context.newPage()
    const errors = []
    page.on('console', (message) => {
      if (message.type() === 'error' && !message.text().includes('status of 404')) errors.push(`console: ${message.text()}`)
    })
    page.on('pageerror', (error) => errors.push(`pageerror: ${String(error)}`))
    page.on('requestfailed', (request) => {
      const reason = request.failure()?.errorText || ''
      if (!reason.includes('ERR_ABORTED')) errors.push(`requestfailed: ${request.method()} ${request.url()} ${reason}`)
    })
    page.on('response', (response) => {
      if (response.status() >= 400 && !response.url().includes('/events/does-not-exist')) {
        errors.push(`http ${response.status()} ${response.url()}`)
      }
    })

    await page.goto(`${baseURL}/login`, { waitUntil: 'domcontentloaded' })
    await page.getByLabel('账号').fill(username)
    await page.getByLabel('密码').fill(password)
    await page.getByRole('button', { name: '进入控制台' }).click()
    await page.waitForURL((url) => url.pathname !== '/login', { timeout: 15000 })
    await page.waitForTimeout(2000)

    for (const [name, route] of pages) {
      const response = await page.goto(`${baseURL}${route}`, { waitUntil: 'domcontentloaded' })
      await page.waitForTimeout(name === 'evidence' ? 5000 : 2200)
      const text = await page.locator('body').innerText()
      const metrics = await page.evaluate(() => ({
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      }))
      result.pages.push({
        name,
        route,
        status: response ? response.status() : 0,
        finalPath: new URL(page.url()).pathname,
        overflow: metrics.overflow,
        hasContent: text.trim().length > 80,
        text: text.slice(0, 900),
      })
      if (['control-center', 'rules', 'traffic-observe', 'response', 'runtime'].includes(name)) {
        await page.screenshot({ path: path.join(evidenceDir, `${name}.png`), fullPage: true })
      }
    }

    const navLinks = await page.locator('a.sx-tab').evaluateAll((links) => links.map((link) => new URL(link.href).pathname))
    const duplicateLinks = navLinks.filter((value, index) => navLinks.indexOf(value) !== index)
    result.checks.nav = { links: [...new Set(navLinks)], duplicateLinks: [...new Set(duplicateLinks)] }

    await page.goto(`${baseURL}/control-center`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1500)
    const controlText = await page.locator('body').innerText()
    result.checks.controlCenter = {
      hasPlatformSettings: controlText.includes('平台设置'),
      hasAgentList: controlText.includes('Agent 列表') || controlText.includes('在线 Agent'),
      hasCapturePanel: controlText.includes('抓包接口'),
      hasTimePanel: controlText.includes('时间设置'),
    }

    await page.goto(`${baseURL}/response`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1800)
    const responseText = await page.locator('body').innerText()
    result.checks.response = {
      hasCreateResponse: responseText.includes('发起响应动作'),
      hasAutomation: responseText.includes('定时自动化处置'),
    }

    await page.goto(`${baseURL}/rules`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(9000)
    const rulesText = await page.locator('body').innerText()
    const ruleTotals = [...rulesText.matchAll(/([0-9][0-9,]*)\s*条规则清单|共\s*([0-9][0-9,]*)\s*条/g)].map((m) => (m[1] || m[2] || '').replace(/,/g, ''))
    result.checks.rules = {
      hasLyprobe: rulesText.includes('LyFlow 探针规则'),
      hasLoading: rulesText.includes('正在读取实装引擎…'),
      totals: ruleTotals,
      totalsAligned: new Set(ruleTotals).size <= 1,
    }

    await page.goto(`${baseURL}/traffic-observe`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(2500)
    const probe = page.getByLabel('探针')
    if (await probe.count()) {
      await probe.selectOption('lyprobe')
      await page.waitForTimeout(2500)
    }
    const trafficText = await page.locator('body').innerText()
    result.checks.trafficObserve = {
      hasLyprobe: trafficText.toLowerCase().includes('lyprobe'),
      hasProbeFilter: await probe.count() > 0,
      hasBytes: /↓\s*\d+\s*B/.test(trafficText),
    }
    await page.screenshot({ path: path.join(evidenceDir, 'traffic-observe-filtered.png'), fullPage: true })

    await page.goto(`${baseURL}/runtime`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1800)
    const runtimeText = await page.locator('body').innerText()
    const runtimeProcessCount = await page.evaluate(async () => {
      const token = localStorage.getItem('token')
      const response = await fetch('/api/v1/component-alerts/runtime?limit=100', { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) return 0
      const payload = await response.json()
      return (payload.data?.items || []).filter((item) => item.type === 'runtime.process.exec' && item.backend === 'ebpf').length
    })
    result.checks.runtime = {
      hasEBPF: runtimeText.includes('eBPF'),
      hasProcessEvents: runtimeText.includes('runtime.process.exec') || runtimeProcessCount > 0,
      runtimeProcessCount,
    }

    const detailRequests = []
    page.on('request', (request) => {
      if (/\/api\/v1\/incidents\/[^/?]+$/.test(request.url())) detailRequests.push(request.url())
    })
    await page.goto(`${baseURL}/incidents`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(2500)
    const incidentLink = page.locator('a[href*="/incidents/"], [data-incident-id], tbody tr, .incident-list-row').first()
    const hasIncidentRow = await incidentLink.count() > 0
    if (hasIncidentRow) {
      await incidentLink.click()
      await page.waitForTimeout(1800)
    }
    const incidentText = await page.locator('body').innerText()
    result.checks.incident = {
      requests: detailRequests.length,
      hasTimeline: incidentText.includes('阶段时间线'),
      hasEvidence: incidentText.includes('证据包'),
      empty: !hasIncidentRow && (incidentText.includes('暂无匹配') || incidentText.includes('没有匹配')),
    }

    await page.goto(`${baseURL}/events/does-not-exist`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1800)
    const missingText = await page.locator('body').innerText()
    result.checks.missingEvent = { hasNotFound: missingText.includes('未找到事件') || missingText.includes('event not found') }

    for (const [legacy, target] of Object.entries(legacyRedirects)) {
      await page.goto(`${baseURL}${legacy}`, { waitUntil: 'domcontentloaded' })
      await page.waitForTimeout(900)
      result.legacy[legacy] = { finalPath: new URL(page.url()).pathname, target }
    }

    result.errors = errors
    await fs.writeFile(path.join(evidenceDir, 'production-acceptance.json'), `${JSON.stringify(result, null, 2)}\n`)
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)

    const failures = []
    for (const entry of result.pages) {
      if (entry.status !== 200) failures.push(`${entry.name} status=${entry.status}`)
      if (entry.overflow > 2) failures.push(`${entry.name} overflow=${entry.overflow}`)
      if (!entry.hasContent) failures.push(`${entry.name} empty`)
    }
    if (result.checks.nav.duplicateLinks.length) failures.push(`duplicate nav links: ${result.checks.nav.duplicateLinks.join(',')}`)
    if (result.checks.controlCenter.hasAgentList) failures.push('control-center still contains Agent list')
    if (!result.checks.controlCenter.hasPlatformSettings) failures.push('control-center missing platform settings')
    if (result.checks.response.hasCreateResponse) failures.push('response duplicate create form')
    if (!result.checks.rules.hasLyprobe || result.checks.rules.hasLoading || !result.checks.rules.totalsAligned) failures.push('rules acceptance failed')
    if (!result.checks.trafficObserve.hasLyprobe) failures.push('traffic observe missing lyprobe')
    if (!result.checks.runtime.hasEBPF || !result.checks.runtime.hasProcessEvents) failures.push('runtime eBPF evidence missing')
    if (result.checks.incident.requests > 1 || (!result.checks.incident.empty && !result.checks.incident.hasTimeline)) failures.push('incident detail failed')
    if (!result.checks.missingEvent.hasNotFound) failures.push('missing event empty state failed')
    for (const [legacy, value] of Object.entries(result.legacy)) {
      if (value.finalPath !== value.target) failures.push(`${legacy} redirected to ${value.finalPath}, want ${value.target}`)
    }
    if (result.errors.length) failures.push(`runtime errors: ${result.errors.length}`)
    if (failures.length) {
      result.failures = failures
      process.exitCode = 2
    }
  } finally {
    await browser.close()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
