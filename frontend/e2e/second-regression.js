const { chromium } = require('@playwright/test')
const fs = require('node:fs/promises')
const path = require('node:path')

const baseURL = process.env.LY_UI_BASE_URL
const adminUser = process.env.LY_UI_USERNAME
const adminPass = process.env.LY_UI_PASSWORD
const approverUser = process.env.LY_UI_APPROVER_USERNAME
const approverPass = process.env.LY_UI_APPROVER_PASSWORD
const evidenceDir = process.env.LY_UI_EVIDENCE_DIR

if (!baseURL || !adminUser || !adminPass || !approverUser || !approverPass || !evidenceDir) {
  throw new Error('Missing second-regression environment')
}

async function login(page, username, password, target) {
  await page.goto(`${baseURL}/login`, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('账号').fill(username)
  await page.getByLabel('密码').fill(password)
  await page.getByRole('button', { name: '进入控制台' }).click()
  try {
    await page.waitForURL((url) => url.pathname !== '/login', { timeout: 12000 })
  } catch {
    // Keep the current page so the caller can record the failed navigation.
  }
  await page.waitForTimeout(1500)
  if (target) {
    await page.goto(`${baseURL}${target}`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(2500)
  }
  return page.url()
}

async function main() {
  await fs.mkdir(evidenceDir, { recursive: true })
  const browser = await chromium.launch({
    headless: true,
    args: ['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'],
  })
  const result = { generatedAt: new Date().toISOString(), checks: {}, errors: [] }
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } })
    const page = await context.newPage()
    const errors = []
    page.on('console', (message) => { if (message.type() === 'error') errors.push(`console: ${message.text()}`) })
    page.on('pageerror', (error) => errors.push(`pageerror: ${String(error)}`))
    page.on('response', (response) => {
      if (response.status() >= 400 && !response.url().includes('/api/v1/events/does-not-exist') && !response.url().includes('/api/v2/events/does-not-exist')) {
        errors.push(`http ${response.status()} ${response.url()}`)
      }
    })
    result.loginURL = await login(page, adminUser, adminPass, '/rules')
    await page.waitForTimeout(9000)
    const rulesText = await page.locator('body').innerText()
    result.checks.rules = {
      hasProbeEngine: rulesText.includes('LyFlow 探针规则'),
      stillLoadingSources: rulesText.includes('正在读取实装引擎与上游'),
      hasEtOpen: rulesText.includes('ET Open'),
      hasRuleCount: /29,?906|29906/.test(rulesText),
      bodyText: rulesText.slice(0, 1800),
    }
    await page.screenshot({ path: path.join(evidenceDir, 'rules-wait9s.png'), fullPage: true })

    for (const [name, route, wait] of [
      ['traffic-observe', '/traffic-observe', 5000],
      ['response', '/response', 2500],
      ['runtime', '/runtime', 2500],
    ]) {
      await page.goto(`${baseURL}${route}`, { waitUntil: 'domcontentloaded' })
      await page.waitForTimeout(wait)
      const text = await page.locator('body').innerText()
      result.checks[name] = {
        url: page.url(),
        hasLyprobe: text.toLowerCase().includes('lyprobe'),
        hasCreateResponse: text.includes('发起响应动作'),
        hasAutomation: text.includes('自动处置'),
        hasEbpf: text.toLowerCase().includes('ebpf'),
        bodyText: text.slice(0, 2200),
      }
      await page.screenshot({ path: path.join(evidenceDir, `${name}.png`), fullPage: true })
    }

    await page.goto(`${baseURL}/events/does-not-exist`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(2500)
    const missingText = await page.locator('body').innerText()
    result.checks.missingEvent = {
      url: page.url(),
      hasNotFound: missingText.includes('事件不存在') || missingText.includes('event not found') || missingText.includes('未找到'),
      bodyText: missingText.slice(0, 1200),
    }
    await page.screenshot({ path: path.join(evidenceDir, 'missing-event.png'), fullPage: true })

    const detailRequests = []
    const onDetail = (request) => {
      if (/\/api\/v1\/incidents\/[^/?]+/.test(request.url()) && !request.url().includes('/actions') && !request.url().includes('/bundles')) {
        detailRequests.push(request.url())
      }
    }
    page.on('request', onDetail)
    await page.goto(`${baseURL}/incidents`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(4000)
    const started = Date.now()
    const incidentLink = page.locator('a[href*="/incidents/"], [data-incident-id], tbody tr').first()
    if (await incidentLink.count()) {
      await incidentLink.click()
      await page.waitForTimeout(2500)
    }
    const incidentFullText = await page.locator('body').innerText()
    result.checks.incidentDetail = {
      url: page.url(),
      elapsedMs: Date.now() - started,
      detailRequests: detailRequests.slice(),
      hasTimeline: incidentFullText.includes('阶段时间线'),
      hasEvidence: incidentFullText.includes('证据包'),
      bodyText: incidentFullText.slice(0, 1500),
    }
    page.off('request', onDetail)
    await page.screenshot({ path: path.join(evidenceDir, 'incident-detail.png'), fullPage: true })

    result.checks.adminErrors = errors.filter((error) => !error.includes('status of 404 (Not Found)'))

    const approverContext = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } })
    const approverPage = await approverContext.newPage()
    const approverErrors = []
    approverPage.on('console', (message) => { if (message.type() === 'error') approverErrors.push(`console: ${message.text()}`) })
    approverPage.on('pageerror', (error) => approverErrors.push(`pageerror: ${String(error)}`))
    const approverLoginURL = await login(approverPage, approverUser, approverPass)
    const approverAfterLogin = (await approverPage.locator('body').innerText()).slice(0, 800)
    await approverPage.goto(`${baseURL}/xdr`, { waitUntil: 'domcontentloaded' })
    await approverPage.waitForTimeout(2500)
    result.checks.approver = {
      loginURL: approverLoginURL,
      afterLoginText: approverAfterLogin,
      xdrURL: approverPage.url(),
      forbiddenText: (await approverPage.locator('body').innerText()).slice(0, 800),
      errors: approverErrors.slice(),
    }
    await approverPage.screenshot({ path: path.join(evidenceDir, 'approver-forbidden.png'), fullPage: true })
    await approverContext.close()

    await fs.writeFile(path.join(evidenceDir, 'second-regression.json'), `${JSON.stringify(result, null, 2)}\n`)
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
    const failed = Object.entries(result.checks).some(([name, value]) => {
      if (name === 'adminErrors') return value.length > 0
      if (name === 'approver') return !value.xdrURL.includes('/forbidden') || value.errors.length > 0
      if (name === 'missingEvent') return !value.hasNotFound
      if (name === 'rules') return !value.hasProbeEngine || value.stillLoadingSources
      if (name === 'response') return value.hasCreateResponse
      if (name === 'incidentDetail') return !value.hasTimeline || value.detailRequests.length > 1
      return false
    })
    if (failed) process.exitCode = 2
  } finally {
    await browser.close()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
