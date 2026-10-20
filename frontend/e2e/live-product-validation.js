const { chromium, firefox } = require('@playwright/test')
const fs = require('node:fs/promises')
const path = require('node:path')

const baseURL = process.env.LY_UI_BASE_URL
const username = process.env.LY_UI_USERNAME
const password = process.env.LY_UI_PASSWORD
const evidenceDir = process.env.LY_UI_EVIDENCE_DIR

if (!baseURL || !username || !password || !evidenceDir) {
  throw new Error('Missing live UI validation environment')
}

const routes = [
  ['dashboard', '/dashboard'],
  ['global-situation', '/situation/global'],
  ['xdr', '/xdr'],
  ['incidents', '/incidents'],
  ['agents', '/assets'],
  ['events', '/events'],
  ['runtime', '/runtime'],
  ['rules-center', '/rules'],
  ['rule-updates', '/rule-updates'],
  ['control-center', '/control-center'],
  ['install-config', '/install-config'],
  ['traffic', '/traffic-threats'],
  ['rasp', '/rasp'],
]

async function inspectPage(page, name, pathname, viewport) {
  const response = await page.goto(`${baseURL}${pathname}`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(2500)
  const metrics = await page.evaluate(() => {
    const canvases = [...document.querySelectorAll('canvas')]
    const canvasPixels = canvases.map((canvas) => {
      try {
        const ctx = canvas.getContext('2d')
        if (!ctx || !canvas.width || !canvas.height) return { width: canvas.width, height: canvas.height, colored: 0 }
        const sample = ctx.getImageData(0, 0, canvas.width, canvas.height).data
        let colored = 0
        const stride = Math.max(4, Math.floor(sample.length / 4000 / 4) * 4)
        for (let index = 0; index < sample.length; index += stride) {
          if (sample[index + 3] > 0 && (sample[index] || sample[index + 1] || sample[index + 2])) colored++
        }
        return { width: canvas.width, height: canvas.height, colored }
      } catch (error) {
        return { width: canvas.width, height: canvas.height, error: String(error) }
      }
    })
    return {
      title: document.title,
      bodyText: document.body.innerText.slice(0, 4000),
      horizontalOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      canvases: canvasPixels,
      visibleDialogs: [...document.querySelectorAll('[role="dialog"]')].filter((el) => {
        const style = getComputedStyle(el)
        return style.display !== 'none' && style.visibility !== 'hidden'
      }).length,
    }
  })
  const filename = `${name}-${viewport.width}x${viewport.height}.png`
  await page.screenshot({ path: path.join(evidenceDir, filename), fullPage: true })
  return { name, pathname, status: response?.status(), url: page.url(), screenshot: filename, ...metrics }
}

async function main() {
  await fs.mkdir(evidenceDir, { recursive: true })
  const useFirefox = process.env.LY_UI_BROWSER === 'firefox'
  const browser = await (useFirefox ? firefox : chromium).launch({
    headless: true,
    executablePath: process.env.LY_UI_BROWSER_PATH || undefined,
    args: useFirefox ? [] : ['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'],
  })
  const result = { generatedAt: new Date().toISOString(), consoleErrors: [], pageErrors: [], requestFailures: [], badResponses: [], pages: [] }
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } })
    const page = await context.newPage()
    page.on('console', (message) => {
      if (message.type() === 'error') result.consoleErrors.push(message.text())
    })
    page.on('pageerror', (error) => result.pageErrors.push(String(error)))
    page.on('requestfailed', (request) => result.requestFailures.push(`${request.method()} ${request.url()} ${request.failure()?.errorText || ''}`))
    page.on('response', (response) => {
      if (response.status() >= 400) result.badResponses.push(`${response.status()} ${response.request().method()} ${response.url()}`)
    })

    result.pages.push(await inspectPage(page, 'login', '/login', { width: 1440, height: 900 }))
    await page.getByLabel('账号').fill(username)
    await page.getByLabel('密码').fill(password)
    await Promise.all([
      page.waitForURL((url) => url.pathname === '/dashboard'),
      page.getByRole('button', { name: '进入控制台' }).click(),
    ])

    for (const [name, pathname] of routes) {
      result.pages.push(await inspectPage(page, name, pathname, { width: 1440, height: 900 }))
    }

    const token = await page.evaluate(() => localStorage.getItem('token'))
    const situation = await page.evaluate(async (authToken) => {
      const response = await fetch('/api/v1/public/situation/global', { headers: { Authorization: `Bearer ${authToken}` } })
      return { status: response.status, body: await response.json() }
    }, token)
    result.globalSituation = situation

    await page.setViewportSize({ width: 390, height: 844 })
    result.pages.push(await inspectPage(page, 'dashboard-mobile', '/dashboard', { width: 390, height: 844 }))
    result.pages.push(await inspectPage(page, 'agents-mobile', '/assets', { width: 390, height: 844 }))
    await page.evaluate(() => localStorage.clear())
    result.pages.push(await inspectPage(page, 'login-mobile', '/login', { width: 390, height: 844 }))
    result.unexpectedRequestFailures = result.requestFailures.filter((failure) => !failure.includes('net::ERR_ABORTED'))
    await fs.writeFile(path.join(evidenceDir, 'validation.json'), `${JSON.stringify(result, null, 2)}\n`)
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
    if (result.consoleErrors.length || result.pageErrors.length || result.unexpectedRequestFailures.length || result.badResponses.length) process.exitCode = 2
    if (result.pages.some((entry) => entry.status !== 200 || entry.horizontalOverflow > 2)) process.exitCode = 3
  } finally {
    await browser.close()
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
