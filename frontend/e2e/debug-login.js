const { chromium } = require('@playwright/test')
const fs = require('node:fs/promises')

const baseURL = process.env.LY_UI_BASE_URL
const username = process.env.LY_UI_USERNAME
const password = process.env.LY_UI_PASSWORD
const evidenceDir = process.env.LY_UI_EVIDENCE_DIR

async function main() {
  const browser = await chromium.launch({ headless: true, args: ['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } })
  const page = await context.newPage()
  const network = []
  const consoleErrors = []
  page.on('response', (response) => {
    if (response.url().includes('/api/')) network.push(`${response.status()} ${response.request().method()} ${response.url()}`)
  })
  page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text()) })
  await page.goto(`${baseURL}/login`, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('账号').fill(username)
  await page.getByLabel('密码').fill(password)
  await page.getByRole('button', { name: '进入控制台' }).click()
  await page.waitForTimeout(4000)
  const result = {
    url: page.url(),
    token: await page.evaluate(() => localStorage.getItem('token')),
    body: await page.locator('body').innerText(),
    network,
    consoleErrors,
  }
  await fs.writeFile(`${evidenceDir}/approver-debug.json`, JSON.stringify(result, null, 2))
  console.log(JSON.stringify(result, null, 2))
  await browser.close()
}
main().catch((error) => { console.error(error); process.exit(1) })
