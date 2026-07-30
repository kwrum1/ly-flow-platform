const { mkdir, writeFile } = require('node:fs/promises')
const path = require('node:path')
const { test, expect } = require('@playwright/test')

const T12_ENVIRONMENT = Object.freeze({
  baseURL: 'T12_UI_BASE_URL',
  username: 'T12_UI_USERNAME',
  password: 'T12_UI_PASSWORD',
  evidenceDirectory: 'T12_UI_EVIDENCE_DIR',
})
const EXPECTED_SOURCES = Object.freeze([
  'suricata-et-open',
  'oisf-trafficid',
  'snort-community',
  'ptresearch-attackdetection',
  'stamus-lateral',
])
const EXPECTED_PROVENANCE = Object.freeze({
  'suricata-et-open': { sid: '2002005', revision: '36', rawHashes: ['b5308e6f1ef208b99d452730fc5f525c49dde8b63132519551cf6fcd97202fdd'] },
  'oisf-trafficid': { sid: '300000000', revision: '1', rawHashes: ['35612b961f41eeb3daabbbef6a1ec2be1d295a20290dd55822eed479da2ced53', '43a2414fa6e2b11484bdb54b177b2c4308acb699cb8833615a5e1cc24224b9d7'] },
  'snort-community': { sid: '26655', revision: '2', rawHashes: ['e780d5538c1bf0590e49eb57d7b2e09381c7362157ab65c3ceacdd18c68be80c', 'fb815e0eabbbfe506bf37d550f4d9f86c8d7262b42f38b9c7961c220f86ac310'] },
  'ptresearch-attackdetection': { sid: '10000005', revision: '3', rawHashes: ['31bf8a471345f3fba783b1f7909fd0b0f4e1dc8123344f9ca6ba7955517173ac', '9af0dcce518c31c1468141ee1e622d5d010c92a402247775b46274beb9b9c0d5'] },
  'stamus-lateral': { sid: '3115102', revision: '4', rawHashes: ['413c09b11e9a055d49b94229576757d6b72857888ec3419d06ce3d17262cde8b', '2afc0f19ed41a7d5a09c38e0a47507f0c476b734d0fe130c78267e61c5ff14f1'] },
})
const VIEWPORT_WIDTHS = Object.freeze([375, 768, 1280])
const isT12Mode = Object.values(T12_ENVIRONMENT).some((name) => Object.hasOwn(process.env, name))

function liveConfiguration() {
  const values = Object.fromEntries(Object.entries(T12_ENVIRONMENT).map(([key, name]) => [key, process.env[name]?.trim() || '']))
  const missing = Object.entries(values).filter(([, value]) => !value).map(([key]) => T12_ENVIRONMENT[key])
  if (missing.length) throw new Error(`T12 live UI mode requires: ${missing.join(', ')}`)
  return values
}

function liveURL(baseURL, pathname) {
  return new URL(pathname, baseURL.endsWith('/') ? baseURL : `${baseURL}/`).toString()
}

function isTrafficThreatResponse(response) {
  return response.request().method() === 'GET' && new URL(response.url()).pathname.endsWith('/threats/traffic')
}

async function collectCurrentPage(page, state) {
  const { detections, evidenceDirectory, screenshots, width } = state
  const rows = page.getByTestId('traffic-threat-row')
  const rowCount = await rows.count()

  for (let index = 0; index < rowCount; index += 1) {
    await rows.nth(index).getByTestId('traffic-threat-detail-open').click()
    const detail = page.getByTestId('traffic-threat-detail')
    await expect(detail).toBeVisible()

    const sourceValue = detail.getByTestId('traffic-threat-detail-native-source')
    if (await sourceValue.count()) {
      const source = (await sourceValue.textContent()).trim()
      if (EXPECTED_SOURCES.includes(source) && !detections.has(source)) {
        const sidValue = detail.getByTestId('traffic-threat-detail-native-sid')
        const revisionValue = detail.getByTestId('traffic-threat-detail-native-revision')
        const rawPathValue = detail.getByTestId('traffic-threat-detail-raw-path')
        const rawHashValue = detail.getByTestId('traffic-threat-detail-raw-hash')
        await expect(sourceValue).toBeVisible()
        await expect(sidValue).toBeVisible()
        await expect(revisionValue).toBeVisible()
        await expect(rawPathValue).toBeVisible()
        await expect(rawHashValue).toBeVisible()
        const detection = {
          source,
          sid: (await sidValue.textContent()).trim(),
          revision: (await revisionValue.textContent()).trim(),
          rawPath: (await rawPathValue.textContent()).trim(),
          rawHash: (await rawHashValue.textContent()).trim(),
        }
        const expected = EXPECTED_PROVENANCE[source]
        expect(detection.sid).toBe(expected.sid)
        expect(detection.revision).toBe(expected.revision)
        expect(detection.rawPath.length).toBeGreaterThan(0)
        expect(expected.rawHashes).toContain(detection.rawHash)
        const screenshot = `${source}-${width}.png`
        detections.set(source, detection)
        await page.screenshot({ path: path.join(evidenceDirectory, screenshot), fullPage: true })
        screenshots.push(screenshot)
      }
    }

    await detail.getByTestId('traffic-threat-detail-close').click()
    await expect(detail).toHaveCount(0)
  }
}

test.describe('T12 real five-source traffic detections', () => {
  test.skip(!isT12Mode, 'T12 live UI environment is not configured')

  test('shows persisted native rule and raw-reference identities through the real UI', async ({ page }) => {
    test.setTimeout(300_000)
    const config = liveConfiguration()
    const evidenceDirectory = path.resolve(config.evidenceDirectory)
    await mkdir(evidenceDirectory, { recursive: true })

    await page.goto(liveURL(config.baseURL, '/login'))
    await page.getByLabel('账号').fill(config.username)
    await page.getByLabel('密码').fill(config.password)
    await Promise.all([
      page.waitForURL((url) => url.pathname !== '/login'),
      page.getByRole('button', { name: '进入控制台' }).click(),
    ])
    expect(new URL(page.url()).pathname).not.toBe('/change-password')

    const screenshots = []
    const viewportResults = []
    for (const width of VIEWPORT_WIDTHS) {
      await page.setViewportSize({ width, height: 900 })
      const initialThreats = page.waitForResponse(isTrafficThreatResponse)
      await page.goto(liveURL(config.baseURL, '/traffic-threats'))
      expect((await initialThreats).ok()).toBe(true)
      await expect(page.getByTestId('traffic-threat-row').first()).toBeVisible()

      const pageState = {
        width,
        text: '第 1 页 / 1 页',
        previousDisabled: true,
        nextDisabled: true,
      }
      await expect(page.getByTestId('traffic-threat-page')).toHaveText(pageState.text)
      await expect(page.getByTestId('traffic-threat-previous-page')).toBeDisabled()
      await expect(page.getByTestId('traffic-threat-next-page')).toBeDisabled()

      const detections = new Map()
      await collectCurrentPage(page, { detections, evidenceDirectory, screenshots, width })
      expect([...detections.keys()].sort(), `Missing T12 detail metadata at ${width}px`).toEqual([...EXPECTED_SOURCES].sort())
      viewportResults.push({ width, detections, pageState })
    }

    expect(screenshots).toHaveLength(EXPECTED_SOURCES.length * VIEWPORT_WIDTHS.length)
    expect(new Set(screenshots).size).toBe(screenshots.length)
    const sources = EXPECTED_SOURCES.map((source) => ({
      source,
      viewports: viewportResults.map(({ width, detections }) => ({
        width,
        ...detections.get(source),
        screenshot: `${source}-${width}.png`,
      })),
    }))
    const singlePage = viewportResults.map(({ pageState }) => pageState)
    await writeFile(
      path.join(evidenceDirectory, 't12-real-detections.json'),
      `${JSON.stringify({ singlePage, sources }, null, 2)}\n`,
    )
  })
})
