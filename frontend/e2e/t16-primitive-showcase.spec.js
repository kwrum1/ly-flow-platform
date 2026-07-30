const { mkdir, readFile, readdir, writeFile } = require('node:fs/promises')
const path = require('node:path')
const { test, expect } = require('@playwright/test')

const EVIDENCE_DIRECTORY = path.resolve(__dirname, '../../acceptance-evidence/T16')
const SCREENSHOT_DIRECTORY = path.join(EVIDENCE_DIRECTORY, 'primitive-screenshots')
const VIEWPORTS = [375, 768, 1280]
const TOKEN_NAMES = [
  '--ly-rail-width',
  '--ly-nav-width',
  '--ly-identity-height',
  '--ly-control-height',
  '--ly-font-12',
  '--ly-font-14',
  '--ly-font-16',
  '--ly-font-20',
  '--ly-radius-control',
  '--ly-radius-navigation',
  '--ly-radius-visualization',
  '--ly-icon-size',
  '--ly-color-success',
  '--ly-color-warning',
  '--ly-color-danger',
  '--ly-color-focus',
]

async function scanRejectedReferences() {
  const sourceDirectory = path.resolve(__dirname, '../src')
  const sourcePaths = await readdir(sourceDirectory, { recursive: true })
  const runtimePaths = sourcePaths.filter(
    (entry) => /\.(?:css|html|js|json|ts|vue)$/u.test(entry) && !/\.(?:spec|test)\.[jt]s$/u.test(entry),
  )
  const matches = []
  for (const entry of runtimePaths) {
    const content = await readFile(path.join(sourceDirectory, entry), 'utf8')
    if (/xitonggaik\.png|old iKuai 3|iKuai 3\.x|爱快/iu.test(`${entry}\n${content}`)) matches.push(entry)
  }
  return { scannedFiles: runtimePaths.length, matches }
}

test('captures T16 primitive visual and accessibility evidence', async ({ page }) => {
  await mkdir(SCREENSHOT_DIRECTORY, { recursive: true })
  const visualResults = []
  const accessibilityResults = []
  let tokenInventory = null

  for (const width of VIEWPORTS) {
    const consoleErrors = []
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text())
    })
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/primitive-showcase.html')
    await expect(page.getByTestId('primitive-showcase')).toBeVisible()
    await page.getByLabel('搜索基础组件').focus()
    await expect.poll(() => page.locator('.ly-console-search .el-input__wrapper').evaluate(
      (element) => getComputedStyle(element).boxShadow,
    )).toContain('rgb(0, 95, 189)')

    const evidence = await page.evaluate((tokenNames) => {
      const rectangle = (selector) => {
        const value = document.querySelector(selector).getBoundingClientRect()
        return { x: value.x, y: value.y, width: value.width, height: value.height, right: value.right, bottom: value.bottom }
      }
      const styleValue = (selector, property) => getComputedStyle(document.querySelector(selector)).getPropertyValue(property).trim()
      const boxes = ['rail', 'navigation', 'workspace'].map((name) => ({ name, ...rectangle(`[data-qa-box="${name}"]`) }))
      const overlaps = []
      for (let index = 0; index < boxes.length; index += 1) {
        for (let otherIndex = index + 1; otherIndex < boxes.length; otherIndex += 1) {
          const first = boxes[index]
          const second = boxes[otherIndex]
          if (first.x < second.right && first.right > second.x && first.y < second.bottom && first.bottom > second.y) {
            overlaps.push(`${first.name}:${second.name}`)
          }
        }
      }
      const clipping = [...document.querySelectorAll('[data-qa-clip]')]
        .filter((element) => element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight)
        .map((element) => element.textContent.trim())
      const interactiveNames = [...document.querySelectorAll('button, input')].map((element) => ({
        tag: element.tagName.toLowerCase(),
        name: element.getAttribute('aria-label') || element.textContent.trim(),
      }))
      const rootStyle = getComputedStyle(document.querySelector('.ly-console'))
      const tokens = Object.fromEntries(tokenNames.map((name) => [name, rootStyle.getPropertyValue(name).trim()]))
      return {
        viewport: { width: window.innerWidth, height: window.innerHeight },
        boxes,
        overlaps,
        clipping,
        documentOverflow: document.documentElement.scrollWidth > window.innerWidth,
        nestedSurfaces: document.querySelectorAll('.ly-console-surface .ly-console-surface').length,
        railWidth: rectangle('.ly-console-frame__rail').width,
        navigationWidth: rectangle('.ly-console-frame__navigation').width,
        identityHeight: rectangle('.ly-console-identity').height,
        controlHeight: rectangle('.ly-console-search .el-input__wrapper').height,
        typeScale: [12, 14, 16, 20].map((size) => styleValue(`[data-type-token="${size}"]`, 'font-size')),
        stateColors: {
          healthy: styleValue('[data-showcase-state="healthy"]', 'color'),
          warning: styleValue('[data-showcase-state="warning"]', 'color'),
          abnormal: styleValue('[data-showcase-state="abnormal"]', 'color'),
        },
        radii: {
          control: styleValue('.geometry-control', 'border-radius'),
          navigation: styleValue('.showcase-navigation button', 'border-radius'),
          surface: styleValue('.ly-console-surface', 'border-radius'),
          visualization: styleValue('.visualization-well', 'border-radius'),
        },
        icon: rectangle('.showcase-icon svg'),
        focusShadow: styleValue('.ly-console-search .el-input__wrapper', 'box-shadow'),
        landmarks: {
          main: document.querySelectorAll('main').length,
          navigation: document.querySelectorAll('nav').length,
          heading: document.querySelectorAll('h1').length,
        },
        searchLabel: document.querySelector('input[type="search"]').getAttribute('aria-label'),
        unnamedInteractive: interactiveNames.filter((item) => item.name.length === 0),
        tokens,
      }
    }, TOKEN_NAMES)

    expect(evidence.railWidth).toBe(40)
    if (width >= 768) expect(evidence.navigationWidth).toBe(176)
    expect(evidence.identityHeight).toBe(56)
    expect(evidence.controlHeight).toBe(36)
    expect(evidence.typeScale).toEqual(['12px', '14px', '16px', '20px'])
    expect(evidence.stateColors).toEqual({
      healthy: 'rgb(22, 138, 85)',
      warning: 'rgb(173, 104, 0)',
      abnormal: 'rgb(196, 56, 56)',
    })
    expect(evidence.radii).toEqual({ control: '8px', navigation: '8px', surface: '8px', visualization: '12px' })
    expect(evidence.icon.width).toBe(18)
    expect(evidence.icon.height).toBe(18)
    expect(evidence.focusShadow).toContain('rgb(0, 95, 189)')
    expect(evidence.overlaps).toEqual([])
    expect(evidence.clipping).toEqual([])
    expect(evidence.documentOverflow).toBe(false)
    expect(evidence.nestedSurfaces).toBe(0)
    expect(evidence.unnamedInteractive).toEqual([])
    expect(consoleErrors).toEqual([])

    await page.screenshot({
      path: path.join(SCREENSHOT_DIRECTORY, `primitive-showcase-${width}.png`),
      fullPage: true,
    })
    visualResults.push({ width, consoleErrors, ...evidence })
    accessibilityResults.push({
      width,
      landmarks: evidence.landmarks,
      searchLabel: evidence.searchLabel,
      focusVisible: evidence.focusShadow.includes('rgb(0, 95, 189)'),
      unnamedInteractive: evidence.unnamedInteractive,
      clipping: evidence.clipping,
      overlaps: evidence.overlaps,
    })
    if (width === 1280) tokenInventory = evidence.tokens
  }

  const rejectedReferences = await scanRejectedReferences()
  expect(rejectedReferences.matches).toEqual([])
  await writeFile(path.join(EVIDENCE_DIRECTORY, 'design-tokens.json'), `${JSON.stringify(tokenInventory, null, 2)}\n`)
  await writeFile(path.join(EVIDENCE_DIRECTORY, 'visual-qa.json'), `${JSON.stringify({ status: 'PASS', viewports: visualResults }, null, 2)}\n`)
  await writeFile(path.join(EVIDENCE_DIRECTORY, 'accessibility.json'), `${JSON.stringify({ status: 'PASS', viewports: accessibilityResults }, null, 2)}\n`)
  await writeFile(path.join(EVIDENCE_DIRECTORY, 'rejected-reference-check.json'), `${JSON.stringify({ status: 'PASS', ...rejectedReferences }, null, 2)}\n`)
})
