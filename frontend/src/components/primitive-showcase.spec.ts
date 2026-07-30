/// <reference types="node" />

import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

const frontendDirectory = fileURLToPath(new URL('../../', import.meta.url))
const sourceDirectory = new URL('../', import.meta.url)

const readFrontendFile = (path: string): Promise<string> =>
  readFile(new URL(`../../${path}`, import.meta.url), 'utf8')

describe('T16 primitive showcase acceptance', () => {
  it('locks shell, type, radius, focus, icon, and state tokens', async () => {
    // Given the scoped T16 token package
    const tokens = await readFrontendFile('src/design-system/tokens.css')

    // When the planned acceptance values are enumerated
    const contract = [
      '--ly-rail-width: 40px;',
      '--ly-nav-width: 176px;',
      '--ly-identity-height: 56px;',
      '--ly-control-height: 36px;',
      '--ly-font-12: 12px;',
      '--ly-font-14: 14px;',
      '--ly-font-16: 16px;',
      '--ly-font-20: 20px;',
      '--ly-radius-control: 8px;',
      '--ly-radius-navigation: 8px;',
      '--ly-radius-visualization: 12px;',
      '--ly-icon-size: 18px;',
      '--ly-focus-ring:',
      '--ly-color-success:',
      '--ly-color-warning:',
      '--ly-color-danger:',
    ]

    // Then every downstream invariant has one named token
    for (const value of contract) expect(tokens).toContain(value)
  })

  it('renders the four primitives without nested surfaces', async () => {
    // Given the planned page-level showcase
    const showcase = await readFrontendFile('src/pages/PrimitiveShowcase.vue')

    // When its primitive composition is inspected
    const primitives = [
      'ConsoleFrame',
      'ConsoleIdentityRow',
      'ConsoleSearchField',
      'ConsoleSurface',
    ]

    // Then all primitives and visual states are present without card nesting
    for (const primitive of primitives) expect(showcase).toContain(primitive)
    expect(showcase).toContain('data-showcase-state="healthy"')
    expect(showcase).toContain('data-showcase-state="warning"')
    expect(showcase).toContain('data-showcase-state="abnormal"')
    expect(showcase).not.toMatch(/<ConsoleSurface[^>]*>\s*<ConsoleSurface/)
  })

  it('keeps the showcase outside production navigation', async () => {
    // Given production router and navigation sources
    const productionSources = await Promise.all([
      readFrontendFile('src/router/index.js'),
      readFrontendFile('src/layout/nav-config.js'),
      readFrontendFile('src/shared/navigation.js'),
    ])

    // When T16 showcase names are checked
    const productionText = productionSources.join('\n')

    // Then no product route or navigation entry exposes the harness
    expect(productionText).not.toMatch(/PrimitiveShowcase|primitive-showcase/)
  })

  it('rejects old iKuai assets and copied product text from frontend runtime files', async () => {
    // Given every frontend runtime source and public asset path
    const sourcePaths = await readdir(sourceDirectory, { recursive: true })
    const runtimePaths = sourcePaths.filter(
      (path) => /\.(?:css|html|js|json|ts|vue)$/u.test(path) && !/\.(?:spec|test)\.[jt]s$/u.test(path),
    )

    // When filenames and runtime contents are scanned for rejected references
    const findings: string[] = []
    for (const path of runtimePaths) {
      const content = await readFile(new URL(path, sourceDirectory), 'utf8')
      if (/xitonggaik\.png|old iKuai 3|iKuai 3\.x|爱快/iu.test(`${path}\n${content}`)) findings.push(path)
    }
    const publicPaths = await readdir(`${frontendDirectory}public`, { recursive: true }).catch(() => [])
    const rejectedAssets = publicPaths.filter((path) => /xitonggaik|ikuai.*3|3.*ikuai/iu.test(path))

    // Then neither rejected assets nor copied iKuai labels enter the frontend
    expect(findings).toEqual([])
    expect(rejectedAssets).toEqual([])
  })
})
