/// <reference types="node" />

import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

const designSystemDirectory = fileURLToPath(new URL('.', import.meta.url))
const repositoryDirectory = fileURLToPath(new URL('../../../', import.meta.url))

const readDesignSystemFile = (path: string): Promise<string> =>
  readFile(new URL(path, import.meta.url), 'utf8')

describe('T16 design system contract', () => {
  it('documents the approved iKuai 4 beta operational console', async () => {
    // Given the repository-level design contract
    const contract = await readFile(`${repositoryDirectory}DESIGN.md`, 'utf8')

    // When downstream work reads its required decisions
    const requiredDecisions = [
      '## 0. Research Log',
      'iKuai 4 beta',
      'https://www.ikuai8.com/',
      '40px primary icon rail',
      '176px secondary navigation',
      '56px identity row',
      '36px search',
      '12px, 14px, 16px, and 20px',
      'WCAG 2.2 AA',
      '## 8. Accessibility Constraints & Accepted Debt',
    ]

    // Then every approved source and non-negotiable is explicit
    for (const decision of requiredDecisions) expect(contract).toContain(decision)
  })

  it('publishes scoped tokens for geometry, typography, and focus', async () => {
    // Given the frontend token stylesheet
    const tokens = await readDesignSystemFile('./tokens.css')

    // When the approved foundation variables are inspected
    const requiredTokens = [
      '--ly-rail-width: 40px;',
      '--ly-nav-width: 176px;',
      '--ly-identity-height: 56px;',
      '--ly-control-height: 36px;',
      '--ly-font-12: 12px;',
      '--ly-font-14: 14px;',
      '--ly-font-16: 16px;',
      '--ly-font-20: 20px;',
      '--ly-radius-max: 8px;',
      '--ly-letter-spacing: 0;',
      '--ly-focus-ring:',
      '--el-color-primary:',
    ]

    // Then all downstream geometry is available under the ly-console scope
    expect(tokens).toContain('.ly-console')
    for (const token of requiredTokens) expect(tokens).toContain(token)
  })

  it('provides reusable Vue and Element Plus primitives', async () => {
    // Given the public primitive barrel
    const barrel = await readDesignSystemFile('./index.js')
    const primitiveModule = await import('./index.js')

    // When downstream tasks import the T16 foundation
    const primitives = [
      'ConsoleFrame',
      'ConsoleIdentityRow',
      'ConsoleSearchField',
      'ConsoleSurface',
    ]

    // Then each primitive is exported and the search field uses Element Plus
    for (const primitive of primitives) expect(barrel).toContain(`export { default as ${primitive} }`)
    expect(Object.keys(primitiveModule).sort()).toEqual([...primitives].sort())
    const searchField = await readFile(
      `${designSystemDirectory}primitives/ConsoleSearchField.vue`,
      'utf8',
    )
    expect(searchField).toContain('<el-input')
    expect(searchField).toContain('aria-label')
  })
})
