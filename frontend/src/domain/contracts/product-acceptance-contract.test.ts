import { beforeAll, describe, expect, it, vi } from 'vitest'

import { backendContractDomains } from '../../contracts/backend-contracts.js'
import { navGroups, routeMeta } from '../../layout/nav-config.js'
import { PRODUCT_ACCEPTANCE_CONTRACT } from './product-acceptance-contract'

const routerCapture = vi.hoisted(() => ({ routes: [] as readonly RouteRecord[] }))

type RouteRecord = {
  readonly path: string
  readonly redirect?: string
  readonly children?: readonly RouteRecord[]
}

vi.mock('vue-router', () => ({
  createWebHistory: () => ({}),
  createRouter: ({ routes }: { readonly routes: readonly RouteRecord[] }) => {
    routerCapture.routes = routes
    return { beforeEach: vi.fn() }
  },
}))

const unsupportedPaths = [
  '/logs',
  '/traffic',
  '/defense',
  '/topology',
  '/intelligence',
  '/intelligence/rules',
  '/situation/global',
  '/control',
  '/settings',
  '/reports',
  '/unified',
  '/intelligence/dpi',
  '/intelligence/xdr',
  '/intelligence/rasp',
  '/threat-intel',
  '/vulnerabilities',
] as const

const consolidationPaths = [
  '/application-threats',
  '/system-security-audit',
  '/host-ops',
  '/real-time-posture',
  '/rule-visibility',
  '/rule-updates',
] as const

describe('T02 current red gaps', () => {
  beforeAll(async () => {
    await import('../../router/index.js')
  })

  it('records unsupported navigation and metadata paths for T15 removal', () => {
    const navigationPaths = navGroups.flatMap((group) => group.items.map((item) => item.path))
    const metadataPaths = Object.keys(routeMeta)
    const presentUnsupportedPaths = unsupportedPaths.filter(
      (path) => navigationPaths.includes(path) || metadataPaths.includes(path),
    )

    const contractedRemovals = PRODUCT_ACCEPTANCE_CONTRACT.frontendRoutes
      .filter((route) => route.disposition === 'remove')
      .map((route) => route.path)

    expect(presentUnsupportedPaths).toEqual([...unsupportedPaths])
    expect(contractedRemovals).toEqual(expect.arrayContaining(presentUnsupportedPaths))
  })

  it('records standalone duplicate pages for T15 consolidation', () => {
    const shell = routerCapture.routes.find((route) => Array.isArray(route.children))
    const protectedPaths = (shell?.children ?? []).map((route) => `/${route.path}`)

    const presentConsolidationPaths = protectedPaths.filter((path) => consolidationPaths.includes(path))
    const contractedConsolidations = PRODUCT_ACCEPTANCE_CONTRACT.frontendRoutes
      .filter((route) => route.disposition === 'consolidate')
      .map((route) => route.path)

    expect(presentConsolidationPaths).toEqual([...consolidationPaths])
    expect(contractedConsolidations).toEqual([...consolidationPaths])
  })

  it('replaces missing legacy API dispositions with authoritative API ownership', () => {
    const apiRecords = backendContractDomains.flatMap((domain) => domain.routes)
    const recordsMissingDisposition = apiRecords.filter((record) => !('disposition' in record))

    expect(recordsMissingDisposition).toHaveLength(apiRecords.length)
    expect(PRODUCT_ACCEPTANCE_CONTRACT.apiRoutes).toHaveLength(PRODUCT_ACCEPTANCE_CONTRACT.registry.mountedPathCount)
    expect(PRODUCT_ACCEPTANCE_CONTRACT.apiRoutes.every((route) => route.disposition.length > 0)).toBe(true)
  })

  it('records dashboard fallback as a T15-owned authenticated 404 gap', () => {
    const fallback = routerCapture.routes.find((route) => route.path === '/:pathMatch(.*)*')
    const fallbackContract = PRODUCT_ACCEPTANCE_CONTRACT.frontendRoutes.find((route) => route.path === '/:pathMatch(.*)*')
    const gap = PRODUCT_ACCEPTANCE_CONTRACT.expectedRedGaps.find((item) => item.id === 'authenticated-unknown-path-dashboard-fallback')

    expect(fallback?.redirect).toBe('/dashboard')
    expect(fallbackContract?.disposition).toBe('404')
    expect(gap?.ownerTask).toBe('T15')
  })
})
