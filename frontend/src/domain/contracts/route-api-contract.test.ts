import { describe, expect, it } from 'vitest'

import {
  parseProductAcceptanceContract,
  PRODUCT_ACCEPTANCE_CONTRACT,
  ProductAcceptanceContractError,
} from './product-acceptance-contract'

const canonicalProtectedRoutes = [
  '/dashboard',
  '/events',
  '/incidents',
  '/timeline',
  '/xdr',
  '/assets',
  '/runtime',
  '/rasp',
  '/trace',
  '/rules',
  '/users',
  '/install-config',
  '/traffic-observe',
  '/traffic-threats',
  '/control-center',
] as const

describe('product route and API acceptance contract', () => {
  it('contains one complete record per mounted backend path', () => {
    const paths = PRODUCT_ACCEPTANCE_CONTRACT.apiRoutes.map((route) => route.path)

    expect(paths).toHaveLength(PRODUCT_ACCEPTANCE_CONTRACT.registry.mountedPathCount)
    expect(new Set(paths).size).toBe(paths.length)
    for (const route of PRODUCT_ACCEPTANCE_CONTRACT.apiRoutes) {
      expect(route.operations.length).toBeGreaterThan(0)
      expect(new Set(route.operations.map((operation) => operation.method)).size).toBe(route.operations.length)
      for (const operation of route.operations) {
        expect(operation.validFixture.method).toBe(operation.method)
        expect(operation.validFixture.expectedStatuses.length).toBeGreaterThan(0)
        expect(operation.invalidFixture.expectedStatuses.length).toBeGreaterThan(0)
        expect(operation.readback.length).toBeGreaterThan(0)
        expect(operation.persistence.length).toBeGreaterThan(0)
      }
    }
  })

  it('retains exactly the 15 canonical protected routes', () => {
    const retainedProtected = PRODUCT_ACCEPTANCE_CONTRACT.frontendRoutes
      .filter((route) => route.disposition === 'retain' && route.authMode === 'session')
      .map((route) => route.path)

    expect(retainedProtected).toEqual(canonicalProtectedRoutes)
  })

  it('records exact consolidation targets and the authenticated 404 gap', () => {
    const consolidations = Object.fromEntries(
      PRODUCT_ACCEPTANCE_CONTRACT.frontendRoutes
        .filter((route) => route.disposition === 'consolidate')
        .map((route) => [route.path, route.canonicalPaths]),
    )

    expect(consolidations).toEqual({
      '/application-threats': ['/rasp'],
      '/system-security-audit': ['/runtime'],
      '/host-ops': ['/assets'],
      '/real-time-posture': ['/xdr'],
      '/rule-visibility': ['/rules'],
      '/rule-updates': ['/rules'],
    })
    expect(PRODUCT_ACCEPTANCE_CONTRACT.expectedRedGaps).toContainEqual(
      expect.objectContaining({ id: 'authenticated-unknown-path-dashboard-fallback', ownerTask: 'T15' }),
    )
  })

  it('rejects malformed contract input at the typed boundary', () => {
    const malformed = {
      schema_version: 1,
      registry: { mounted_path_count: 116, sorted_path_sha256: 'invalid' },
      roles: ['admin', 'analyst', 'viewer'],
      frontend_routes: [{ path: '/dashboard', disposition: 'unsupported' }],
      api_routes: [],
      expected_red_gaps: [],
    }

    expect(() => parseProductAcceptanceContract(malformed)).toThrow(ProductAcceptanceContractError)
  })

  it('rejects unknown fields, duplicate roles, and empty required arrays', () => {
    const base = {
      schema_version: 1,
      registry: { mounted_path_count: 116, sorted_path_sha256: 'a'.repeat(64) },
      roles: ['admin', 'analyst', 'viewer'],
      frontend_routes: [],
      api_routes: [],
      expected_red_gaps: [],
    }

    expect(() => parseProductAcceptanceContract({ ...base, unexpected: true })).toThrow(ProductAcceptanceContractError)
    expect(() => parseProductAcceptanceContract({ ...base, roles: ['admin', 'admin', 'viewer'] })).toThrow(ProductAcceptanceContractError)
    expect(() => parseProductAcceptanceContract(base)).toThrow(ProductAcceptanceContractError)
  })
})
