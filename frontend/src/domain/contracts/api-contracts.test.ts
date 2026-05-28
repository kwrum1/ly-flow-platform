import { describe, expect, it } from 'vitest'

import {
  API_CONTRACT_MATRIX,
  DASHBOARD_CONTRACT_MATRIX,
  THREAT_INTELLIGENCE_TABS,
  validateDashboardContractPayload,
} from './api-contracts'

const REQUIRED_DOMAINS = [
  'auth',
  'stats',
  'events',
  'incidents',
  'timeline',
  'topology',
  'xdr',
  'unified',
  'rasp',
  'trace',
  'assets',
  'agent',
  'threatIntelligence',
  'rules',
  'publicSituation',
] as const

describe('API_CONTRACT_MATRIX', () => {
  it('contains exactly the expected platform domains', () => {
    const actualDomains = Object.keys(API_CONTRACT_MATRIX).sort()
    const expectedDomains = [...REQUIRED_DOMAINS].sort()

    expect(actualDomains).toEqual(expectedDomains)
    expect(actualDomains).toHaveLength(REQUIRED_DOMAINS.length)
  })

  it('includes all key domains explicitly', () => {
    for (const domain of REQUIRED_DOMAINS) {
      expect(API_CONTRACT_MATRIX).toHaveProperty(domain)
      expect(API_CONTRACT_MATRIX[domain].endpoints.length).toBeGreaterThan(0)
    }
  })

  it('ensures each endpoint has consumerSurface/refreshMode/authRequired', () => {
    for (const domain of REQUIRED_DOMAINS) {
      for (const endpoint of API_CONTRACT_MATRIX[domain].endpoints) {
        expect(endpoint).toHaveProperty('consumerSurface')
        expect(endpoint).toHaveProperty('refreshMode')
        expect(endpoint).toHaveProperty('authRequired')

        expect(typeof endpoint.consumerSurface).toBe('string')
        expect(endpoint.consumerSurface.trim().length).toBeGreaterThan(0)
        expect(typeof endpoint.refreshMode).toBe('string')
        expect(endpoint.refreshMode.trim().length).toBeGreaterThan(0)
        expect(typeof endpoint.authRequired).toBe('boolean')
      }
    }
  })

  it('defines a public global situation contract without auth', () => {
    const endpoints = API_CONTRACT_MATRIX.publicSituation.endpoints

    expect(endpoints).toContainEqual({
      path: '/api/v1/public/situation/global',
      methods: ['GET'],
      consumerSurface: 'globalSituation',
      refreshMode: 'poll',
      authRequired: false,
    })
  })

  it('defines threat intelligence as rasp/runtime/combined tabs', () => {
    expect(THREAT_INTELLIGENCE_TABS.map(tab => tab.label)).toEqual(['rasp应用', 'runtime主机', '合并'])
    expect(THREAT_INTELLIGENCE_TABS.map(tab => tab.key)).toEqual(['rasp-apps', 'runtime-hosts', 'combined'])

    const endpointPaths = API_CONTRACT_MATRIX.threatIntelligence.endpoints.map(endpoint => endpoint.path).sort()
    expect(endpointPaths).toEqual([
      '/api/v1/threat-intelligence/combined',
      '/api/v1/threat-intelligence/rasp-apps',
      '/api/v1/threat-intelligence/runtime-hosts',
    ])
  })

  it('defines rule sync endpoints and keeps them authenticated', () => {
    const endpoints = API_CONTRACT_MATRIX.rules.endpoints
    expect(endpoints.map(endpoint => endpoint.path)).toEqual([
      '/api/v1/rules/sources',
      '/api/v1/rules/sync/{source}/dry-run',
      '/api/v1/rules/sync/{source}',
      '/api/v1/rules/sync/history',
    ])
    expect(endpoints.every(endpoint => endpoint.authRequired)).toBe(true)
  })

  it('defines architecture dashboard contracts for all requested modules', () => {
    expect(Object.keys(DASHBOARD_CONTRACT_MATRIX).sort()).toEqual([
      'assets',
      'events',
      'incidents',
      'timeline',
      'topology',
    ])

    expect(DASHBOARD_CONTRACT_MATRIX.incidents.listEndpoint).toBe('/api/v1/incidents')
    expect(DASHBOARD_CONTRACT_MATRIX.timeline.detailEndpoint).toBe('/api/v1/incidents/{id}/timeline')
    expect(DASHBOARD_CONTRACT_MATRIX.topology.requiredFields).toEqual(['nodes', 'edges', 'updated_at'])
  })

  it('keeps dashboard contract endpoints represented in the API matrix', () => {
    const endpointPaths = Object.values(API_CONTRACT_MATRIX).flatMap(domain => domain.endpoints.map(endpoint => endpoint.path))

    for (const contract of Object.values(DASHBOARD_CONTRACT_MATRIX)) {
      expect(endpointPaths).toContain(contract.listEndpoint)
      if (contract.detailEndpoint) {
        expect(endpointPaths).toContain(contract.detailEndpoint)
      }
      for (const mutateEndpoint of contract.mutateEndpoints ?? []) {
        expect(endpointPaths).toContain(mutateEndpoint)
      }
    }
  })

  it('validates dashboard payloads and rejects malformed incident shapes', () => {
    expect(validateDashboardContractPayload('incidents', {
      id: 'inc-1',
      severity: 'high',
      status: 'new',
      title: 'Suspicious behavior chain',
      event_count: 3,
      created_at: '2026-05-13T01:00:00Z',
    })).toEqual({ valid: true, missing: [] })

    expect(validateDashboardContractPayload('incidents', {
      id: 'inc-2',
      severity: 'high',
      status: 'new',
      event_count: 1,
    })).toEqual({ valid: false, missing: ['title', 'created_at'] })
  })
})
