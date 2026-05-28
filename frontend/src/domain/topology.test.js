import { describe, expect, it } from 'vitest'
import { buildTopology } from './topology'

describe('topology domain', () => {
  it('aggregates repeated semantic flows into bounded edges', () => {
    const graph = buildTopology({
      assets: [{ id: 'host-1', hostname: 'checkout-01', risk_level: 'high' }],
      flows: [
        { asset_id: 'host-1', domain: 'api.example.com', count: 4, risk_level: 'medium' },
        { asset_id: 'host-1', domain: 'api.example.com', count: 6, risk_level: 'high' },
      ],
    })

    expect(graph.nodes.map((item) => item.id)).toEqual(expect.arrayContaining(['host-1', 'api.example.com']))
    expect(graph.edges).toHaveLength(1)
    expect(graph.edges[0]).toMatchObject({ source: 'host-1', target: 'api.example.com', count: 10, risk: 'high' })
  })
})
