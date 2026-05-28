import { describe, expect, it } from 'vitest'
import { normalizeIncident, summarizeIncidents } from './incidents'

describe('incident domain normalization', () => {
  it('normalizes XDR chain incidents without converting every event into an incident', () => {
    const incident = normalizeIncident({
      incident_id: 'inc-1',
      severity: 'critical',
      status: 'triaged',
      affected_asset: 'checkout-01',
      attack_chain: [{ source_module: 'runtime', message: 'process spawned shell' }],
      evidence: [{ event_id: 'evt-1', source_module: 'rasp', raw_reference: 'evidence/evt-1.json' }],
    })

    expect(incident).toMatchObject({
      id: 'inc-1',
      severity: 'critical',
      status: 'triaged',
      affectedAsset: 'checkout-01',
    })
    expect(incident.stages[0]).toMatchObject({ sourceModule: 'runtime' })
    expect(incident.evidence[0]).toMatchObject({ sourceModule: 'rasp', rawReference: 'evidence/evt-1.json' })
  })

  it('summarizes open and high-risk incidents', () => {
    expect(summarizeIncidents([
      { severity: 'critical', status: 'open' },
      { severity: 'high', status: 'closed' },
    ])).toEqual({ critical: 1, high: 1, open: 1 })
  })
})
