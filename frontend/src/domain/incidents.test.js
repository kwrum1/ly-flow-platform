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

  it('separates the victim address from the requested domain', () => {
    const incident = normalizeIncident({
      incident_id: 'inc-2',
      victim_display: '10.1.0.101',
      requested_domains: ['cas.example.test'],
      evidence: [{
        event_id: 'evt-2',
        narrative: '10.1.1.1 对 10.1.0.101 尝试路径穿越。',
        victim_ip: '10.1.0.101',
        dst_ip: '10.1.0.101',
        requested_domain: 'cas.example.test',
        client_forwarded_for: '203.0.113.9',
        src_ip: '10.1.1.1',
      }],
    })

    // The victim is the wire destination, never the requested host name.
    expect(incident.victimDisplay).toBe('10.1.0.101')
    expect(incident.requestedDomains).toEqual(['cas.example.test'])
    expect(incident.evidence[0].targetIP).toBe('10.1.0.101')
    // The timeline shows the explanation, not the raw rule message.
    expect(incident.evidence[0].summary).toContain('路径穿越')
    // X-Forwarded-For stays a self-reported reference.
    expect(incident.evidence[0].forwardedFor).toBe('203.0.113.9')
  })
})
