import { describe, expect, it } from 'vitest'
import { normalizeAttackQueueItems } from './normalize'

describe('attack queue normalization', () => {
  it('preserves source module, entity id, and raw reference fields', () => {
    const [event] = normalizeAttackQueueItems({
      '/rasp/events': [
        {
          id: 'rasp-1',
          severity: 'high',
          status: 'open',
          attack_type: 'sql_injection',
          entity_id: 'app:web-checkout',
          raw_reference: { capture_ref: 'evidence/rasp-1.json' },
        },
      ],
    })

    expect(event).toMatchObject({
      id: 'rasp-1',
      source: 'rasp',
      entityId: 'app:web-checkout',
      rawReference: 'evidence/rasp-1.json',
    })
  })
})
