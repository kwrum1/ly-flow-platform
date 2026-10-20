import { describe, expect, it } from 'vitest'
import { attackStageOrder, buildAttackMatrix } from './attack-matrix'

describe('attack matrix', () => {
  it('keeps the canonical stage order', () => {
    expect(attackStageOrder[0].key).toBe('recon')
    expect(attackStageOrder.at(-1).key).toBe('unknown')
  })

  it('counts events by stage and technique', () => {
    const { matrix, observedTechniques } = buildAttackMatrix([
      { stage: 'initial_access', technique_id: 'T1190' },
      { stage: 'initial_access', technique_id: 'T1190' },
      { stage: 'execution', technique_id: 'T1059' },
      { stage: 'execution' },
    ])
    const initial = matrix.find((cell) => cell.key === 'initial_access')
    expect(initial.count).toBe(2)
    expect(initial.techniques[0]).toEqual({ id: 'T1190', count: 2 })
    const execution = matrix.find((cell) => cell.key === 'execution')
    expect(execution.count).toBe(2)
    expect(observedTechniques).toBe(3)
  })

  it('routes missing stages to unknown', () => {
    const { matrix } = buildAttackMatrix([{ technique_id: 'T1071' }])
    expect(matrix.find((cell) => cell.key === 'unknown').count).toBe(1)
  })
})
