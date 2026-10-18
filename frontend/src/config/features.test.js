import { describe, expect, it } from 'vitest'
import { parseFlag, resolveFeatures } from './features'

describe('feature flags', () => {
  it('defaults to false', () => {
    expect(parseFlag(undefined)).toBe(false)
    expect(parseFlag('', true)).toBe(true)
    expect(resolveFeatures({})).toEqual({
      uiShellV2: false,
      queryV2: false,
      attackV2: false,
      agentFacade: false,
      responseApproval: false,
    })
  })

  it('accepts common truthy spellings', () => {
    for (const value of ['1', 'true', 'TRUE', 'yes', 'on']) {
      expect(parseFlag(value)).toBe(true)
    }
    for (const value of ['0', 'false', 'no', 'off']) {
      expect(parseFlag(value)).toBe(false)
    }
  })

  it('resolves each flag independently', () => {
    expect(resolveFeatures({
      VITE_UI_SHELL_V2_ENABLED: 'true',
      VITE_QUERY_V2_ENABLED: '1',
      VITE_ATTACK_V2_ENABLED: 'yes',
      VITE_AGENT_FACADE_ENABLED: 'on',
      VITE_RESPONSE_APPROVAL_ENABLED: 'TRUE',
    })).toEqual({
      uiShellV2: true,
      queryV2: true,
      attackV2: true,
      agentFacade: true,
      responseApproval: true,
    })
  })
})
