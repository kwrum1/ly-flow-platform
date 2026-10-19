import { describe, expect, it } from 'vitest'
import { parseFlag, resolveFeatures } from './features'

describe('feature flags', () => {
  it('defaults to the ly_vis shell while keeping other flags off', () => {
    expect(parseFlag(undefined)).toBe(false)
    expect(parseFlag('', true)).toBe(true)
    expect(resolveFeatures({})).toEqual({
      uiShellV2: true,
      queryV2: false,
      attackV2: true,
      agentFacade: false,
      responseApproval: false,
    })
  })

  it('allows the legacy shell to be selected explicitly', () => {
    expect(resolveFeatures({ VITE_UI_SHELL_V2_ENABLED: 'false' }).uiShellV2).toBe(false)
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
