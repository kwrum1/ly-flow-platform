/// <reference types="node" />
/* @vitest-environment jsdom */

import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

const engineRules = vi.fn()
const engineRuntimeStatus = vi.fn()
const sources = vi.fn()

vi.mock('../api/domain', () => ({
  ruleClient: {
    engineRules,
    engineRuntimeStatus,
    sources,
    updateSource: vi.fn(),
    updateRuleItem: vi.fn(),
    updateEngineRules: vi.fn(),
  },
}))

describe('RulesCenter count semantics', () => {
  it('renders typed signed signature and rule-file counts', async () => {
    engineRules.mockResolvedValue({
      items: [],
      total: 0,
      counts: { suricata: 479, wazuh: 3, yara: 2, rasp: 2 },
      count_semantics: {
        suricata: {
          signature_count: 479,
          rule_file_count: 14,
          source: 'signed_active_lifecycle',
          ledger_digest: '7fcc908e17d05fea6a0716168aa8580ccf1d0ed8c032f2f8936aec9a0aaeaf28',
        },
      },
    })
    engineRuntimeStatus.mockResolvedValue({ engines: { suricata: { installed: true, running: true }, wazuh: {}, yara: {}, geoip: {} } })
    sources.mockResolvedValue({ items: [{ source_id: 'suricata-et-open', name: 'ET Open', category: 'dpi', vendor: 'Proofpoint' }] })

    const { default: RulesCenter } = await import('./RulesCenter.vue')
    const wrapper = mount(RulesCenter)
    await flushPromises()

    expect(wrapper.text()).toContain('规则签名')
    expect(wrapper.text()).toContain('479 条')
    expect(wrapper.text()).toContain('规则文件')
    expect(wrapper.text()).toContain('14 个')
    expect(wrapper.text()).not.toContain('规则数量\n479 条')
    expect(engineRules).toHaveBeenCalledOnce()
  })
})
