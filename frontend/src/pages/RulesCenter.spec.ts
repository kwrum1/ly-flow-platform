/// <reference types="node" />
/* @vitest-environment jsdom */

import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

const engineRules = vi.fn()
const engineRuntimeStatus = vi.fn()
const sources = vi.fn()
const engineHealth = vi.fn()
const platformSources = vi.fn()
const platformVersions = vi.fn()
const platformActiveBundle = vi.fn()

vi.mock('../api/domain', () => ({
  assetAgentClient: { engineHealth },
  ruleClient: {
    engineRules,
    engineRuntimeStatus,
    sources,
    platformSources,
    platformVersions,
    platformActiveBundle,
    platformSync: vi.fn(),
    platformActivateBundle: vi.fn(),
    updateSource: vi.fn(),
    updateRuleItem: vi.fn(),
  },
}))

describe('RulesCenter source semantics', () => {
  it('shows installed engines and real upstream sources instead of hardcoded rule categories', async () => {
    engineRules.mockResolvedValue({
      items: [],
      total: 0,
      counts: { suricata: 479, wazuh: 3, yara: 2, rasp: 2 },
      count_semantics: { suricata: { signature_count: 479, rule_file_count: 14 } },
    })
    engineRuntimeStatus.mockResolvedValue({ engines: { suricata: { running: true }, 'security-engine': { status: 'running', bundle_version: 'bundle-1', rule_counts: { traffic: 479 } } } })
    engineHealth.mockResolvedValue({ items: [
      { engine: 'suricata', installed: true, running: true, agent_status: 'online', rule_pack_version: 'et-open' },
      { engine: 'wazuh', installed: true, running: true, agent_status: 'online', rule_pack_version: 'wazuh-default' },
      { engine: 'yara', installed: true, running: true, agent_status: 'online', rule_pack_version: 'yara-security' },
      { engine: 'rasp', installed: true, running: true, agent_status: 'online', rule_pack_version: 'rasp-active' },
    ] })
    sources.mockResolvedValue({ items: [] })
    platformSources.mockResolvedValue({ items: [
      { source_id: 'et-open-connector', name: 'Emerging Threats Open Connector', category: 'traffic', license: 'ET Open', connector: true, updatable: true, restricted: false, url: 'https://rules.emergingthreats.net/open/suricata/emerging-all.rules' },
      { source_id: 'lyflow-default', name: 'LyFlow Default Rules', category: 'all', connector: false, updatable: false, restricted: false, url: '' },
    ] })
    platformVersions.mockResolvedValue({ items: [{ source_id: 'et-open-connector', version: 'catalog-20261020', synced_at: '2026-10-20T02:24:02Z' }] })
    platformActiveBundle.mockResolvedValue({ version: 'bundle-1' })

    const { default: RulesCenter } = await import('./RulesCenter.vue')
    const wrapper = mount(RulesCenter)
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('LyFlow 安全引擎')
    expect(text).toContain('Suricata')
    expect(text).toContain('Emerging Threats Open Connector')
    expect(text).toContain('rules.emergingthreats.net')
    expect(text).toContain('479')
    expect(text).toContain('可更新上游')
    expect(text).not.toContain('LyFlow Default Rules')
    expect(text).not.toContain('IP地理归属更新')
    expect(engineRules).toHaveBeenCalledOnce()
  })
})
