import { describe, expect, it, vi } from 'vitest'

vi.mock('./index', () => ({
  default: {
    get: vi.fn((path, config) => ({ method: 'GET', path, config })),
    post: vi.fn((path, payload) => ({ method: 'POST', path, payload })),
  },
}))

const clients = await import('./domain')

describe('流影领域 API 客户端', () => {
  it('攻击链工作台客户端覆盖事件、事故和时间线', () => {
    expect(clients.attackWorkbenchClient.events({ limit: 20 })).toMatchObject({ path: '/unified/events' })
    expect(clients.attackWorkbenchClient.incident('inc-1')).toMatchObject({ path: '/incidents/inc-1' })
    expect(clients.attackWorkbenchClient.timelineItem('tl-1')).toMatchObject({ path: '/timeline/tl-1' })
  })

  it('资产和 Agent 客户端覆盖安装、下载和详情', () => {
    expect(clients.assetAgentClient.agents()).toMatchObject({ path: '/agents' })
    expect(clients.assetAgentClient.agent('agent-1')).toMatchObject({ path: '/agents/agent-1' })
    expect(clients.assetAgentClient.installScript()).toMatchObject({ path: '/agent/install.sh' })
  })

  it('规则、信号和总览客户端使用真实后端路径', () => {
    expect(clients.ruleClient.test({})).toMatchObject({ method: 'POST', path: '/rules/test' })
    expect(clients.signalClient.raspProtectionStatus()).toMatchObject({ path: '/rasp/protection/status' })
    expect(clients.overviewClient.globalSituation()).toMatchObject({ path: '/public/situation/global' })
  })
})
