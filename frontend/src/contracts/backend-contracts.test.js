import { describe, expect, it } from 'vitest'
import {
  backendContractDomains,
  forbiddenUiTerms,
  listBackendGaps,
  listUiRequiredRoutes,
  productIdentity,
} from './backend-contracts'

describe('流影后端驱动前端契约', () => {
  it('使用商业化产品身份和中国时间', () => {
    expect(productIdentity).toMatchObject({
      name: '流影',
      primaryWorkspace: '攻击链工作台',
      locale: 'zh-CN',
      timeZone: 'Asia/Shanghai',
    })
  })

  it('覆盖文档要求的用户可见产品域', () => {
    expect(backendContractDomains.map((domain) => domain.id)).toEqual([
      'auth',
      'attack-workbench',
      'assets-agents',
      'rules',
      'signals',
      'traffic-overview',
    ])
  })

  it('所有用户可见产品域都绑定真实 API 路由', () => {
    const routes = listUiRequiredRoutes()
    expect(routes.length).toBeGreaterThan(40)
    expect(routes.every((route) => route.path.startsWith('/api/v1/'))).toBe(true)
    expect(routes.some((route) => route.path === '/api/v1/unified/events')).toBe(true)
    expect(routes.some((route) => route.path === '/api/v1/incidents')).toBe(true)
    expect(routes.some((route) => route.path === '/api/v1/timeline')).toBe(true)
    expect(routes.some((route) => route.path === '/api/v1/agent/install.sh')).toBe(true)
    expect(routes.some((route) => route.path === '/api/v1/rasp/protection/status')).toBe(true)
  })

  it('标记需要后端先补齐的真实持久化缺口', () => {
    const gaps = listBackendGaps()
    expect(gaps.length).toBeGreaterThanOrEqual(5)
    expect(gaps.map((item) => item.domain)).toContain('attack-workbench')
    expect(gaps.map((item) => item.domain)).toContain('signals')
    expect(gaps.map((item) => item.gap).join(' ')).toContain('真实持久化')
  })

  it('禁止测试产品、占位和假数据词进入用户界面文案', () => {
    expect(forbiddenUiTerms).toContain('占位')
    expect(forbiddenUiTerms).toContain('假数据')
    expect(forbiddenUiTerms).toContain('测试产品')
  })
})
