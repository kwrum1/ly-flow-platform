import { describe, expect, it } from 'vitest'
import { backendGapReport, criticalBackendGaps } from './backend-gap-report'

describe('后端先行缺口审计', () => {
  it('记录攻击链工作台上线前必须补齐的关键缺口', () => {
    const critical = criticalBackendGaps()
    expect(critical.map((item) => item.domain)).toContain('攻击链工作台')
    expect(critical.map((item) => item.domain)).toContain('统一事件')
    expect(critical.map((item) => item.domain)).toContain('RASP 与 Runtime')
  })

  it('每个缺口都有 UI 前置要求和代码来源', () => {
    expect(backendGapReport.every((item) => item.requiredBeforeUi && item.source)).toBe(true)
  })

  it('缺口描述不包含测试产品或占位表达', () => {
    const text = backendGapReport.map((item) => `${item.finding}${item.requiredBeforeUi}`).join(' ')
    expect(text).not.toMatch(/mock|demo|placeholder|测试产品|占位|假数据/i)
  })
})
