import { describe, expect, it } from 'vitest'
import { backendGapReport, criticalBackendGaps } from './backend-gap-report'

describe('正式发布剩余缺口审计', () => {
  it('记录目标环境成熟前必须补齐的关键证据', () => {
    const critical = criticalBackendGaps()
    expect(critical.map((item) => item.domain)).toContain('现场 Agent 认证')
    expect(critical.map((item) => item.domain)).toContain('检测质量基线')
    expect(critical.map((item) => item.domain)).toContain('RASP 兼容矩阵')
  })

  it('每个缺口都有正式发布要求和代码来源', () => {
    expect(backendGapReport.every((item) => item.requiredForRelease && item.source)).toBe(true)
  })

  it('不会把已修复的核心闭环继续列为缺口', () => {
    const domains = backendGapReport.map((item) => item.domain)
    expect(domains).not.toContain('攻击链工作台')
    expect(domains).not.toContain('统一事件')
  })
})
