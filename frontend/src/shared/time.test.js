import { describe, expect, it } from 'vitest'
import { formatChinaDateTime, formatChinaTime } from './time'

describe('中国时间格式化', () => {
  it('把 UTC 时间转换为中国时间展示', () => {
    expect(formatChinaDateTime('2026-05-13T00:00:00Z')).toContain('2026')
    expect(formatChinaDateTime('2026-05-13T00:00:00Z')).toContain('08:00:00')
  })

  it('返回中文异常提示而不是开发术语', () => {
    expect(formatChinaTime('not-a-time')).toBe('时间格式异常')
    expect(formatChinaDateTime()).toBe('暂无时间')
  })
})
