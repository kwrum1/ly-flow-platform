import { describe, expect, it } from 'vitest'
import { activeGroupForPath, activeItemsForPath, visibleGroups } from './navigation'

describe('ly_vis-style shell navigation', () => {
  it('filters groups by role', () => {
    const groups = visibleGroups('viewer')
    expect(groups).toEqual([])
    expect(visibleGroups('admin').length).toBe(3)
  })

  it('selects the group that owns the current path', () => {
    expect(activeGroupForPath('/incidents')?.title).toBe('核心运营')
    expect(activeGroupForPath('/traffic-threats')?.title).toBe('检测面')
    expect(activeGroupForPath('/rules')?.title).toBe('系统管理')
  })

  it('matches nested paths', () => {
    expect(activeGroupForPath('/incidents/abc')?.title).toBe('核心运营')
  })

  it('falls back to the first visible group', () => {
    expect(activeGroupForPath('/unknown')?.title).toBe('核心运营')
  })

  it('returns the active group tabs', () => {
    const items = activeItemsForPath('/rasp', 'admin')
    expect(items.map((item) => item.path)).toContain('/rasp')
  })
})
