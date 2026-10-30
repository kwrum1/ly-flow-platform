import { describe, expect, it } from 'vitest'
import { V4_NAVIGATION } from '../../v4/navigation'

describe('v4 shell navigation', () => {
  it('每个分组都有入口', () => {
    expect(V4_NAVIGATION.length).toBe(4)
    for (const group of V4_NAVIGATION) {
      expect(group.items.length).toBeGreaterThan(0)
    }
  })

  it('态势总览是默认落点', () => {
    expect(V4_NAVIGATION[0].items[0].path).toBe('/overview')
  })

  it('检测面是一个合并后的入口', () => {
    const threats = V4_NAVIGATION.flatMap((group) => group.items).find((item) => item.path === '/threats')
    expect(threats).toBeTruthy()
    expect(threats.label).toBe('检测面')
  })
})
