import { describe, expect, it } from 'vitest'
import { canAccessNavigationItem, flattenNavigation, productNavigation } from './navigation'

describe('流影运营导航', () => {
  it('按当前产品口径展示核心运营、检测面和系统管理入口', () => {
    expect(productNavigation.map((group) => group.title)).toEqual(['核心运营', '检测面', '系统管理'])
    expect(productNavigation[0].items.map((item) => item.label)).toEqual(['运营总览', '攻击链处置', '资产运维'])
    expect(productNavigation[1].items.map((item) => item.label)).toEqual(['流量威胁', 'XDR 调查', '运行威胁', '应用威胁', '事件中心'])
    expect(productNavigation[2].items.map((item) => item.label)).toEqual(['规则中心', '控制中心', '安装配置', '账户管理'])
  })

  it('所有导航文案都是中文自然语言且不暴露内部占位文案', () => {
    const text = flattenNavigation().map((item) => `${item.label}${item.description}`).join(' ')
    for (const label of ['运营总览', '事件中心', '攻击链处置', '流量威胁', 'XDR 调查', '运行威胁', '应用威胁', '规则中心', '资产运维', '安装配置', '账户管理']) {
      expect(text).toContain(label)
    }
    expect(text).not.toMatch(/TODO|mock|demo|placeholder|test/i)
  })

  it('管理员入口受角色控制', () => {
    for (const item of flattenNavigation()) {
      expect(canAccessNavigationItem(item, 'viewer')).toBe(false)
      expect(canAccessNavigationItem(item, 'admin')).toBe(true)
    }
  })
})
