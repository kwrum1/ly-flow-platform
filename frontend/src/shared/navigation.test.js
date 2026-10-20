import { describe, expect, it } from 'vitest'
import { canAccessNavigationItem, flattenNavigation, productNavigation } from './navigation'

describe('流影运营导航', () => {
  it('按当前产品口径展示核心运营、检测面、资产与处置和系统管理入口', () => {
    expect(productNavigation.map((group) => group.title)).toEqual(['核心运营', '检测面', '资产与处置', '系统管理'])
    expect(productNavigation[0].items.map((item) => item.label)).toEqual(['运营总览', '攻击链处置', '事件中心'])
    expect(productNavigation[1].items.map((item) => item.label)).toEqual(['流量威胁', 'XDR 调查', '运行威胁', '应用威胁', '全球态势'])
    expect(productNavigation[2].items.map((item) => item.label)).toEqual(['资产运维', '响应处置', '证据库'])
    expect(productNavigation[3].items.map((item) => item.label)).toEqual(['规则中心', '引擎健康', '平台设置', '安装配置', '账户管理'])
  })

  it('所有导航文案都是中文自然语言且不暴露内部占位文案', () => {
    const text = flattenNavigation().map((item) => `${item.label}${item.description}`).join(' ')
    for (const label of ['运营总览', '事件中心', '攻击链处置', '流量威胁', 'XDR 调查', '运行威胁', '应用威胁', '规则中心', '资产运维', '安装配置', '账户管理', '响应处置', '证据库', '引擎健康']) {
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
