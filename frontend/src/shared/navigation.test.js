import { describe, expect, it } from 'vitest'
import { V4_NAVIGATION, flattenV4Navigation } from '../v4/navigation'

describe('流影 v4 导航', () => {
  it('只保留可运营的作业面', () => {
    expect(V4_NAVIGATION.map((group) => group.title)).toEqual(['运营', '检测', '资产与数据', '系统'])
    expect(V4_NAVIGATION[0].items.map((item) => item.label)).toEqual(['态势总览', '攻击链处置', '事件检索'])
    expect(V4_NAVIGATION[1].items.map((item) => item.label)).toEqual(['检测面'])
    expect(V4_NAVIGATION[2].items.map((item) => item.label)).toEqual(['资产运维', '数据与健康', '规则中心'])
    expect(V4_NAVIGATION[3].items.map((item) => item.label)).toEqual(['系统管理'])
  })

  it('砍掉的旧入口不再出现在导航里', () => {
    const labels = flattenV4Navigation().map((item) => item.label)
    for (const removed of ['全球态势', '证据库', '响应处置', '时间线', '引擎健康', '账户管理']) {
      expect(labels).not.toContain(removed)
    }
  })

  it('每个入口路径唯一且都有说明', () => {
    const items = flattenV4Navigation()
    const paths = items.map((item) => item.path)
    expect(new Set(paths).size).toBe(paths.length)
    for (const item of items) {
      expect(item.description.length).toBeGreaterThan(0)
    }
  })
})
