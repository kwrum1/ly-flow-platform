import { describe, expect, it } from 'vitest'
import { findDuplicateNavPaths, navGroups, navIndex } from './nav-config'

describe('layout nav config', () => {
  it('keeps disposal-priority order', () => {
    const overviewPos = navIndex('/dashboard', navGroups)
    const timelinePos = navIndex('/timeline', navGroups)
    const assetsPos = navIndex('/assets', navGroups)
    const eventsPos = navIndex('/events', navGroups)
    const incidentsPos = navIndex('/incidents', navGroups)
    const topologyPos = navIndex('/topology', navGroups)
    const intelligencePos = navIndex('/intelligence', navGroups)

    expect(overviewPos).toBeGreaterThanOrEqual(0)
    expect(timelinePos).toBeGreaterThan(overviewPos)
    expect(assetsPos).toBeGreaterThan(timelinePos)
    expect(eventsPos).toBeGreaterThan(assetsPos)
    expect(incidentsPos).toBeGreaterThan(eventsPos)
    expect(topologyPos).toBeGreaterThan(incidentsPos)
    expect(intelligencePos).toBeGreaterThan(topologyPos)
  })

  it('exposes the five requested architecture modules', () => {
    const requiredModules = [
      { path: '/assets', label: 'Assets' },
      { path: '/events', label: '事件队列' },
      { path: '/incidents', label: 'Incidents 事件' },
      { path: '/timeline', label: 'Attack Chain' },
      { path: '/topology', label: 'Topology 拓扑' },
    ]
    const items = navGroups.flatMap(group => group.items)

    requiredModules.forEach((module) => {
      expect(items).toContainEqual(expect.objectContaining(module))
    })
  })

  it('exposes the rebuilt security operations console modules', () => {
    const labels = navGroups.flatMap(group => group.items.map(item => item.label))
    ;['Overview', 'Attack Chain', 'Assets', 'Log Audit', 'Traffic Analysis', 'RASP/Runtime', 'Agent Control', '检测规则', 'System Management'].forEach((label) => {
      expect(labels).toContain(label)
    })
  })

  it('consolidates threat intelligence navigation terminology', () => {
    const labels = navGroups.flatMap(group => group.items.map(item => item.label))
    expect(labels.filter(label => label === '威胁情报')).toHaveLength(1)
    expect(labels).not.toContain('DPI 语义')
    expect(labels).not.toContain('XDR 关联')
    expect(labels).not.toContain('RASP 应用')
    expect(labels).not.toContain('Runtime 主机')
  })

  it('has no duplicate key navigation entries', () => {
    const duplicates = findDuplicateNavPaths(navGroups)
    expect(duplicates).not.toContain('/events')
    expect(duplicates).not.toContain('/assets')
    expect(duplicates).not.toContain('/incidents')
    expect(duplicates).not.toContain('/timeline')
    expect(duplicates).not.toContain('/topology')
    expect(duplicates).not.toContain('/xdr')
    expect(duplicates).toEqual([])
  })

  it('keeps admin-only navigation restricted', () => {
    const adminOnlyPaths = navGroups
      .flatMap(group => group.items)
      .filter(item => Array.isArray(item.roles) && item.roles.includes('admin'))
      .map(item => item.path)

    expect(adminOnlyPaths).toContain('/control')
    expect(adminOnlyPaths).toContain('/intelligence/rules')
    expect(adminOnlyPaths).not.toContain('/events')
    expect(adminOnlyPaths).not.toContain('/assets')
    expect(adminOnlyPaths).not.toContain('/incidents')
    expect(adminOnlyPaths).not.toContain('/timeline')
    expect(adminOnlyPaths).not.toContain('/topology')
  })
})
