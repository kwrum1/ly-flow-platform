export const navGroups = [
  {
    title: 'Security Operations Console',
    items: [
      { path: '/dashboard', label: 'Overview', hint: '安全态势、Agent 覆盖与资源总览', icon: 'M3 13h8V3H3v10z M13 21h8V3h-8v18z M3 21h8v-6H3v6z', match: ['/dashboard'] },
      { path: '/timeline', label: 'Attack Chain', hint: '攻击链时间线与阶段图', icon: 'M12 8v5l3 3 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z', match: ['/timeline'] },
      { path: '/assets', label: 'Assets', hint: '资产资源利用率与风险', icon: 'M3 4h18v12H3V4z M8 20h8 M12 16v4', match: ['/assets'] },
      { path: '/events', label: '事件队列', hint: 'DPI、Runtime、RASP、XDR 统一事件', icon: 'M12 9v4 M12 17h.01 M10.29 3.86 1.82 18h20.36L13.71 3.86a2 2 0 0 0-3.42 0z', badge: 'Events', match: ['/events', '/unified'] },
      { path: '/incidents', label: 'Incidents 事件', hint: '攻击链与处置状态', icon: 'M5 3h14v4H5z M5 10h14v11H5z M9 14h6 M9 18h3', badge: 'P1', match: ['/incidents'] },
    ]
  },
  {
    title: 'Analysis Centers',
    items: [
      { path: '/logs', label: 'Log Audit', hint: 'SSH/sudo/nginx 日志分析', icon: 'M4 4h16v16H4z M8 8h8 M8 12h8 M8 16h5', match: ['/logs'] },
      { path: '/traffic', label: 'Traffic Analysis', hint: '语义流量与 DPI 告警', icon: 'M4 7h6l2 3h8 M4 17h6l2-3h8', match: ['/traffic'] },
      { path: '/defense', label: 'RASP/Runtime', hint: '应用与主机运行时防护', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', match: ['/defense', '/rasp', '/runtime'] },
      { path: '/topology', label: 'Topology 拓扑', hint: '主机、进程、服务调用关系', icon: 'M6 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M18 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M12 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M8 6l8 0 M7 8l4 9 M17 8l-4 9', match: ['/topology'] },
      { path: '/intelligence', label: '威胁情报', hint: 'RASP、Runtime 与 XDR 合并视图', icon: 'M22 12h-4l-3 8L9 4l-3 8H2', match: ['/intelligence', '/xdr', '/rasp', '/runtime'] },
      { path: '/intelligence/rules', label: '检测规则', hint: '规则覆盖与命中', icon: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h8', match: ['/intelligence/rules'], roles: ['admin'] },
      { path: '/situation/global', label: '全球态势', hint: '外部攻击热区与趋势', icon: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M2 12h20 M12 2a15.3 15.3 0 0 1 0 20 M12 2a15.3 15.3 0 0 0 0 20', match: ['/situation/global'] }
    ]
  },
  {
    title: 'Control & Management',
    items: [
      { path: '/control', label: 'Agent Control', hint: '安装、下载、策略与漂移', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', match: ['/control'], roles: ['admin'] },
      { path: '/settings', label: 'System Management', hint: '账号、策略与系统安全', icon: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06-2.83 2.83-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21h-4v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06-2.83-2.83.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3v-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06 2.83-2.83.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3h4v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06 2.83 2.83-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21v4h-.09a1.65 1.65 0 0 0-1.51 1z', match: ['/settings'], roles: ['admin'] },
      { path: '/reports', label: '报告中心', hint: '风险复盘与输出', icon: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h5', match: ['/reports'] },
    ]
  }
]

export const routeMeta = {
  '/dashboard': { crumbs: ['首页', '风险驾驶舱'], intent: '先看可经营风险，再进处置队列。' },
  '/assets': { crumbs: ['首页', '暴露与情报', '资产暴露面'], intent: '定位受影响业务资产与覆盖缺口。' },
  '/events': { crumbs: ['首页', '优先处置', '事件队列'], intent: '筛选统一事件并查看原始证据引用。' },
  '/incidents': { crumbs: ['首页', '优先处置', 'Incidents 事件'], intent: '优先闭环跨源关联形成的攻击链。' },
  '/timeline': { crumbs: ['首页', '暴露与情报', 'Timeline 时间线'], intent: '按时间复盘 DPI、Runtime、RASP 与 XDR 证据。' },
  '/topology': { crumbs: ['首页', '暴露与情报', 'Topology 拓扑'], intent: '查看主机、进程、服务和流量之间的关系。' },
  '/unified': { crumbs: ['首页', '统一事件'], intent: '保留统一事件旧入口，展示同一攻击队列。' },
  '/intelligence': { crumbs: ['首页', '暴露与情报', 'DPI 语义'], intent: '把流量信号转成业务语义。' },
  '/intelligence/dpi': { crumbs: ['首页', '暴露与情报', 'DPI 语义'], intent: '把流量信号转成业务语义。' },
  '/intelligence/xdr': { crumbs: ['首页', '暴露与情报', 'XDR 关联'], intent: '跨 DPI、Runtime、RASP 汇聚攻击链。' },
  '/xdr': { crumbs: ['首页', '暴露与情报', 'XDR 关联'], intent: '跨源事件聚合和攻击链检测。' },
  '/intelligence/rasp': { crumbs: ['首页', '暴露与情报', 'RASP 应用'], intent: '查看应用运行时阻断与证据。' },
  '/rasp': { crumbs: ['首页', '暴露与情报', 'RASP 应用'], intent: '查看应用运行时阻断与证据。' },
  '/runtime': { crumbs: ['首页', '暴露与情报', 'Runtime 主机'], intent: '查看进程、文件与主机行为。' },
  '/intelligence/rules': { crumbs: ['首页', '暴露与情报', '检测规则'], intent: '评估规则覆盖与命中质量。' },
  '/control': { crumbs: ['首页', '控制与设置', 'Agent 控制'], intent: '确认采集覆盖与防护模式。' },
  '/situation/global': { crumbs: ['首页', '暴露与情报', '全球态势'], intent: '查看外部攻击趋势与地理来源。' },
  '/reports': { crumbs: ['首页', '控制与设置', '报告中心'], intent: '生成可交付的风险复盘。' },
  '/threat-intel': { crumbs: ['首页', '控制与设置', '威胁情报'], intent: '验证 IOC 置信度与命中情况。' },
  '/vulnerabilities': { crumbs: ['首页', '控制与设置', '漏洞风险'], intent: '关联漏洞与受影响业务资产。' },
  '/settings': { crumbs: ['首页', '控制与设置', '系统设置'], intent: '配置账号、告警与安全策略。' }
}

export function flattenNavPaths(groups = navGroups) {
  return groups.flatMap((group) => group.items.map((item) => item.path))
}

export function findDuplicateNavPaths(groups = navGroups) {
  const seen = new Set()
  const duplicates = new Set()

  flattenNavPaths(groups).forEach((path) => {
    if (seen.has(path)) duplicates.add(path)
    seen.add(path)
  })

  return Array.from(duplicates)
}

export function navIndex(path, groups = navGroups) {
  return flattenNavPaths(groups).indexOf(path)
}
