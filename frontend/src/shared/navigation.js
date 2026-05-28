export const productNavigation = Object.freeze([
  {
    title: '核心运营',
    items: [
      { path: '/dashboard', label: '运营总览', description: '健康、风险、攻击态势', roles: ['admin'] },
      { path: '/incidents', label: '攻击链处置', description: '按渗透阶段串联证据', roles: ['admin'] },
      { path: '/assets', label: '资产运维', description: '', roles: ['admin'] },
    ],
  },
  {
    title: '检测面',
    items: [
      { path: '/traffic-threats', label: '流量威胁', description: '', roles: ['admin'] },
      { path: '/runtime', label: '运行威胁', description: '', roles: ['admin'] },
      { path: '/rasp', label: '应用威胁', description: '', roles: ['admin'] },
      { path: '/events', label: '会话查询', description: '', roles: ['admin'] },
    ],
  },
  {
    title: '系统管理',
    items: [
      { path: '/rules', label: '规则中心', description: '', roles: ['admin'] },
      { path: '/control-center', label: '控制中心', description: '', roles: ['admin'] },
      { path: '/install-config', label: '安装配置', description: '', roles: ['admin'] },
      { path: '/users', label: '账户管理', description: '', roles: ['admin'] },
    ],
  },
])

export function flattenNavigation() {
  return productNavigation.flatMap((group) => group.items.map((item) => ({ ...item, group: group.title })))
}

export function canAccessNavigationItem(item, role) {
  if (!item.roles || item.roles.length === 0) return true
  return item.roles.includes(role)
}
