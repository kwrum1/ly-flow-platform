export const V4_NAVIGATION = Object.freeze([
  {
    title: '运营',
    items: [
      { path: '/overview', label: '态势总览', description: '风险、趋势与覆盖' },
      { path: '/incidents', label: '攻击链处置', description: '证据链与闭环' },
      { path: '/events', label: '事件检索', description: '统一事件下钻' },
    ],
  },
  {
    title: '检测',
    items: [
      { path: '/threats', label: '检测面', description: '流量 / 主机 / 应用' },
    ],
  },
  {
    title: '资产与数据',
    items: [
      { path: '/assets', label: '资产运维', description: '资产、Agent 与能力' },
      { path: '/rules', label: '规则中心', description: '规则源与版本' },
    ],
  },
  {
    title: '系统',
    items: [
      { path: '/settings', label: '系统管理', description: '平台、账户与安装' },
    ],
  },
])

export function flattenV4Navigation() {
  return V4_NAVIGATION.flatMap((group) => group.items.map((item) => ({ ...item, group: group.title })))
}
