export const productNavigation = Object.freeze([
  {
    title: '态势',
    items: [
      { path: '/dashboard', label: '态势总览', description: '风险、攻击链与实时检测', roles: ['admin'] },
      { path: '/incidents', label: '攻击链处置', description: '按渗透阶段串联证据', roles: ['admin'] },
      { path: '/events', label: '事件中心', description: '统一事件检索与证据下钻', roles: ['admin'] },
    ],
  },
  {
    title: '检测',
    items: [
      { path: '/traffic-threats', label: '流量威胁', description: 'Suricata / DPI / 流量会话', roles: ['admin'] },
      { path: '/runtime', label: '运行威胁', description: 'Wazuh / 主机运行时告警', roles: ['admin'] },
      { path: '/rasp', label: '应用威胁', description: 'RASP 运行时攻击与阻断', roles: ['admin'] },
      { path: '/xdr', label: 'XDR 调查', description: '跨源关联与攻击时间线', roles: ['admin'] },
      { path: '/situation/global', label: '全球态势', description: '公网攻击来源与目标', roles: ['admin'] },
    ],
  },
  {
    title: '资产与处置',
    items: [
      { path: '/assets', label: '资产与 Agent', description: '资产 360、Agent 与能力', roles: ['admin'] },
      { path: '/response', label: '响应处置', description: '审批、执行与回滚', roles: ['admin'] },
      { path: '/evidence', label: '证据库', description: 'PCAP / 证据包 / 哈希', roles: ['admin'] },
    ],
  },
  {
    title: '平台',
    items: [
      { path: '/rules', label: '规则中心', description: '规则源、索引与生命周期', roles: ['admin'] },
      { path: '/engines', label: '引擎健康', description: 'Suricata / Wazuh / RASP / YARA', roles: ['admin'] },
      { path: '/control-center', label: '控制中心', description: '采集接口、时间与 Agent 控制', roles: ['admin'] },
      { path: '/install-config', label: '安装配置', description: 'Agent 安装与令牌', roles: ['admin'] },
      { path: '/users', label: '账户管理', description: '用户、角色与登录状态', roles: ['admin'] },
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
