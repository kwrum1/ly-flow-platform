export const stageLabels = Object.freeze({
  recon: '侦察',
  initial_access: '初始访问',
  execution: '执行',
  persistence: '持久化',
  privilege_escalation: '提权',
  defense_evasion: '防御规避',
  credential_access: '凭据访问',
  discovery: '发现',
  lateral_movement: '横向移动',
  collection: '收集',
  command_and_control: '命令控制',
  exfiltration: '外传',
  impact: '影响',
  unknown: '未映射',
})

export function stageLabel(value) {
  return stageLabels[value] || value || '-'
}

export function severityLabel(value) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危' })[value] || value || '-'
}
