export const attackStageOrder = Object.freeze([
  { key: 'recon', label: '侦察' },
  { key: 'initial_access', label: '初始访问' },
  { key: 'execution', label: '执行' },
  { key: 'persistence', label: '持久化' },
  { key: 'privilege_escalation', label: '提权' },
  { key: 'defense_evasion', label: '防御规避' },
  { key: 'credential_access', label: '凭据访问' },
  { key: 'discovery', label: '发现' },
  { key: 'lateral_movement', label: '横向移动' },
  { key: 'collection', label: '收集' },
  { key: 'command_and_control', label: '命令控制' },
  { key: 'exfiltration', label: '外传' },
  { key: 'impact', label: '影响' },
  { key: 'unknown', label: '未映射' },
])

export function buildAttackMatrix(events = []) {
  const byStage = new Map(attackStageOrder.map((stage) => [stage.key, { ...stage, count: 0, techniques: new Map() }]))
  for (const event of events) {
    const stageKey = byStage.has(event?.stage) ? event.stage : 'unknown'
    const cell = byStage.get(stageKey)
    cell.count += 1
    const technique = event?.technique_id || 'unmapped'
    cell.techniques.set(technique, (cell.techniques.get(technique) || 0) + 1)
  }
  const observed = new Set()
  const matrix = [...byStage.values()].map((cell) => ({
    key: cell.key,
    label: cell.label,
    count: cell.count,
    techniques: [...cell.techniques.entries()]
      .map(([id, count]) => ({ id, count }))
      .sort((left, right) => right.count - left.count || left.id.localeCompare(right.id)),
  }))
  for (const cell of matrix) {
    for (const technique of cell.techniques) observed.add(technique.id)
  }
  return { matrix, observedTechniques: observed.size }
}
