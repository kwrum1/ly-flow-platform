function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === 0) return '0'
    if (value !== undefined && value !== null && String(value).trim() !== '') return String(value)
  }
  return ''
}

function normalizeSeverity(value) {
  const severity = String(value || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low'].includes(severity)) return severity
  return 'low'
}

function normalizeStatus(value) {
  const status = String(value || '').toLowerCase()
  if (['new', 'open', 'triaged', 'processing', 'resolved', 'closed'].includes(status)) return status
  return 'open'
}

const STAGE_LABELS = {
  recon: '扫描侦察阶段',
  reconnaissance: '扫描侦察阶段',
  initial_access: '入侵突破阶段',
  execution: '命令执行阶段',
  persistence: '持久化阶段',
  privilege_escalation: '提权阶段',
  credential_access: '凭证访问阶段',
  lateral_movement: '横向移动阶段',
  collection: '数据收集阶段',
  c2_exfiltration: '回连外传阶段',
  impact: '影响破坏阶段',
  detection: '风险确认阶段',
}

const STAGE_TACTICS = {
  recon: 'TA0043 Reconnaissance',
  reconnaissance: 'TA0043 Reconnaissance',
  initial_access: 'TA0001 Initial Access',
  execution: 'TA0002 Execution',
  persistence: 'TA0003 Persistence',
  privilege_escalation: 'TA0004 Privilege Escalation',
  credential_access: 'TA0006 Credential Access',
  lateral_movement: 'TA0008 Lateral Movement',
  collection: 'TA0009 Collection',
  c2_exfiltration: 'TA0011 Command and Control / Exfiltration',
  impact: 'TA0040 Impact',
  detection: 'XDR Detection',
}

function stageKey(value = '') {
  return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_')
}

function normalizeStage(stage = {}, index = 0) {
  if (typeof stage === 'string') stage = { stage }
  const key = stageKey(firstNonEmpty(stage.stage, stage.stage_id, stage.name, stage.phase, stage.tactic))
  const fallbackKey = index === 0 ? 'recon' : index === 1 ? 'initial_access' : 'detection'
  const resolvedKey = STAGE_LABELS[key] ? key : fallbackKey
  return {
    id: firstNonEmpty(stage.id, stage.stage_id, stage.stage, stage.name, `stage-${index + 1}`),
    stageKey: resolvedKey,
    name: firstNonEmpty(stage.stage_label, stage.label, STAGE_LABELS[resolvedKey], stage.summary, `攻击阶段 ${index + 1}`),
    tactic: firstNonEmpty(stage.tactic, stage.mitre_tactic, STAGE_TACTICS[resolvedKey]),
    shortCode: firstNonEmpty(stage.short_code, stage.code, STAGE_TACTICS[resolvedKey]?.split(' ')[0], 'XDR'),
    sourceModule: firstNonEmpty(stage.source_module, stage.sourceModule, stage.module, stage.source, 'xdr'),
    timestamp: firstNonEmpty(stage.timestamp, stage.time, stage.created_at, stage.occurred_at),
    summary: firstNonEmpty(stage.summary, stage.description, stage.message, stage.rule_name),
  }
}

function normalizeEvidence(item = {}, index = 0) {
  return {
    id: firstNonEmpty(item.id, item.event_id, item.raw_reference, `evidence-${index + 1}`),
    sourceModule: firstNonEmpty(item.source_module, item.sourceModule, item.module, item.source, 'xdr'),
    title: firstNonEmpty(item.title, item.rule_name, item.raw_event?.rule_name, item.event_type, item.type, item.message, `Evidence ${index + 1}`),
    summary: firstNonEmpty(item.summary, item.message, item.raw_event?.summary, item.raw_event?.message, item.title, item.rule_name, item.event_type, item.type),
    time: firstNonEmpty(item.time, item.date, item.timestamp, item.created_at, item.occurred_at),
    stage: stageKey(firstNonEmpty(item.stage, item.stage_hint, item.phase, item.tactic)),
    rawReference: firstNonEmpty(item.raw_reference, item.rawReference, item.raw_ref, item.evidence_ref),
    entityId: firstNonEmpty(item.entity_id, item.entityId, item.asset_id, item.agent_id, item.host_id, item.process_id),
    sourceIP: firstNonEmpty(item.src_ip, item.source_ip, item.entities?.source_ip, item.client_ip),
    targetIP: firstNonEmpty(item.dst_ip, item.target_ip, item.entities?.target_ip, item.server_ip),
    detectionSurface: firstNonEmpty(item.detection_surface, item.source_engine, item.engine, item.source_module, item.module, item.source, 'xdr'),
    raw: item.raw_event || item.raw || item.payload || item,
  }
}

function normalizeStageGroup(group = {}, index = 0) {
  const rawStage = firstNonEmpty(group.stage, group.stage_id, group.name, group.phase, group.tactic)
  const key = stageKey(rawStage)
  const fallbackKey = index === 0 ? 'recon' : index === 1 ? 'initial_access' : 'detection'
  const resolvedKey = STAGE_LABELS[key] ? key : fallbackKey
  const evidence = Array.isArray(group.evidence) ? group.evidence : []
  return {
    id: firstNonEmpty(group.id, rawStage, `stage-group-${index + 1}`),
    stage: resolvedKey,
    name: firstNonEmpty(group.stage_label, group.label, STAGE_LABELS[resolvedKey], rawStage, `攻击阶段 ${index + 1}`),
    tactic: firstNonEmpty(group.tactic, group.mitre_tactic, STAGE_TACTICS[resolvedKey]),
    shortCode: firstNonEmpty(group.short_code, group.code, STAGE_TACTICS[resolvedKey]?.split(' ')[0], 'XDR'),
    evidence: evidence.map(normalizeEvidence),
  }
}

export function normalizeIncident(raw = {}) {
  const attackChain = Array.isArray(raw.attack_chain) ? raw.attack_chain : []
  const stages = Array.isArray(raw.stages) ? raw.stages : attackChain
  const evidence = Array.isArray(raw.evidence) ? raw.evidence : Array.isArray(raw.events) ? raw.events : attackChain
  const stageGroups = Array.isArray(raw.stage_groups) ? raw.stage_groups : []
  const firstEvidence = evidence[0] || {}

  return {
    id: firstNonEmpty(raw.id, raw.incident_id, raw.chain_id),
    title: firstNonEmpty(raw.title, raw.name, raw.rule_name, raw.attack_type, '关联安全事件'),
    severity: normalizeSeverity(raw.severity || raw.risk_level),
    status: normalizeStatus(raw.status),
    affectedAsset: firstNonEmpty(raw.affected_asset, raw.affectedAsset, raw.asset, raw.hostname, raw.host, raw.entity_id, raw.asset_id, raw.agent_id, raw.host_id, firstEvidence.entity_id, firstEvidence.asset_id, firstEvidence.agent_id, firstEvidence.host_id),
    entityId: firstNonEmpty(raw.entity_id, raw.entityId, raw.asset_id, raw.agent_id, raw.host_id, raw.chain_id, raw.source_chain_id, firstEvidence.entity_id, firstEvidence.asset_id),
    recommendedAction: firstNonEmpty(raw.recommended_action, raw.recommendedAction, raw.action, raw.remediation),
    createdAt: firstNonEmpty(raw.created_at, raw.createdAt, raw.timestamp, raw.first_seen),
    updatedAt: firstNonEmpty(raw.updated_at, raw.updatedAt, raw.last_seen),
    sourceIPs: Array.isArray(raw.source_ips) ? raw.source_ips : Array.isArray(raw.sourceIPs) ? raw.sourceIPs : [firstNonEmpty(raw.src_ip, raw.source_ip)].filter(Boolean),
    victimIPs: Array.isArray(raw.victim_ips) ? raw.victim_ips : Array.isArray(raw.victimIPs) ? raw.victimIPs : [firstNonEmpty(raw.dst_ip, raw.target_ip)].filter(Boolean),
    stages: stages.map(normalizeStage),
    evidence: evidence.map(normalizeEvidence),
    stageGroups: stageGroups.map(normalizeStageGroup).filter((group) => group.evidence.length),
  }
}

export function normalizeIncidents(items = []) {
  return items.map(normalizeIncident).filter((incident) => incident.id)
}

export function summarizeIncidents(items = []) {
  return {
    critical: items.filter((item) => item.severity === 'critical').length,
    high: items.filter((item) => item.severity === 'high').length,
    open: items.filter((item) => ['new', 'open', 'triaged', 'processing'].includes(item.status)).length,
  }
}
