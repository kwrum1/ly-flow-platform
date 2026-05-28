function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === 0) return '0'
    if (value !== undefined && value !== null && String(value).trim() !== '') return String(value)
  }
  return ''
}

function riskLevel(value) {
  const token = String(value || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low'].includes(token)) return token
  return 'low'
}

function node(id, label, type, risk = 'low', raw = {}) {
  return { id, label, type, risk: riskLevel(risk), raw }
}

function edgeKey(source, target, relation) {
  return `${source}->${target}:${relation}`
}

export function buildTopology({ assets = [], flows = [], incidents = [] } = {}) {
  const nodes = new Map()
  const edges = new Map()

  assets.forEach((asset, index) => {
    const id = firstNonEmpty(asset.id, asset.asset_id, asset.agent_id, asset.hostname, `asset-${index}`)
    nodes.set(id, node(id, firstNonEmpty(asset.hostname, asset.name, id), 'asset', asset.risk_level, asset))
  })

  flows.forEach((flow, index) => {
    const source = firstNonEmpty(flow.asset_id, flow.agent_id, flow.src_asset, flow.src_ip, `flow-source-${index}`)
    const target = firstNonEmpty(flow.domain, flow.dst_domain, flow.dst_ip, flow.remote_addr, `flow-target-${index}`)
    if (!nodes.has(source)) nodes.set(source, node(source, source, 'asset', flow.risk_level, flow))
    if (!nodes.has(target)) nodes.set(target, node(target, target, target.includes('.') ? 'domain' : 'remote', flow.risk_level, flow))
    const key = edgeKey(source, target, 'semantic_flow')
    const current = edges.get(key) || { id: key, source, target, relation: 'semantic_flow', count: 0, risk: 'low' }
    current.count += Number(flow.count || flow.flow_count || 1)
    if (riskScore(flow.risk_level) > riskScore(current.risk)) current.risk = riskLevel(flow.risk_level)
    edges.set(key, current)
  })

  incidents.forEach((incident) => {
    const assetId = firstNonEmpty(incident.affected_asset, incident.affectedAsset, incident.entity_id, incident.asset_id)
    const incidentId = firstNonEmpty(incident.id, incident.incident_id, incident.chain_id)
    if (!assetId || !incidentId) return
    nodes.set(incidentId, node(incidentId, firstNonEmpty(incident.title, incidentId), 'incident', incident.severity, incident))
    if (!nodes.has(assetId)) nodes.set(assetId, node(assetId, assetId, 'asset', incident.severity, incident))
    const key = edgeKey(assetId, incidentId, 'incident')
    edges.set(key, { id: key, source: assetId, target: incidentId, relation: 'incident', count: 1, risk: riskLevel(incident.severity) })
  })

  return { nodes: Array.from(nodes.values()), edges: Array.from(edges.values()) }
}

export function riskScore(risk) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[riskLevel(risk)] || 1
}
