import api from './index'

export const authClient = Object.freeze({
  login: (payload) => api.post('/auth/login', payload),
  logout: () => api.post('/auth/logout'),
  profile: () => api.get('/auth/profile'),
  changePassword: (payload) => api.post('/auth/change-password', payload),
  createUser: (payload) => api.post('/auth/register', payload),
  users: (params = {}) => api.get('/auth/users', { params }),
  updateUser: (id, payload) => api.put(`/auth/users/${encodeURIComponent(id)}`, payload),
  deleteUser: (id) => api.delete(`/auth/users/${encodeURIComponent(id)}`),
  resetPassword: (payload) => api.put('/auth/users/password', payload),
})

export const attackWorkbenchClient = Object.freeze({
  stats: () => api.get('/unified/stats'),
  events: (params = {}) => api.get('/unified/events', { params }),
  searchEvents: (payload) => api.post('/unified/events/search', payload),
  incidents: (params = {}) => api.get('/incidents', { params }),
  incident: (id) => api.get(`/incidents/${encodeURIComponent(id)}`),
  timeline: (params = {}) => api.get('/timeline', { params }),
  timelineItem: (id) => api.get(`/timeline/${encodeURIComponent(id)}`),
  xdrChains: (params = {}) => api.get('/xdr/chains', { params }),
  xdrPosture: () => api.get('/xdr/posture'),
})

export const assetAgentClient = Object.freeze({
  assetStats: () => api.get('/assets/stats'),
  assets: (params = {}) => api.get('/assets', { params }),
  asset: (id) => api.get(`/assets/${encodeURIComponent(id)}`),
  assetGroups: () => api.get('/assets/groups'),
  agents: (params = {}) => api.get('/agents', { params }),
  agent: (id) => api.get(`/agents/${encodeURIComponent(id)}`),
  toggleAgentCapability: (id, field, enabled) => api.put(`/agent/capabilities/${encodeURIComponent(id)}`, { field, enabled }),
  renameAgent: (id, displayName) => api.put(`/agent/name/${encodeURIComponent(id)}`, { display_name: displayName }),
  agentTags: (id) => api.get(`/agent/tags/${encodeURIComponent(id)}`),
  setAgentTags: (id, tags) => api.put(`/agent/tags/${encodeURIComponent(id)}`, { tags }),
  deleteAgent: (id) => api.delete(`/agents/${encodeURIComponent(id)}`),
  agentNames: () => api.get('/agent/names'),
  engineHealth: () => api.get('/engine-health'),
  setAgentName: (id, name) => api.put('/agent/names', { agent_id: id, display_name: name }),
  installScript: () => api.get('/agent/install.sh'),
  uninstallScript: () => api.get('/agent/uninstall.sh'),
  downloadAgent: (params = {}) => api.get('/agent/download', { params }),
})

export const trafficClient = Object.freeze({
  flows: (params = {}) => api.get('/traffic/flows', { params }),
  sessions: (params = {}) => api.get('/traffic/sessions', { params }),
  threats: (params = {}) => api.get('/traffic/threats', { params }),
  mirrorInterface: () => api.get('/traffic/mirror-interface'),
  updateMirrorInterface: (payload) => api.put('/traffic/mirror-interface', payload),
  threatCategory: (category, params = {}) => api.get(`/threats/${encodeURIComponent(category)}`, { params }),
  componentAlerts: (category, params = {}) => api.get(`/component-alerts/${encodeURIComponent(category)}`, { params }),
})

export const ruleClient = Object.freeze({
  list: (params = {}) => api.get('/rules', { params }),
  inventory: (params = {}) => api.get('/rules/inventory', { params }),
  reports: () => api.get('/rules/reports'),
  quarantine: () => api.get('/rules/quarantine'),
  scoreWeights: () => api.get('/rules/score-weights'),
  updateScoreWeights: (payload) => api.put('/rules/score-weights', payload),
  updateRuleItem: (id, payload) => api.put(`/rules/items/${encodeURIComponent(id)}`, payload),
  sources: () => api.get('/rules/sources'),
  saveSource: (id, payload) => api.put(`/rules/sources/${encodeURIComponent(id)}`, payload),
  updateSource: (id) => api.post(`/rules/sources/${encodeURIComponent(id)}/update`, undefined, { timeout: 120000 }),
  platformSources: () => api.get('/rule-platform/sources'),
  platformSync: (payload) => api.post('/rule-platform/sync', payload),
  platformSyncStatus: () => api.get('/rule-platform/sync'),
  platformVersions: (params = {}) => api.get('/rule-platform/versions', { params }),
  platformCompilePreview: (payload = {}) => api.post('/rule-platform/compile-preview', payload),
  platformActiveBundle: () => api.get('/rule-platform/active-bundle'),
  platformActivateBundle: () => api.post('/rule-platform/active-bundle'),
  /** @returns {Promise<import('../domain/contracts/api-contracts').NativeEngineRulesResponse>} */
  engineRules: (params = {}) => api.get('/engine-rules', { params }),
  engineRuntimeStatus: () => api.get('/engine-runtime/status'),
  trafficRuleProfile: () => api.get('/traffic/rule-profile'),
  exportTrafficRuleProfile: (payload = {}) => api.post('/traffic/rule-profile/export', payload),
  updateEngineRules: () => api.post('/engine-rules/update'),
  platformRollback: (payload = {}) => api.post('/rule-platform/rollback', payload),
  responseActions: (params = {}) => api.get('/response/actions', { params }),
  createResponseAction: (payload) => api.post('/response/actions', payload),
  approveResponseAction: (id, payload = {}) => api.post(`/response/actions/${id}/approve`, payload),
  rollbackResponseAction: (id) => api.post(`/response/actions/${id}/rollback`, {}),
  categories: () => api.get('/rules/categories'),
  stats: () => api.get('/rules/stats'),
  subscription: () => api.get('/rules/subscription'),
  update: (payload) => api.post('/rules/update', payload),
  test: (payload) => api.post('/rules/test', payload),
})

export const responseClient = Object.freeze({
  actions: (params = {}) => api.get('/response/actions', { params }),
  create: (payload) => api.post('/response/actions', payload),
  approve: (id, payload = {}) => api.post(`/response/actions/${encodeURIComponent(id)}/approve`, payload),
  rollback: (id) => api.post(`/response/actions/${encodeURIComponent(id)}/rollback`, {}),
  automation: () => api.get('/response/automation'),
  updateAutomation: (payload) => api.put('/response/automation', payload),
  policy: () => api.get('/response/policy'),
  updatePolicy: (payload) => api.put('/response/policy', payload),
  suppress: (payload) => api.post('/response/policy', payload),
})

export const evidenceClient = Object.freeze({
  bundles: (params = {}) => api.get('/evidence/bundles', { params }),
  bundle: (id) => api.get(`/evidence/bundles/${encodeURIComponent(id)}`),
  download: (id) => api.get(`/evidence/bundles/${encodeURIComponent(id)}/download`, { responseType: 'blob' }),
  createBundle: (payload) => api.post('/evidence/bundles', payload),
  uploadArtifact: (payload, headers = {}) => api.post('/evidence/artifacts', payload, { headers }),
})

export const signalClient = Object.freeze({
  xdrStats: () => api.get('/xdr/stats'),
  xdrEvents: (params = {}) => api.get('/xdr/events', { params }),
  xdrSources: () => api.get('/xdr/sources'),
  xdrTopEvents: () => api.get('/xdr/top-events'),
  xdrChains: (params = {}) => api.get('/xdr/chains', { params }),
  xdrPosture: () => api.get('/xdr/posture'),
  raspStats: () => api.get('/rasp/stats'),
  raspEvents: (params = {}) => api.get('/rasp/events', { params }),
  raspRules: () => api.get('/rasp/rules'),
  raspAgents: () => api.get('/rasp/agents'),
  raspProtectionStatus: (params = {}) => api.get('/rasp/protection/status', { params }),
  traceStats: () => api.get('/trace/stats'),
  traceSessions: (params = {}) => api.get('/trace/sessions', { params }),
  traceSession: (id) => api.get(`/trace/sessions/${encodeURIComponent(id)}`),
  traceEvents: (params = {}) => api.get('/trace/events', { params }),
  traceSearch: (params = {}) => api.get('/trace/search', { params }),
})

export const raspPolicyClient = Object.freeze({
  status: () => api.get('/rasp/policy'),
  startCanary: (payload) => api.post('/rasp/policy/canary', payload),
  complete: (version, payload) => api.post(`/rasp/policy/actions/${version}/complete`, payload),
  promote: (version) => api.post(`/rasp/policy/actions/${version}/promote`, {}),
  rollback: (version) => api.post(`/rasp/policy/actions/${version}/rollback`, {}),
  emergencyStop: () => api.post('/rasp/policy/actions/emergency-stop', {}),
})

export const yaraClient = Object.freeze({
  status: () => api.get('/rule-platform/yara'),
  import: (formData) => api.post('/rule-platform/yara/import', formData, { headers: { 'Content-Type': 'multipart/form-data' } }),
  clear: () => api.delete('/rule-platform/yara'),
})

export const overviewClient = Object.freeze({
  health: () => api.get('/health'),
  stats: () => api.get('/stats'),
  threats: (params = {}) => api.get('/unified/events', { params }),
  globalSituation: () => api.get('/public/situation/global'),
  targetLocation: () => api.get('/situation/target-location'),
  updateTargetLocation: (payload) => api.put('/situation/target-location', payload),
  systemTime: () => api.get('/system/time'),
  updateSystemTime: (payload) => api.put('/system/time', payload),
})

/**
 * Platform truth surface: component health, ingestion stats and the
 * time source. These feed the shell status bar and the data-quality page,
 * and must never be silently defaulted to a "healthy" value.
 */
/**
 * Raw GET for endpoints whose envelope has no `data` field. The shared
 * axios interceptor intentionally unwraps `{code,data}` envelopes and
 * returns `{}` for `{code,status,components}`, so component health must be
 * read directly or the console would silently show a wrong state.
 */
async function rawGet(path) {
  const token = typeof localStorage !== 'undefined' ? localStorage.getItem('token') : ''
  const response = await fetch(`/api/v1${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

export const opsClient = Object.freeze({
  components: () => rawGet('/debug/components'),
  stats: () => api.get('/stats'),
  unifiedStats: () => api.get('/unified/stats'),
  xdrStats: () => api.get('/xdr/stats'),
  systemTime: () => api.get('/system/time'),
  agents: (params = {}) => api.get('/agents', { params }),
  assets: (params = {}) => api.get('/assets', { params }),
  engineHealth: () => api.get('/engine-health'),
  eventSample: (params = {}) => api.get('/unified/events', { params }),
})
