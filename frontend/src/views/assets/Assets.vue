<template>
  <div class="page-shell assets-page">
    <section class="assets-hero">
      <div>
        <span class="page-kicker">Exposure Surface</span>
        <h1 class="page-title">资产暴露面</h1>
        <p class="page-subtitle">从在线率、Agent 覆盖和攻击命中视角呈现业务资产风险，而不是单纯主机清单。</p>
      </div>
      <el-input
        v-model="searchQuery"
        placeholder="搜索主机或 IP..."
        clearable
        style="max-width: 320px"
      />
    </section>

    <section class="signal-grid asset-signals">
      <article class="signal-card">
        <div class="signal-label">资产总数</div>
        <div class="signal-value">{{ stats.total }}</div>
        <p class="signal-note">纳入安全可见性的主机数量</p>
      </article>
      <article class="signal-card low">
        <div class="signal-label">在线资产</div>
        <div class="signal-value">{{ stats.online }}</div>
        <p class="signal-note">当前可采集和响应的节点</p>
      </article>
      <article class="signal-card critical">
        <div class="signal-label">离线缺口</div>
        <div class="signal-value">{{ stats.offline }}</div>
        <p class="signal-note">需要恢复 Agent 或网络连通</p>
      </article>
      <article class="signal-card info">
        <div class="signal-label">覆盖率</div>
        <div class="signal-value">{{ coverageRate }}%</div>
        <p class="signal-note">在线 / 总资产</p>
      </article>
    </section>

    <section class="surface-card assets-workbench">
      <div class="card-header">
        <div>
          <h2 class="card-title">资产处置清单</h2>
          <p class="card-caption">优先排查离线、未知和被攻击命中的资产</p>
        </div>
        <div class="filter-tabs">
          <button
            v-for="tab in filterTabs"
            :key="tab.key"
            type="button"
            :class="{ active: activeFilter === tab.key }"
            @click="activeFilter = tab.key"
          >
            {{ tab.label }}
            <span>{{ tab.count }}</span>
          </button>
        </div>
      </div>

      <div class="asset-table">
        <div class="table-header">
          <span>资产</span>
          <span>IP</span>
          <span>系统</span>
          <span>能力覆盖</span>
          <span>资源占用</span>
          <span>状态</span>
          <span>操作</span>
        </div>
        <div
          v-if="loading"
          class="table-state"
        >加载资产数据中...</div>
        <div
          v-else-if="error"
          class="table-state error"
        >
          <span>{{ error }}</span>
          <el-button size="small" type="primary" @click="loadAssets">重试</el-button>
        </div>
        <div
          v-else-if="filteredHosts.length === 0"
          class="table-state"
        >
          <strong>暂无资产数据</strong>
          <span>当前筛选条件下没有主机；未知能力会在资产上报后显式展示。</span>
        </div>
        <div
          v-for="host in filteredHosts"
          :key="host.id || host.ip"
          class="asset-row"
        >
          <span class="asset-name">
            <span class="status-dot" :class="host.status" />
            <strong>{{ host.hostname || host.name || '未知资产' }}</strong>
          </span>
          <span class="mono">{{ host.ip || '-' }}</span>
          <span>{{ host.os || '-' }}</span>
          <span class="capability-strip">
            <span
              v-for="capability in capabilityBadges(host)"
              :key="capability.key"
              class="capability-pill"
              :class="capability.state"
            >{{ capability.label }}: {{ capability.text }}</span>
          </span>
          <span class="ops-metrics">
            <small>CPU {{ formatMetric(host.cpu_usage_percent) }}</small>
            <small>MEM {{ formatMetric(host.memory_usage_percent) }}</small>
            <small>DISK {{ formatMetric(host.disk_usage_percent) }}</small>
            <small>Fresh {{ host.metrics_freshness || 'unknown' }}</small>
          </span>
          <span class="status-badge" :class="host.status === 'online' ? 'online' : 'offline'">
            {{ host.status === 'online' ? '在线可响应' : '离线缺口' }}
          </span>
          <span class="asset-actions">
            <el-button
              link
              type="primary"
              size="small"
              @click="showHostDetail(host)"
            >查看</el-button>
          </span>
        </div>
      </div>
    </section>

    <el-drawer v-model="detailVisible" size="520px" :with-header="false" class="asset-detail-drawer">
      <section v-if="selectedHost" class="host-detail-panel">
        <div class="detail-head">
          <span class="page-kicker">Host Detail</span>
          <h2>{{ selectedHost.hostname }}</h2>
          <p>{{ selectedHost.ip }} · {{ selectedHost.os }}</p>
        </div>
        <div class="detail-status-line">
          <span class="status-badge" :class="selectedHost.status === 'online' ? 'online' : 'offline'">
            {{ selectedHost.status === 'online' ? '在线可响应' : '离线缺口' }}
          </span>
          <span class="risk-chip" :class="selectedHost.risk_level">{{ selectedHost.risk_level || 'unknown' }}</span>
          <span class="risk-chip muted">{{ selectedHost.metrics_freshness || 'unknown' }}</span>
        </div>
        <div class="detail-section">
          <h3>能力覆盖</h3>
          <div class="capability-grid">
            <span
              v-for="capability in capabilityBadges(selectedHost)"
              :key="capability.key"
              class="capability-pill"
              :class="capability.state"
            >{{ capability.label }}: {{ capability.text }}</span>
          </div>
        </div>
        <div class="detail-section">
          <h3>拓扑与性能</h3>
          <dl class="detail-kv">
            <div><dt>Topology ID</dt><dd>{{ selectedHost.topology_id || 'unknown' }}</dd></div>
            <div><dt>Interfaces</dt><dd>{{ selectedHost.interfaces?.length ?? 0 }}</dd></div>
            <div><dt>Listening ports</dt><dd>{{ selectedHost.listening_ports?.length ?? 0 }}</dd></div>
            <div><dt>Processes</dt><dd>{{ selectedHost.process_count ?? 0 }}</dd></div>
          </dl>
        </div>
        <div class="detail-section">
          <h3>处置线索</h3>
          <dl class="detail-kv">
            <div><dt>Alerts</dt><dd>{{ selectedHost.alert_count }}</dd></div>
            <div><dt>Vulns</dt><dd>{{ selectedHost.vuln_count }}</dd></div>
            <div><dt>RASP blocked</dt><dd>{{ selectedHost.rasp_blocked }}</dd></div>
          </dl>
        </div>
      </section>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import api, { createRequestController, isRequestCanceled } from '../../api'
import { normalizeList } from '../../api/adapters'

const searchQuery = ref('')
const activeFilter = ref('all')
const selectedHost = ref(null)
const activeHostTab = ref('overview')
const detailVisible = ref(false)

const stats = ref({
  total: 0,
  online: 0,
  offline: 0,
  by_risk_level: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  with_vulnerabilities: 0,
  total_alerts: 0,
  with_rasp: 0,
})
const filterTabs = ref([
  { key: 'all', label: '全部', count: 0 },
  { key: 'online', label: '在线', count: 0 },
  { key: 'offline', label: '离线', count: 0 }
])
const hosts = ref([])
const loading = ref(false)
const error = ref('')

const firstDefined = (source, ...keys) => {
  for (const key of keys) {
    const value = source?.[key]
    if (value !== undefined && value !== null) return value
  }
  return undefined
}

const toSafeNumber = (value) => {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const normalized = Number(value)
  return Number.isFinite(normalized) ? normalized : 0
}

const normalizeRiskLevel = (value) => {
  const token = String(value || '').toLowerCase()
  if (['critical', 'high', 'medium', 'low'].includes(token)) return token
  return 'unknown'
}

const normalizeStatus = (host = {}) => {
  const rawStatus = String(firstDefined(host, 'status', 'agent_status') || '').toLowerCase()
  if (rawStatus === 'online' || rawStatus === 'up' || rawStatus === 'active') return 'online'
  if (rawStatus === 'offline' || rawStatus === 'down' || rawStatus === 'inactive') return 'offline'
  const onlineFlag = firstDefined(host, 'online', 'is_online', 'isOnline')
  return onlineFlag ? 'online' : 'offline'
}

const normalizeRiskStats = (riskSource = {}) => ({
  critical: toSafeNumber(firstDefined(riskSource, 'critical', 'Critical')),
  high: toSafeNumber(firstDefined(riskSource, 'high', 'High')),
  medium: toSafeNumber(firstDefined(riskSource, 'medium', 'Medium')),
  low: toSafeNumber(firstDefined(riskSource, 'low', 'Low')),
  unknown: toSafeNumber(firstDefined(riskSource, 'unknown', 'Unknown')),
})

const normalizeHost = (host = {}, index = 0) => {
  const status = normalizeStatus(host)
  const capabilities = firstDefined(host, 'capabilities', 'capability_model', 'capabilityModel') || {}
  return {
    ...host,
    id: firstDefined(host, 'id', 'asset_id', 'assetId', 'uuid') || `asset-${index}`,
    hostname: firstDefined(host, 'hostname', 'host_name', 'name') || '未知资产',
    ip: firstDefined(host, 'ip', 'ip_addr', 'address') || '-',
    os: firstDefined(host, 'os', 'os_name', 'platform', 'system') || '-',
    status,
    risk_level: normalizeRiskLevel(firstDefined(host, 'risk_level', 'riskLevel', 'risk', 'threat_level')),
    last_heartbeat: firstDefined(host, 'last_heartbeat', 'lastHeartbeat', 'heartbeat_at', 'updated_at') || '',
    alert_count: toSafeNumber(firstDefined(host, 'alert_count', 'alertCount', 'alerts', 'total_alerts')),
    vuln_count: toSafeNumber(firstDefined(host, 'vuln_count', 'vulnCount', 'vulnerability_count', 'with_vulnerabilities')),
    rasp_blocked: toSafeNumber(firstDefined(host, 'rasp_blocked', 'raspBlocked', 'blocked_by_rasp')),
    cpu_usage_percent: firstDefined(host, 'cpu_usage_percent', 'cpuUsagePercent', 'cpu_percent'),
    memory_usage_percent: firstDefined(host, 'memory_usage_percent', 'memoryUsagePercent', 'memory_percent'),
    disk_usage_percent: firstDefined(host, 'disk_usage_percent', 'diskUsagePercent', 'disk_percent'),
    memory_mb: firstDefined(host, 'memory_mb', 'memoryTotalMb'),
    disk_gb: firstDefined(host, 'disk_gb', 'diskTotalGb'),
    capabilities,
    interfaces: firstDefined(host, 'interfaces') || [],
    listening_ports: firstDefined(host, 'listening_ports', 'listeningPorts') || [],
    process_count: toSafeNumber(firstDefined(host, 'process_count', 'processCount')),
    topology_id: firstDefined(host, 'topology_id', 'topologyId') || '',
    metrics_freshness: firstDefined(host, 'metrics_freshness', 'metricsFreshness') || 'unknown',
  }
}

const capabilityState = (value) => {
  if (value === true || value === 'active' || value === 'enabled' || value === 'online') return { state: 'active', text: 'active' }
  if (value === false || value === 'disabled' || value === 'offline') return { state: 'disabled', text: 'off' }
  if (value === 'fallback' || value === 'unsupported_fallback') return { state: 'fallback', text: value }
  if (value) return { state: 'active', text: String(value) }
  return { state: 'unknown', text: 'unknown' }
}

const capabilityBadges = (host = {}) => {
  const caps = host.capabilities || {}
  const traffic = caps.traffic_collector || caps.traffic || {}
  const runtime = caps.runtime_sensor || caps.runtime || {}
  const rasp = caps.rasp_probe_manager || caps.rasp || {}
  return [
    { key: 'capture', label: 'Capture', ...capabilityState(firstDefined(traffic, 'backend_status', 'status', 'active_engine')) },
    { key: 'runtime', label: 'Runtime', ...capabilityState(firstDefined(runtime, 'status', 'backend_status', 'enabled')) },
    { key: 'rasp', label: 'RASP', ...capabilityState(firstDefined(rasp, 'status', 'active_backend', 'enabled')) },
  ]
}

const formatMetric = (value) => {
  if (value === undefined || value === null || value === '') return '未知'
  const numeric = Number(value)
  return Number.isFinite(numeric) ? `${Math.round(numeric)}%` : '未知'
}

const hostPriorityScore = (host = {}) => {
  const offlineScore = host.status === 'offline' ? 1 : 0
  const riskScore = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }[host.risk_level] || 0
  const alertScore = toSafeNumber(host.alert_count)
  return { offlineScore, riskScore, alertScore }
}

const compareByDisposalPriority = (a, b) => {
  const aScore = hostPriorityScore(a)
  const bScore = hostPriorityScore(b)

  if (bScore.offlineScore !== aScore.offlineScore) return bScore.offlineScore - aScore.offlineScore
  if (bScore.riskScore !== aScore.riskScore) return bScore.riskScore - aScore.riskScore
  if (bScore.alertScore !== aScore.alertScore) return bScore.alertScore - aScore.alertScore

  const aName = `${a.hostname}:${a.ip}:${a.id}`
  const bName = `${b.hostname}:${b.ip}:${b.id}`
  return aName.localeCompare(bName)
}

const filteredHosts = computed(() => {
  let result = hosts.value.slice()
  if (activeFilter.value !== 'all') {
    result = result.filter(h => h.status === activeFilter.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(h => h.hostname?.toLowerCase().includes(q) || h.ip?.includes(q))
  }
  return result.sort(compareByDisposalPriority)
})

const coverageRate = computed(() => stats.value.total ? Math.round((stats.value.online / stats.value.total) * 100) : 0)

let requestController = null
let detailRequestController = null

const updateFilterTabs = () => {
  filterTabs.value = [
    { key: 'all', label: '全部', count: stats.value.total },
    { key: 'online', label: '在线', count: stats.value.online },
    { key: 'offline', label: '离线', count: stats.value.offline },
  ]
}

const loadStats = async (signal) => {
  const data = await api.get('/assets/stats', { signal })
  const rawRiskLevel = firstDefined(data, 'by_risk_level', 'byRiskLevel', 'risk_level_distribution') || {}

  stats.value = {
    total: toSafeNumber(firstDefined(data, 'total', 'Total')),
    online: toSafeNumber(firstDefined(data, 'online', 'Online')),
    offline: toSafeNumber(firstDefined(data, 'offline', 'Offline')),
    by_risk_level: normalizeRiskStats(rawRiskLevel),
    with_vulnerabilities: toSafeNumber(firstDefined(data, 'with_vulnerabilities', 'withVulnerabilities', 'vulnerable_assets')),
    total_alerts: toSafeNumber(firstDefined(data, 'total_alerts', 'totalAlerts', 'alerts_total')),
    with_rasp: toSafeNumber(firstDefined(data, 'with_rasp', 'withRasp', 'rasp_covered')),
  }
  updateFilterTabs()
}

const loadHosts = async (signal) => {
  const payload = await api.get('/assets', { params: { limit: 100 }, signal })
  const list = normalizeList(payload, ['items', 'hosts', 'list']).items
  hosts.value = list.map((host, index) => normalizeHost(host, index)).sort(compareByDisposalPriority)
}

const showHostDetail = async (host) => {
  selectedHost.value = host
  activeHostTab.value = 'overview'
  detailVisible.value = true

  if (!host?.id) return
  if (detailRequestController) detailRequestController.abort()
  detailRequestController = createRequestController()

  try {
    const detailPayload = await api.get(`/assets/${encodeURIComponent(host.id)}`, { signal: detailRequestController.signal })
    const detailRecord = detailPayload?.asset || detailPayload?.item || detailPayload || {}
    const mergedHost = normalizeHost({ ...host, ...detailRecord })

    hosts.value = hosts.value.map((item) => item.id === mergedHost.id ? mergedHost : item)
    if (selectedHost.value?.id === mergedHost.id) {
      selectedHost.value = mergedHost
    }
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '资产详情加载失败'
    }
  }
}

const loadAssets = async () => {
  if (requestController) requestController.abort()
  requestController = createRequestController()
  const { signal } = requestController

  loading.value = true
  error.value = ''
  try {
    await Promise.all([loadStats(signal), loadHosts(signal)])
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '资产数据加载失败'
      hosts.value = []
    }
  } finally {
    loading.value = false
  }
}

onMounted(loadAssets)
onUnmounted(() => {
  if (requestController) requestController.abort()
  if (detailRequestController) detailRequestController.abort()
})
</script>

<style scoped>
.assets-page {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.assets-hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 20px;
}

.asset-signals .signal-card.low {
  border-top: 3px solid var(--risk-low);
}

.asset-signals .signal-card.critical {
  border-top: 3px solid var(--risk-critical);
}

.asset-signals .signal-card.info {
  border-top: 3px solid var(--risk-info);
}

.assets-workbench {
  overflow: hidden;
}

.filter-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.filter-tabs button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 34px;
  padding: 0 12px;
  border: 1px solid var(--border-color);
  border-radius: 999px;
  background: rgba(8, 18, 32, 0.58);
  color: var(--text-secondary);
  cursor: pointer;
}

.filter-tabs button.active {
  border-color: var(--border-glow);
  background: rgba(56, 189, 248, 0.14);
  color: var(--primary-light);
}

.asset-table {
  padding: 0 18px 18px;
}

.table-header,
.asset-row {
  display: grid;
  grid-template-columns: minmax(210px, 1.15fr) 140px 110px minmax(210px, 1fr) 170px 120px 80px;
  gap: 14px;
  align-items: center;
}

.table-state {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 10px;
  min-height: 150px;
  color: var(--text-muted);
  text-align: center;
}

.table-state.error {
  color: #fecaca;
}

.capability-strip,
.capability-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.capability-pill {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 0 8px;
  border: 1px solid rgba(148, 163, 184, 0.28);
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.72);
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 800;
}

.capability-pill.active {
  border-color: rgba(34, 197, 94, 0.45);
  color: #86efac;
}

.capability-pill.fallback {
  border-color: rgba(251, 191, 36, 0.5);
  color: #fde68a;
}

.capability-pill.disabled,
.capability-pill.unknown {
  border-color: rgba(148, 163, 184, 0.24);
  color: #94a3b8;
}

.ops-metrics {
  display: grid;
  gap: 2px;
  color: var(--text-secondary);
  font-family: var(--font-mono);
}

.ops-metrics small {
  font-size: 11px;
}

.table-header {
  padding: 12px 14px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 900;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.asset-row {
  margin-bottom: 10px;
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: 16px;
  background: rgba(8, 18, 32, 0.52);
  color: var(--text-secondary);
}

.asset-name {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 9px;
}

.asset-name strong {
  overflow: hidden;
  color: var(--text-primary);
  white-space: nowrap;
  text-overflow: ellipsis;
}

.asset-actions {
  display: flex;
  justify-content: flex-end;
}

.host-detail-panel {
  display: grid;
  gap: 18px;
  color: var(--text-primary);
}

.detail-head h2 {
  margin: 6px 0;
  font-size: 28px;
}

.detail-head p {
  margin: 0;
  color: var(--text-secondary);
}

.detail-status-line {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.detail-section {
  padding: 16px;
  border: 1px solid var(--border-light);
  border-radius: 18px;
  background: rgba(8, 18, 32, 0.68);
}

.detail-section h3 {
  margin: 0 0 12px;
  font-size: 13px;
  letter-spacing: .12em;
  text-transform: uppercase;
}

.detail-kv {
  display: grid;
  gap: 10px;
  margin: 0;
}

.detail-kv div {
  display: flex;
  justify-content: space-between;
  gap: 16px;
}

.detail-kv dt {
  color: var(--text-muted);
}

.detail-kv dd {
  margin: 0;
  color: var(--text-primary);
  font-family: var(--font-mono);
}

.risk-chip {
  padding: 5px 10px;
  border-radius: 999px;
  background: rgba(248, 113, 113, 0.14);
  color: #fecaca;
  font-size: 12px;
  font-weight: 800;
}

.risk-chip.muted {
  background: rgba(148, 163, 184, 0.12);
  color: var(--text-secondary);
}

@media (max-width: 980px) {
  .assets-hero {
    align-items: flex-start;
    flex-direction: column;
  }

  .table-header {
    display: none;
  }

  .asset-row {
    grid-template-columns: 1fr;
  }

  .asset-actions {
    justify-content: flex-start;
  }
}
</style>
