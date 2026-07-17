<template>
  <div class="page-shell command-dashboard">
    <section class="hero-panel">
      <div class="hero-copy">
        <span class="page-kicker">Executive Risk</span>
        <h1 class="page-title">安全信号驾驶舱</h1>
        <p class="page-subtitle">
          以业务影响、攻击链阶段和可处置优先级组织 DPI、Runtime、RASP、XDR 信号，先暴露需要立刻处理的风险。
        </p>
        <div class="polling-meta" :class="{ stale: dashboardPolling.stale }">
          <span>上次更新：{{ dashboardPolling.lastUpdatedText }}</span>
          <span class="polling-badge">{{ dashboardPolling.stale ? '数据陈旧' : '数据新鲜' }}</span>
        </div>
        <div class="hero-actions">
          <button
            type="button"
            class="action-button"
            @click="go('/events')"
          >进入攻击队列</button>
          <button
            type="button"
            class="ghost-button"
            @click="go('/control')"
          >检查防护覆盖</button>
        </div>
      </div>
      <div class="risk-orb" :class="riskTone">
        <span class="orb-label">Risk Score</span>
        <strong>{{ riskScore }}</strong>
        <span class="orb-state">{{ riskLabel }}</span>
      </div>
    </section>

    <div
      v-if="error"
      class="page-state error"
    >{{ error }}</div>

    <section class="signal-grid executive-grid">
      <article
        v-for="signal in executiveSignals"
        :key="signal.key"
        class="signal-card"
        :class="signal.tone"
      >
        <div class="signal-label">{{ signal.label }}</div>
        <div class="signal-value">{{ signal.value }}</div>
        <p class="signal-note">{{ signal.note }}</p>
        <button
          type="button"
          class="signal-link"
          @click="go(signal.route)"
        >{{ signal.action }}</button>
      </article>
    </section>

    <section class="dashboard-matrix">
      <article class="surface-card priority-panel">
        <div class="card-header">
          <div>
            <h2 class="card-title">P1 攻击队列</h2>
            <p class="card-caption">按严重度、新发状态和业务资产影响排序</p>
          </div>
          <span class="risk-badge critical">{{ urgentIncidents.length }} 待处理</span>
        </div>
        <div class="card-body incident-list">
          <div
            v-if="loading"
            class="table-state"
          >加载安全事件中...</div>
          <div
            v-else-if="urgentIncidents.length === 0"
            class="table-state"
          >暂无 P1/P2 事件</div>
          <button
            v-for="incident in urgentIncidents"
            :key="incident.id || `${incident.timestamp}-${incident.src_ip}`"
            type="button"
            class="incident-row"
            @click="openIncident(incident)"
          >
            <span class="incident-rank">{{ incident.priority }}</span>
            <span class="incident-main">
              <strong>{{ incident.title }}</strong>
              <span>{{ incident.src_ip || '未知源' }} → {{ incident.dst_ip || incident.domain || '业务资产' }}</span>
            </span>
            <span class="incident-meta">
              <span class="risk-badge" :class="incident.severity">{{ severityText(incident.severity) }}</span>
              <span>{{ formatTime(incident.timestamp) }}</span>
            </span>
          </button>
        </div>
      </article>

      <article class="surface-card chain-panel">
        <div class="card-header">
          <div>
            <h2 class="card-title">攻击链态势</h2>
            <p class="card-caption">从网络语义到主机与应用运行时证据</p>
          </div>
          <button
            type="button"
            class="ghost-button"
            @click="go('/xdr')"
          >查看关联</button>
        </div>
        <div class="card-body attack-chain">
          <div
            v-for="stage in attackStages"
            :key="stage.key"
            class="stage-node"
            :class="{ active: stage.count > 0 }"
          >
            <span class="stage-count">{{ stage.count }}</span>
            <span class="stage-name">{{ stage.name }}</span>
            <span class="stage-source">{{ stage.source }}</span>
          </div>
        </div>
      </article>

      <article class="surface-card exposure-panel">
        <div class="card-header">
          <div>
            <h2 class="card-title">受影响资产</h2>
            <p class="card-caption">按攻击命中与在线状态暴露业务受害面</p>
          </div>
          <button
            type="button"
            class="ghost-button"
            @click="go('/assets')"
          >资产视图</button>
        </div>
        <div class="card-body exposure-list">
          <div
            v-if="loading"
            class="table-state"
          >加载资产中...</div>
          <div
            v-else-if="topAssets.length === 0"
            class="table-state"
          >暂无受影响资产</div>
          <div
            v-for="asset in topAssets"
            :key="asset.id || asset.ip"
            class="asset-row"
          >
            <span class="status-dot" :class="asset.status" />
            <span class="asset-main">
              <strong>{{ asset.name }}</strong>
              <span>{{ asset.ip }}</span>
            </span>
            <span class="asset-impact">{{ asset.attack_count }} 命中</span>
          </div>
        </div>
      </article>

      <article class="surface-card action-panel">
        <div class="card-header">
          <div>
            <h2 class="card-title">处置路径</h2>
            <p class="card-caption">把安全信号转成运营动作</p>
          </div>
        </div>
        <div class="card-body response-steps">
          <button
            v-for="step in responseSteps"
            :key="step.route"
            type="button"
            class="response-step"
            @click="go(step.route)"
          >
            <span>{{ step.index }}</span>
            <strong>{{ step.title }}</strong>
            <em>{{ step.description }}</em>
          </button>
        </div>
      </article>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import api, { isRequestCanceled } from '../api'
import { normalizeList } from '../api/adapters'
import { aggregateLifecycleMetrics, aggregateStatusPipeline, formatDurationLabel } from '../domain/ops-metrics'
import { createPollingScheduler } from '../data/polling/scheduler'
import { createPollingFreshnessTracker } from '../data/polling/freshness'
import { formatChinaDateTime, formatChinaTime } from '../shared/time'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const stats = ref({ total_hosts: 0, online_hosts: 0, critical_events: 0, high_events: 0 })
const assets = ref([])
const events = ref([])
const protectionStatus = ref('disabled')

const dashboardPolling = ref({
  stale: false,
  lastUpdatedText: '-',
})
const dashboardFreshness = createPollingFreshnessTracker({ staleAfterMs: 90000, staleFailureThreshold: 2 })
const dashboardScheduler = createPollingScheduler()
let dashboardStaleTimer = null

const severityWeight = { critical: 4, high: 3, medium: 2, low: 1 }
const severityTextMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' }

const normalizeItems = (payload, keys = ['items', 'events', 'hosts', 'list']) => normalizeList(payload, keys).items
const countOf = (source, ...keys) => keys.reduce((value, key) => value ?? source?.[key], undefined) || 0

const formatPollingTime = (value) => {
  if (!value) return '-'
  const text = formatChinaTime(value)
  return text === '时间格式异常' ? '-' : text
}

const updateDashboardPolling = (snapshot = dashboardFreshness.getSnapshot()) => {
  dashboardPolling.value = {
    stale: snapshot.stale,
    lastUpdatedText: formatPollingTime(snapshot.lastUpdatedAt),
  }
}

const fetchStats = async (signal) => {
  const [assetPayload, statPayload] = await Promise.allSettled([
    api.get('/assets/stats', { signal }),
    api.get('/stats', { signal }),
  ])
  const assetData = assetPayload.status === 'fulfilled' ? (assetPayload.value || {}) : {}
  const statData = statPayload.status === 'fulfilled' ? (statPayload.value || {}) : {}
  stats.value = {
    total_hosts: countOf(assetData, 'total', 'Total'),
    online_hosts: countOf(assetData, 'online', 'Online'),
    critical_events: countOf(statData, 'critical_events', 'critical'),
    high_events: countOf(statData, 'high_events', 'high'),
  }
}

const fetchAssets = async (signal) => {
  const payload = await api.get('/assets', { params: { limit: 100 }, signal })
  const list = normalizeItems(payload, ['items', 'hosts', 'list'])
  assets.value = list.map((asset, index) => ({
    ...asset,
    id: asset.id || asset.uuid || index,
    name: asset.hostname || asset.name || asset.host_name || '未知资产',
    ip: asset.ip || asset.ip_addr || asset.address || '-',
    status: asset.status || (asset.online ? 'online' : 'offline'),
    attack_count: Number(asset.attack_count || asset.alert_count || asset.risk_count || 0)
  }))
}

const fetchEvents = async (signal) => {
  const payload = await api.get('/events', { params: { limit: 200 }, signal })
  const list = normalizeItems(payload, ['items', 'events', 'list'])
  events.value = list.map((event, index) => ({
    ...event,
    id: event.id || event.uuid || index,
    severity: event.severity || event.level || 'medium',
    status: event.status || 'new',
    title: event.event_type || event.type || event.rule_name || event.message || '安全事件',
    priority: `P${Math.max(1, 5 - (severityWeight[event.severity || event.level] || 2))}`
  }))
}

const fetchProtection = async (signal) => {
  try {
    const statusData = await api.get('/rasp/protection/status', { signal })
    const agent = Array.isArray(statusData) ? statusData[0] : statusData
    protectionStatus.value = agent?.enabled ? 'enabled' : 'disabled'
  } catch (err) {
    if (!isRequestCanceled(err)) {
      protectionStatus.value = 'disabled'
    }
  }
}

const fetchAll = async ({ signal } = {}) => {
  loading.value = true
  error.value = ''
  const result = await Promise.allSettled([
    fetchStats(signal),
    fetchAssets(signal),
    fetchEvents(signal),
    fetchProtection(signal),
  ])
  const failed = result.find(item => item.status === 'rejected' && !isRequestCanceled(item.reason))
  if (failed) {
    error.value = failed.reason?.message || '安全信号加载不完整'
    updateDashboardPolling(dashboardFreshness.markFailure())
  } else {
    updateDashboardPolling(dashboardFreshness.markSuccess())
  }
  loading.value = false
}

const urgentIncidents = computed(() => events.value
  .filter(item => ['critical', 'high'].includes(item.severity) || ['new', 'open'].includes(item.status))
  .sort((a, b) => (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0))
  .slice(0, 6))

const criticalCount = computed(() => events.value.filter(item => item.severity === 'critical').length || stats.value.critical_events)
const highCount = computed(() => events.value.filter(item => item.severity === 'high').length || stats.value.high_events)
const openCount = computed(() => events.value.filter(item => ['new', 'open'].includes(item.status)).length)
const lifecycleMetrics = computed(() => {
  const metrics = aggregateLifecycleMetrics(events.value)
  return {
    mttaLabel: formatDurationLabel(metrics.mttaMs),
    mttrLabel: formatDurationLabel(metrics.mttrMs),
    mttaSamples: metrics.mttaSampleCount,
    mttrSamples: metrics.mttrSampleCount,
  }
})
const pipelineSummary = computed(() => aggregateStatusPipeline(events.value))
const onlineRate = computed(() => stats.value.total_hosts ? Math.round((stats.value.online_hosts / stats.value.total_hosts) * 100) : 0)
const riskScore = computed(() => Math.min(100, criticalCount.value * 12 + highCount.value * 8 + openCount.value * 3 + (protectionStatus.value === 'disabled' ? 18 : 0)))
const riskTone = computed(() => riskScore.value >= 75 ? 'critical' : riskScore.value >= 45 ? 'high' : 'low')
const riskLabel = computed(() => ({ critical: '立即处置', high: '重点关注', low: '稳定监测' }[riskTone.value]))

const executiveSignals = computed(() => [
  { key: 'critical', label: '关键攻击', value: criticalCount.value, note: '严重事件需要优先闭环', action: '处置事件', route: '/events', tone: 'critical' },
  { key: 'open', label: '待确认队列', value: openCount.value, note: '新发或打开状态事件', action: '查看队列', route: '/events', tone: 'high' },
  { key: 'coverage', label: '资产在线率', value: `${onlineRate.value}%`, note: `${stats.value.online_hosts}/${stats.value.total_hosts} 台资产在线`, action: '看暴露面', route: '/assets', tone: 'info' },
  { key: 'protect', label: 'RASP 防护', value: protectionStatus.value === 'enabled' ? '开启' : '关闭', note: '应用运行时阻断状态', action: '检查控制', route: '/control', tone: protectionStatus.value === 'enabled' ? 'low' : 'critical' },
  { key: 'mtta', label: 'MTTA', value: lifecycleMetrics.value.mttaLabel, note: `${lifecycleMetrics.value.mttaSamples} 条可计算响应样本`, action: '查看队列', route: '/events', tone: 'info' },
  { key: 'mttr', label: 'MTTR', value: lifecycleMetrics.value.mttrLabel, note: `${lifecycleMetrics.value.mttrSamples} 条可计算处置样本`, action: '查看详情', route: '/events', tone: 'low' },
  { key: 'pipeline', label: '状态管线', value: `${pipelineSummary.value.queued}/${pipelineSummary.value.handling}/${pipelineSummary.value.resolved}`, note: '待确认 / 处理中 / 已闭环', action: '处置队列', route: '/events', tone: 'high' }
])

const attackStages = computed(() => {
  const textOf = (item) => `${item.title || ''} ${item.category || ''} ${item.tactic || ''}`.toLowerCase()
  return [
    { key: 'dpi', name: '语义流量', source: 'DPI', count: events.value.filter(item => ['dpi', 'network'].some(key => textOf(item).includes(key))).length },
    { key: 'runtime', name: '主机行为', source: 'Runtime', count: events.value.filter(item => ['runtime', 'process', 'file'].some(key => textOf(item).includes(key))).length },
    { key: 'rasp', name: '应用阻断', source: 'RASP', count: events.value.filter(item => ['rasp', 'sql', 'xss', 'payload'].some(key => textOf(item).includes(key))).length },
    { key: 'xdr', name: '关联成案', source: 'XDR', count: urgentIncidents.value.length }
  ]
})

const topAssets = computed(() => {
  const counts = events.value.reduce((map, event) => {
    if (event.dst_ip) map[event.dst_ip] = (map[event.dst_ip] || 0) + 1
    return map
  }, {})
  return assets.value
    .map(asset => ({ ...asset, attack_count: Math.max(asset.attack_count, counts[asset.ip] || 0) }))
    .filter(asset => asset.attack_count > 0 || asset.status === 'online')
    .sort((a, b) => b.attack_count - a.attack_count)
    .slice(0, 5)
})

const responseSteps = [
  { index: '01', title: '确认攻击', description: '进入事件详情核对证据与影响面', route: '/events' },
  { index: '02', title: '定位资产', description: '确认受害主机、应用和 Agent 覆盖', route: '/assets' },
  { index: '03', title: '关联攻击链', description: '查看 XDR 聚合后的跨源行为链', route: '/xdr' },
  { index: '04', title: '加固控制', description: '调整 RASP/规则/Agent 防护策略', route: '/control' }
]

const severityText = (severity) => severityTextMap[severity] || severity || '未知'
const go = (path) => router.push(path)
const openIncident = (incident) => router.push(incident.id !== undefined ? `/events/${incident.id}` : '/events')
const formatTime = (value) => {
  if (!value) return '-'
  const normalized = typeof value === 'number' && value < 1000000000000 ? value * 1000 : value
  const date = new Date(normalized)
  if (Number.isNaN(date.getTime())) return '-'
  return formatChinaDateTime(normalized)
}

onMounted(() => {
  updateDashboardPolling(dashboardFreshness.refresh())
  dashboardScheduler.start({
    id: 'dashboard-polling',
    intervalMs: 30000,
    run: ({ signal }) => fetchAll({ signal }),
  })
  dashboardStaleTimer = setInterval(() => {
    updateDashboardPolling(dashboardFreshness.refresh())
  }, 1000)
})

onUnmounted(() => {
  dashboardScheduler.stopAll()
  if (dashboardStaleTimer) clearInterval(dashboardStaleTimer)
})
</script>

<style scoped>
.command-dashboard {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.hero-panel {
  position: relative;
  overflow: hidden;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 250px;
  gap: 24px;
  padding: 28px;
  border: 1px solid var(--border-color);
  border-radius: 28px;
  background: radial-gradient(circle at 20% 20%, rgba(56, 189, 248, 0.2), transparent 30%), linear-gradient(135deg, rgba(17, 31, 52, 0.96), rgba(7, 17, 31, 0.92));
  box-shadow: var(--shadow-hard);
}

.hero-copy {
  position: relative;
  z-index: 1;
}

.hero-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 22px;
}

.polling-meta {
  margin-top: 12px;
  display: flex;
  gap: 10px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 12px;
}

.polling-badge {
  padding: 2px 8px;
  border: 1px solid var(--border-color);
  border-radius: 999px;
}

.polling-meta.stale .polling-badge {
  color: var(--risk-critical);
  border-color: var(--risk-critical-border);
}

.risk-orb {
  position: relative;
  min-height: 210px;
  display: grid;
  place-items: center;
  align-content: center;
  border: 1px solid var(--border-color);
  border-radius: 50%;
  background: radial-gradient(circle, rgba(56, 189, 248, 0.2), rgba(15, 23, 42, 0.2) 58%, rgba(15, 23, 42, 0.76));
  box-shadow: inset 0 0 70px rgba(56, 189, 248, 0.14), 0 24px 80px rgba(0, 0, 0, 0.34);
}

.risk-orb.critical {
  border-color: var(--risk-critical-border);
  box-shadow: inset 0 0 80px rgba(255, 77, 79, 0.18), 0 0 54px rgba(255, 77, 79, 0.16);
}

.risk-orb.high {
  border-color: var(--risk-high-border);
  box-shadow: inset 0 0 80px rgba(255, 159, 67, 0.16), 0 0 54px rgba(255, 159, 67, 0.12);
}

.orb-label,
.orb-state {
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.risk-orb strong {
  color: var(--text-primary);
  font-size: 72px;
  line-height: 1;
  font-weight: 950;
  letter-spacing: -0.08em;
}

.risk-orb.critical strong {
  color: var(--risk-critical);
}

.risk-orb.high strong {
  color: var(--risk-high);
}

.executive-grid .signal-card {
  border-top: 3px solid transparent;
}

.signal-card.critical {
  border-top-color: var(--risk-critical);
}

.signal-card.high {
  border-top-color: var(--risk-high);
}

.signal-card.info {
  border-top-color: var(--risk-info);
}

.signal-card.low {
  border-top-color: var(--risk-low);
}

.signal-link {
  margin-top: 14px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--primary-light);
  font-size: 12px;
  font-weight: 900;
  cursor: pointer;
}

.dashboard-matrix {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(360px, 0.85fr);
  gap: 18px;
}

.priority-panel,
.chain-panel,
.exposure-panel,
.action-panel {
  min-height: 360px;
}

.priority-panel {
  grid-row: span 2;
}

.incident-list,
.exposure-list,
.response-steps {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.incident-row,
.asset-row,
.response-step {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: 16px;
  background: rgba(8, 18, 32, 0.56);
  color: var(--text-primary);
  text-align: left;
  transition: all var(--transition-fast);
}

.incident-row,
.response-step {
  cursor: pointer;
}

.incident-row:hover,
.response-step:hover {
  transform: translateX(3px);
  border-color: var(--border-glow);
  background: rgba(56, 189, 248, 0.08);
}

.incident-rank,
.response-step > span {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: var(--risk-critical-bg);
  color: var(--risk-critical);
  border: 1px solid var(--risk-critical-border);
  font-weight: 950;
}

.incident-main,
.asset-main {
  min-width: 0;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.incident-main strong,
.asset-main strong,
.response-step strong {
  color: var(--text-primary);
  font-size: 14px;
}

.incident-main span,
.asset-main span,
.response-step em {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 12px;
  font-style: normal;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.incident-meta {
  display: flex;
  align-items: flex-end;
  flex-direction: column;
  gap: 6px;
  color: var(--text-muted);
  font-size: 11px;
}

.attack-chain {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.stage-node {
  min-height: 150px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 8px;
  padding: 16px;
  border: 1px solid var(--border-light);
  border-radius: 18px;
  background: rgba(8, 18, 32, 0.46);
}

.stage-node.active {
  border-color: rgba(56, 189, 248, 0.42);
  box-shadow: inset 0 0 36px rgba(56, 189, 248, 0.08);
}

.stage-count {
  color: var(--primary-light);
  font-size: 34px;
  line-height: 1;
  font-weight: 950;
}

.stage-name {
  color: var(--text-primary);
  font-weight: 850;
}

.stage-source {
  color: var(--text-muted);
  font-size: 12px;
}

.asset-impact {
  color: var(--risk-high);
  font-weight: 900;
}

.response-step {
  align-items: flex-start;
  flex-direction: column;
}

@media (max-width: 1280px) {
  .hero-panel,
  .dashboard-matrix {
    grid-template-columns: 1fr;
  }

  .risk-orb {
    max-width: 250px;
  }
}

@media (max-width: 860px) {
  .attack-chain {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .incident-row,
  .asset-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .incident-meta {
    align-items: flex-start;
  }
}
</style>
