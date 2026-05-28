<template>
  <div class="rasp-page">
    <div class="page-header">
      <div>
        <h2>应用感知 (RASP)</h2>
        <div class="polling-meta" :class="{ stale: raspPolling.stale }">
          <span>上次更新：{{ raspPolling.lastUpdatedText }}</span>
          <span class="polling-badge">{{ raspPolling.stale ? '数据陈旧' : '数据新鲜' }}</span>
        </div>
      </div>
      <div class="header-actions">
        <span
          class="status-badge"
          :class="protectionStatus.enabled ? 'online' : 'info'"
        >{{ protectionStatus.enabled ? '防护已启用' : '防护未启用' }}</span>
        <el-button
          v-if="isAdmin"
          type="primary"
          size="small"
          :loading="protectionLoading"
          :disabled="protectionStatus.enabled"
          @click="setProtectionStatus(true)"
        >启用防护</el-button>
        <el-button
          v-if="isAdmin"
          size="small"
          :loading="protectionLoading"
          :disabled="!protectionStatus.enabled"
          @click="setProtectionStatus(false)"
        >禁用防护</el-button>
        <span
          v-else
          class="status-badge info"
        >仅管理员可切换防护</span>
      </div>
    </div>

    <div
      v-if="loading"
      class="page-state"
    >
      加载中...
    </div>
    <div
      v-else-if="error"
      class="page-state error"
    >
      <span>{{ error }}</span>
      <el-button
        type="primary"
        plain
        size="small"
        @click="loadRaspData"
      >重试加载</el-button>
    </div>

    <div
      v-if="protectionError"
      class="page-state error"
    >
      <span>{{ protectionError }}</span>
      <el-button
        type="primary"
        plain
        size="small"
        :loading="protectionLoading"
        @click="retryProtectionAction"
      >重试操作</el-button>
    </div>

    <div
      v-if="protectionFeedback"
      class="page-state"
    >{{ protectionFeedback }}</div>

    <div class="stats-grid">
      <div
        v-for="stat in stats"
        :key="stat.key"
        class="stat-card"
      >
        <span class="stat-value">{{ stat.value }}</span>
        <span class="stat-label">{{ stat.label }}</span>
      </div>
    </div>

    <div class="charts-row">
      <div class="chart-card">
        <div class="chart-header">
          <h3>RASP 拦截趋势</h3>
        </div>
        <div class="chart-body">
          <div
            ref="trendRef"
            style="height: 180px"
          />
        </div>
      </div>
      <div class="chart-card">
        <div class="chart-header">
          <h3>攻击类型分布</h3>
        </div>
        <div class="chart-body">
          <div
            ref="pieRef"
            style="height: 180px"
          />
        </div>
      </div>
    </div>

    <div class="filter-tabs">
      <button
        v-for="f in filters"
        :key="f.key"
        :class="{ active: activeFilter === f.key }"
        @click="activeFilter = f.key"
      >
        {{ f.label }}
      </button>
    </div>

    <div class="log-section">
      <div class="section-header">
        <h3>应用日志</h3>
        <div class="section-meta">
          <span class="status-badge online">在线 Agent {{ agentStatus.online }}</span>
          <span class="status-badge info">离线 Agent {{ agentStatus.offline }}</span>
          <span class="status-badge">启用规则 {{ enabledRuleCount }}</span>
        </div>
      </div>
      <div class="log-table">
        <div class="table-header">
          <div class="th">
            时间
          </div>
          <div class="th">
            应用
          </div>
          <div class="th">
            类型
          </div>
          <div class="th">
            攻击Payload
          </div>
          <div class="th">
            状态
          </div>
          <div class="th">
            操作
          </div>
        </div>
        <div class="table-body">
          <div
            v-if="!loading && !error && filteredLogs.length === 0"
            class="table-state"
          >
            暂无应用日志
          </div>
          <div
            v-for="log in filteredLogs"
            :key="log.id"
            class="table-row"
            :class="log.level"
          >
            <div class="td">
              {{ log.timeText }}
            </div>
            <div class="td app">
              {{ log.app }}
            </div>
            <div class="td">
              <span class="type-tag">{{ log.type }}</span>
            </div>
            <div class="td payload">
              {{ log.payload }}
              <span
                v-if="log.masked"
                class="payload-hint"
              >已脱敏</span>
            </div>
            <div class="td">
              <span
                class="status-dot"
                :class="log.status"
              /> {{ log.statusText }}
            </div>
            <div class="td actions">
              <el-button
                link
                type="primary"
                size="small"
                disabled
              >
                查看
              </el-button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import * as echarts from 'echarts'
import api, { isRequestCanceled } from '../../api'
import { normalizeList } from '../../api/adapters'
import { createPollingScheduler } from '../../data/polling/scheduler'
import { createPollingFreshnessTracker } from '../../data/polling/freshness'
import { sanitizeSensitiveValue } from '../../utils/security-display'

const activeFilter = ref('all')
const trendRef = ref(null)
const pieRef = ref(null)
const currentUserRole = ref(localStorage.getItem('role') || 'viewer')
const loading = ref(false)
const error = ref('')
const protectionLoading = ref(false)
const protectionFeedback = ref('')
const protectionError = ref('')
const lastProtectionIntent = ref(null)

const raspStats = ref({
  total_events: 0,
  blocked: 0,
  allowed: 0,
  by_attack_type: {},
  protected_apps: 0,
})
const protectionStatus = ref({
  enabled: false,
  updatedAt: '',
})
const rules = ref([])
const agents = ref([])
const logs = ref([])
const isAdmin = computed(() => currentUserRole.value === 'admin')

const raspPolling = ref({ stale: false, lastUpdatedText: '-' })
const raspFreshness = createPollingFreshnessTracker({ staleAfterMs: 90000, staleFailureThreshold: 2 })
const raspScheduler = createPollingScheduler()
let raspStaleTimer = null

const firstDefined = (source, ...keys) => {
  for (const key of keys) {
    const value = source?.[key]
    if (value !== undefined && value !== null) return value
  }
  return undefined
}

const toNumber = (value) => {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const normalized = Number(value)
  return Number.isFinite(normalized) ? normalized : 0
}

const normalizeItems = (payload, aliases = ['items', 'events', 'list']) => normalizeList(payload, aliases).items

const normalizeSeverity = (severity) => {
  const level = String(severity || '').toLowerCase()
  if (level === 'critical' || level === 'high' || level === 'medium') return level
  return 'low'
}

const formatTime = (value) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN')
}

const formatPollingTime = (value) => {
  if (!value) return '-'
  return new Date(value).toLocaleTimeString('zh-CN', { hour12: false })
}

const updateRaspPolling = (snapshot = raspFreshness.getSnapshot()) => {
  raspPolling.value = {
    stale: snapshot.stale,
    lastUpdatedText: formatPollingTime(snapshot.lastUpdatedAt),
  }
}

const normalizeProtectionEnabled = (rawValue) => {
  if (typeof rawValue === 'boolean') return rawValue
  if (typeof rawValue === 'number') return rawValue > 0
  const token = String(rawValue || '').toLowerCase()
  if (['enabled', 'enable', 'on', 'true', '1', 'active'].includes(token)) return true
  if (['disabled', 'disable', 'off', 'false', '0', 'inactive'].includes(token)) return false
  return false
}

const loadProtectionStatus = async ({ signal } = {}) => {
  const statusData = await api.get('/rasp/protection/status', { signal })
  const rawEnabled = firstDefined(statusData, 'enabled', 'protection_enabled', 'is_enabled', 'status')
  const enabled = normalizeProtectionEnabled(rawEnabled)
  protectionStatus.value = {
    enabled,
    updatedAt: String(firstDefined(statusData, 'updated_at', 'updatedAt', 'last_changed') || ''),
  }
}

const setProtectionStatus = async (enabled) => {
  if (!isAdmin.value) {
    protectionError.value = 'Permission denied: 仅管理员可切换防护状态。'
    return
  }

  protectionLoading.value = true
  protectionError.value = ''
  protectionFeedback.value = ''
  lastProtectionIntent.value = enabled

  try {
    const path = enabled ? '/rasp/protection/enable' : '/rasp/protection/disable'
    const response = await api.post(path, {})
    await loadProtectionStatus()
    protectionFeedback.value = response?.message || (enabled ? 'RASP 防护已启用' : 'RASP 防护已禁用')
  } catch (err) {
    if (!isRequestCanceled(err)) {
      protectionError.value = err.message || (enabled ? '启用防护失败' : '禁用防护失败')
    }
  } finally {
    protectionLoading.value = false
  }
}

const retryProtectionAction = async () => {
  if (typeof lastProtectionIntent.value !== 'boolean') {
    protectionError.value = ''
    await loadRaspData()
    return
  }
  await setProtectionStatus(lastProtectionIntent.value)
}

const filteredLogs = computed(() => {
  if (activeFilter.value === 'all') return logs.value
  return logs.value.filter((log) => log.status === activeFilter.value)
})

const filters = computed(() => {
  const blockedCount = logs.value.filter(log => log.status === 'blocked').length
  const allowedCount = logs.value.filter(log => log.status === 'allowed').length

  return [
    { key: 'all', label: `全部 (${logs.value.length})` },
    { key: 'blocked', label: `已阻断 (${blockedCount})` },
    { key: 'allowed', label: `已放行 (${allowedCount})` }
  ]
})

const enabledRuleCount = computed(() => rules.value.filter(rule => rule.enabled).length)

const agentStatus = computed(() => {
  const online = agents.value.filter(agent => agent.status === 'online').length
  const offline = Math.max(0, agents.value.length - online)
  return { online, offline }
})

const stats = computed(() => [
  { key: 'total_events', label: '总事件', value: raspStats.value.total_events },
  { key: 'blocked', label: '已阻断', value: raspStats.value.blocked },
  { key: 'allowed', label: '已放行', value: raspStats.value.allowed },
  { key: 'attack_types', label: '攻击类型', value: Object.keys(raspStats.value.by_attack_type || {}).length },
  { key: 'agents', label: 'Agent总数', value: agents.value.length },
  { key: 'rules', label: '规则总数', value: rules.value.length },
])

const trendSeries = computed(() => {
  const buckets = new Map()
  logs.value.forEach((log) => {
    const date = new Date(log.rawTime)
    if (Number.isNaN(date.getTime())) return
    const bucket = `${date.getHours().toString().padStart(2, '0')}:00`
    buckets.set(bucket, (buckets.get(bucket) || 0) + (log.status === 'blocked' ? 1 : 0))
  })

  const sortedKeys = [...buckets.keys()].sort((a, b) => a.localeCompare(b))
  const labels = sortedKeys.length > 0 ? sortedKeys : ['00:00']
  const values = sortedKeys.length > 0 ? sortedKeys.map(key => buckets.get(key) || 0) : [0]

  return { labels, values }
})

const attackTypeDistribution = computed(() => {
  const fromStats = Object.entries(raspStats.value.by_attack_type || {})
    .map(([name, value]) => ({ name, value: toNumber(value) }))
    .filter(item => item.value > 0)

  if (fromStats.length > 0) return fromStats

  const fromLogs = logs.value.reduce((acc, log) => {
    const key = log.type || '其他'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})

  return Object.entries(fromLogs).map(([name, value]) => ({ name, value }))
})

const renderCharts = async () => {
  await nextTick()

  if (trendRef.value) {
    const chart = echarts.getInstanceByDom(trendRef.value) || echarts.init(trendRef.value)
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', backgroundColor: 'rgba(22,27,34,0.95)', borderColor: '#30363d', textStyle: { color: '#f0f6fc' } },
      grid: { left: 40, right: 10, top: 10, bottom: 25 },
      xAxis: {
        type: 'category',
        data: trendSeries.value.labels,
        axisLine: { lineStyle: { color: '#30363d' } },
        axisLabel: { color: '#8b949e', fontSize: 10 }
      },
      yAxis: {
        type: 'value',
        axisLine: { show: false },
        splitLine: { lineStyle: { color: '#21262d' } },
        axisLabel: { color: '#8b949e', fontSize: 10 }
      },
      series: [{
        type: 'bar',
        data: trendSeries.value.values,
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: '#ff4d4f' },
            { offset: 1, color: '#ff7a45' }
          ]),
          borderRadius: [4, 4, 0, 0]
        }
      }]
    })
  }

  if (pieRef.value) {
    const chart = echarts.getInstanceByDom(pieRef.value) || echarts.init(pieRef.value)
    const pieData = attackTypeDistribution.value.length > 0
      ? attackTypeDistribution.value
      : [{ name: '暂无数据', value: 1 }]

    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'item', backgroundColor: 'rgba(22,27,34,0.95)', borderColor: '#30363d', textStyle: { color: '#f0f6fc' } },
      legend: { orient: 'vertical', right: 10, top: 'center', textStyle: { color: '#8b949e', fontSize: 11 } },
      series: [{
        type: 'pie',
        radius: ['35%', '60%'],
        center: ['35%', '50%'],
        data: pieData
      }]
    })
  }
}

const loadRaspData = async ({ signal } = {}) => {
  loading.value = true
  error.value = ''
  let didSucceed = false

  try {
    const [statsData, eventsData, rulesData, agentsData, protectionData] = await Promise.all([
      api.get('/rasp/stats', { signal }),
      api.get('/rasp/events', { params: { limit: 50, offset: 0 }, signal }),
      api.get('/rasp/rules', { signal }),
      api.get('/rasp/agents', { signal }),
      api.get('/rasp/protection/status', { signal }),
    ])

    raspStats.value = {
      total_events: toNumber(firstDefined(statsData, 'total_events', 'totalEvents', 'total')),
      blocked: toNumber(firstDefined(statsData, 'blocked', 'blocked_total', 'blockedCount')),
      allowed: toNumber(firstDefined(statsData, 'allowed', 'allowed_total', 'allowedCount')),
      by_attack_type: firstDefined(statsData, 'by_attack_type', 'byAttackType') || {},
      protected_apps: toNumber(firstDefined(statsData, 'protected_apps', 'protectedApps')),
    }

    const rawEnabled = firstDefined(protectionData, 'enabled', 'protection_enabled', 'is_enabled', 'status')
    protectionStatus.value = {
      enabled: normalizeProtectionEnabled(rawEnabled),
      updatedAt: String(firstDefined(protectionData, 'updated_at', 'updatedAt', 'last_changed') || ''),
    }

    const eventItems = normalizeItems(eventsData, ['items', 'events', 'list'])
    logs.value = eventItems.map((event, index) => {
      const blocked = Boolean(firstDefined(event, 'blocked', 'is_blocked', 'intercepted'))
      const payloadState = sanitizeSensitiveValue('payload', firstDefined(event, 'payload', 'message', 'detail') || '-')
      return {
        id: firstDefined(event, 'id', 'event_id', 'alert_id') || `rasp-${index}`,
        rawTime: firstDefined(event, 'timestamp', 'created_at', 'time') || '',
        timeText: formatTime(firstDefined(event, 'timestamp', 'created_at', 'time')),
        app: String(firstDefined(event, 'app', 'application', 'hostname', 'service') || '-'),
        type: String(firstDefined(event, 'attack_type', 'event_type', 'type') || '-'),
        payload: String(payloadState.value || '-'),
        masked: payloadState.masked,
        level: normalizeSeverity(firstDefined(event, 'severity', 'level')),
        status: blocked ? 'blocked' : 'allowed',
        statusText: blocked ? '已阻断' : '已放行',
      }
    })

    rules.value = normalizeItems(rulesData, ['items', 'rules', 'list']).map((rule, index) => ({
      id: firstDefined(rule, 'id', 'rule_id') || `rule-${index}`,
      enabled: Boolean(firstDefined(rule, 'enabled', 'is_enabled', 'active')),
    }))

    agents.value = normalizeItems(agentsData, ['items', 'agents', 'list']).map((agent, index) => {
      const rawStatus = String(firstDefined(agent, 'status', 'agent_status') || '').toLowerCase()
      const onlineFlag = firstDefined(agent, 'online', 'is_online', 'isOnline')
      const normalizedStatus = rawStatus === 'online' || rawStatus === 'up' || rawStatus === 'active' || onlineFlag
        ? 'online'
        : 'offline'

      return {
        id: firstDefined(agent, 'id', 'agent_id') || `agent-${index}`,
        status: normalizedStatus,
      }
    })

    await renderCharts()
    didSucceed = true
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '加载RASP数据失败'
      updateRaspPolling(raspFreshness.markFailure())
    }
  } finally {
    if (didSucceed) updateRaspPolling(raspFreshness.markSuccess())
    loading.value = false
  }
}

const handleResize = () => {
  echarts.getInstanceByDom(trendRef.value)?.resize()
  echarts.getInstanceByDom(pieRef.value)?.resize()
}

onMounted(async () => {
  updateRaspPolling(raspFreshness.refresh())
  raspScheduler.start({
    id: 'rasp-polling',
    intervalMs: 30000,
    run: ({ signal }) => loadRaspData({ signal }),
  })
  raspStaleTimer = setInterval(() => {
    updateRaspPolling(raspFreshness.refresh())
  }, 1000)
  await loadRaspData()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  raspScheduler.stopAll()
  if (raspStaleTimer) clearInterval(raspStaleTimer)
  echarts.getInstanceByDom(trendRef.value)?.dispose()
  echarts.getInstanceByDom(pieRef.value)?.dispose()
})
</script>

<style scoped>
.rasp-page { min-height: 100%; }
.page-state { margin-bottom: 16px; padding: 12px 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-secondary); display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.page-state.error { color: var(--risk-critical); }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 12px; }
.page-header h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }
.header-actions { display: flex; align-items: center; gap: 8px; }
.polling-meta { margin-top: 6px; display: flex; align-items: center; gap: 10px; color: var(--text-secondary); font-size: 12px; }
.polling-badge { border: 1px solid var(--border-color); border-radius: 999px; padding: 2px 8px; }
.polling-meta.stale .polling-badge { color: var(--risk-critical); border-color: var(--risk-critical-border); }
.stats-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .stat-value { display: block; font-size: 24px; font-weight: 700; color: var(--text-primary); }
.stat-card .stat-label { font-size: 12px; color: var(--text-secondary); }
.charts-row { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 20px; }
.chart-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
.chart-header { padding: 14px 16px; border-bottom: 1px solid var(--border-color); }
.chart-header h3 { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.chart-body { padding: 16px; }
.filter-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
.filter-tabs button { padding: 6px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.15s; }
.filter-tabs button.active { background: rgba(24,144,255,0.12); border-color: rgba(24,144,255,0.36); color: #9ecbff; }
.log-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
.section-header h3 { font-size: 16px; color: var(--text-primary); }
.section-meta { display: flex; align-items: center; gap: 8px; }
.log-table { width: 100%; }
.table-header { display: grid; grid-template-columns: 140px 120px 130px 1fr 110px 90px; gap: 12px; padding: 10px 12px; background: rgba(255,255,255,0.02); border-radius: 6px; margin-bottom: 8px; }
.th { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; }
.table-body { max-height: 380px; overflow-y: auto; }
.table-row { display: grid; grid-template-columns: 140px 120px 130px 1fr 110px 90px; gap: 12px; padding: 10px 12px; border-bottom: 1px solid var(--border-color); }
.td { font-size: 13px; color: var(--text-secondary); display: flex; align-items: center; min-width: 0; }
.td.app { color: var(--text-primary); font-weight: 600; }
.td.payload { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.type-tag { padding: 2px 8px; border-radius: 4px; background: rgba(24,144,255,0.12); color: #9ecbff; font-size: 11px; }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status-dot.blocked { background: #ff4d4f; }
.status-dot.allowed { background: #52c41a; }
.table-state { padding: 24px; text-align: center; color: var(--text-muted); }
@media (max-width: 1200px) {
  .stats-grid { grid-template-columns: repeat(3, 1fr); }
  .charts-row { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .page-header { flex-direction: column; align-items: flex-start; }
  .header-actions { flex-wrap: wrap; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .section-header { flex-direction: column; align-items: flex-start; gap: 8px; }
  .table-header, .table-row { grid-template-columns: 1fr; }
  .th { display: none; }
}
</style>
