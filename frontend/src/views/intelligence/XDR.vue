<template>
  <div class="xdr-page">
    <div class="page-header">
      <div>
        <h2>XDR感知</h2>
        <div class="polling-meta" :class="{ stale: xdrPolling.stale }">
          <span>上次更新：{{ xdrPolling.lastUpdatedText }}</span>
          <span class="polling-badge">{{ xdrPolling.stale ? '数据陈旧' : '数据新鲜' }}</span>
        </div>
      </div>
      <div class="header-actions">
        <el-input
          v-model="searchQuery"
          placeholder="搜索事件、IP、域名..."
          prefix-icon="Search"
          clearable
          style="width: 280px"
        />
        <el-button
          type="primary"
          @click="loadXDRData"
        >刷新</el-button>
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
      {{ error }}
    </div>

    <div class="stats-grid">
      <div
        v-for="stat in stats"
        :key="stat.key"
        class="stat-card"
      >
        <div
          class="stat-icon"
          :style="{ background: stat.bg }"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            :stroke="stat.color"
            stroke-width="2"
          >
            <circle
              cx="12"
              cy="12"
              r="10"
            />
          </svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ stat.value }}</span>
          <span class="stat-label">{{ stat.label }}</span>
        </div>
      </div>
    </div>

    <div class="charts-row">
      <div class="chart-card">
        <div class="chart-header">
          <h3>Top 告警规则</h3>
        </div>
        <div class="chart-body">
          <div
            ref="graphRef"
            style="height: 250px"
          />
        </div>
      </div>

      <div class="chart-card">
        <div class="chart-header">
          <h3>来源分布</h3>
        </div>
        <div class="chart-body">
          <div
            ref="radarRef"
            style="height: 250px"
          />
        </div>
      </div>
    </div>

    <div class="events-section">
      <div class="section-header">
        <h3>统一事件检索</h3>
      </div>
      <div class="events-table">
        <div class="table-header">
          <div class="th">
            时间
          </div>
          <div class="th">
            事件类型
          </div>
          <div class="th">
            源IP
          </div>
          <div class="th">
            目标
          </div>
          <div class="th">
            严重度
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
            v-if="!loading && !error && filteredEvents.length === 0"
            class="table-state"
          >
            暂无XDR事件
          </div>
          <div
            v-for="event in filteredEvents"
            :key="event.id"
            class="table-row"
            :class="event.level"
          >
            <div class="td time">
              {{ event.timeText }}
            </div>
            <div class="td type">
              {{ event.type }}
            </div>
            <div class="td">
              {{ event.srcIp }}
            </div>
            <div class="td">
              {{ event.dstDisplay }}
            </div>
            <div class="td">
              <span
                class="risk-badge"
                :class="event.level"
              >{{ event.levelText }}</span>
            </div>
            <div class="td">
              <span
                class="status-dot"
                :class="event.status"
              /> {{ event.statusText }}
            </div>
            <div class="td actions">
              <el-button
                link
                type="primary"
                size="small"
                :disabled="!event.eventDetailId"
                @click="goEventDetail(event)"
              >
                查看证据
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
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import api, { isRequestCanceled } from '../../api'
import { normalizeList } from '../../api/adapters'
import { createPollingScheduler } from '../../data/polling/scheduler'
import { createPollingFreshnessTracker } from '../../data/polling/freshness'
import { PLATFORM_TIME_UPDATED_EVENT, formatChinaDateTime, formatChinaTime } from '../../shared/time'

const router = useRouter()
const searchQuery = ref('')
const graphRef = ref(null)
const radarRef = ref(null)
const loading = ref(false)
const error = ref('')

const xdrStats = ref({
  total_events: 0,
  total_alerts: 0,
  critical_alerts: 0,
  high_alerts: 0,
  medium_alerts: 0,
  events_today: 0,
})
const sourceStats = ref([])
const topEvents = ref([])
const events = ref([])

const xdrPolling = ref({ stale: false, lastUpdatedText: '-' })
const xdrFreshness = createPollingFreshnessTracker({ staleAfterMs: 90000, staleFailureThreshold: 2 })
const xdrScheduler = createPollingScheduler()
let xdrStaleTimer = null

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
  const sev = String(severity || '').toLowerCase()
  if (sev === 'critical') return 'critical'
  if (sev === 'high') return 'high'
  if (sev === 'medium') return 'medium'
  return 'low'
}

const severityText = (level) => {
  if (level === 'critical') return '严重'
  if (level === 'high') return '高危'
  if (level === 'medium') return '中危'
  return '低危'
}

const normalizeStatus = (status) => {
  const s = String(status || '').toLowerCase()
  if (s === 'resolved' || s === 'closed') return 'resolved'
  if (s === 'processed' || s === 'processing' || s === 'open') return 'processed'
  return 'new'
}

const statusText = (status) => {
  if (status === 'resolved') return '已处置'
  if (status === 'processed') return '处理中'
  return '新告警'
}

const formatTime = (value) => {
  if (!value) return '-'
  const text = formatChinaDateTime(value)
  return text === '暂无时间' || text === '时间格式异常' ? '-' : text
}

const formatPollingTime = (value) => {
  if (!value) return '-'
  const text = formatChinaTime(value)
  return text === '时间格式异常' ? '-' : text
}

const stats = computed(() => [
  { key: 'total_events', label: '总事件', value: xdrStats.value.total_events, bg: 'rgba(24,144,255,.15)', color: '#1890ff' },
  { key: 'total_alerts', label: '总告警', value: xdrStats.value.total_alerts, bg: 'rgba(245,34,45,.15)', color: '#f5222d' },
  { key: 'critical_alerts', label: '严重告警', value: xdrStats.value.critical_alerts, bg: 'rgba(167,29,42,.15)', color: '#ff4d4f' },
  { key: 'high_alerts', label: '高危告警', value: xdrStats.value.high_alerts, bg: 'rgba(255,122,69,.15)', color: '#ff7a45' },
  { key: 'medium_alerts', label: '中危告警', value: xdrStats.value.medium_alerts, bg: 'rgba(250,173,20,.15)', color: '#faad14' },
  { key: 'events_today', label: '今日事件', value: xdrStats.value.events_today, bg: 'rgba(82,196,26,.15)', color: '#52c41a' }
])

const filteredEvents = computed(() => {
  const query = searchQuery.value.trim().toLowerCase()
  if (!query) return events.value
  return events.value.filter((event) => {
    return [event.type, event.srcIp, event.dstDisplay, event.domain, event.message, event.ruleName]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query))
  })
})

const refreshFormattedTimes = () => {
  events.value = events.value.map((event) => ({
    ...event,
    timeText: formatTime(event.rawTime),
  }))
  updateXdrPolling()
}

const updateXdrPolling = (snapshot = xdrFreshness.getSnapshot()) => {
  xdrPolling.value = {
    stale: snapshot.stale,
    lastUpdatedText: formatPollingTime(snapshot.lastUpdatedAt),
  }
}

const goEventDetail = (event) => {
  if (!event?.eventDetailId) return
  router.push(`/events/${event.eventDetailId}`)
}

const renderCharts = async () => {
  await nextTick()

  if (graphRef.value) {
    const chart = echarts.getInstanceByDom(graphRef.value) || echarts.init(graphRef.value)
    chart.setOption({
      backgroundColor: 'transparent',
      grid: { left: 10, right: 10, top: 20, bottom: 20, containLabel: true },
      xAxis: {
        type: 'value',
        axisLabel: { color: '#8b949e' },
        splitLine: { lineStyle: { color: '#21262d' } },
      },
      yAxis: {
        type: 'category',
        data: topEvents.value.map(item => item.name),
        axisLabel: { color: '#8b949e' },
      },
      series: [{
        type: 'bar',
        data: topEvents.value.map(item => item.count),
        barWidth: 12,
        itemStyle: { color: '#1890ff', borderRadius: [0, 6, 6, 0] },
      }],
    })
  }

  if (radarRef.value) {
    const chart = echarts.getInstanceByDom(radarRef.value) || echarts.init(radarRef.value)
    const pieData = sourceStats.value.length > 0
      ? sourceStats.value.map((item) => ({ name: item.name, value: item.count }))
      : [{ name: '暂无数据', value: 1 }]

    chart.setOption({
      backgroundColor: 'transparent',
      legend: { bottom: 0, textStyle: { color: '#8b949e', fontSize: 11 } },
      series: [{
        type: 'pie',
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        itemStyle: { borderColor: '#0d1117', borderWidth: 2 },
        label: { color: '#8b949e' },
        data: pieData,
      }],
    })
  }
}

const loadXDRData = async ({ signal } = {}) => {
  loading.value = true
  error.value = ''
  let didSucceed = false

  try {
    const [statsData, eventsData, sourcesData, topEventsData] = await Promise.all([
      api.get('/xdr/stats', { signal }),
      api.get('/xdr/events', { params: { limit: 50, offset: 0 }, signal }),
      api.get('/xdr/sources', { signal }),
      api.get('/xdr/top-events', { signal }),
    ])

    xdrStats.value = {
      total_events: toNumber(firstDefined(statsData, 'total_events', 'totalEvents', 'total', 'events_total')),
      total_alerts: toNumber(firstDefined(statsData, 'total_alerts', 'totalAlerts', 'alerts_total')),
      critical_alerts: toNumber(firstDefined(statsData, 'critical_alerts', 'criticalAlerts')),
      high_alerts: toNumber(firstDefined(statsData, 'high_alerts', 'highAlerts')),
      medium_alerts: toNumber(firstDefined(statsData, 'medium_alerts', 'mediumAlerts')),
      events_today: toNumber(firstDefined(statsData, 'events_today', 'eventsToday', 'today_events')),
    }

    sourceStats.value = normalizeItems(sourcesData, ['items', 'sources', 'list'])
      .map((item, index) => ({
        name: String(firstDefined(item, 'name', 'source') || `source-${index}`),
        count: toNumber(firstDefined(item, 'count', 'total')),
        alerts: toNumber(firstDefined(item, 'alerts', 'alert_count', 'count')),
      }))
      .sort((a, b) => b.count - a.count)

    topEvents.value = normalizeItems(topEventsData, ['items', 'events', 'list'])
      .map((item, index) => ({
        id: firstDefined(item, 'id', 'rule_id') || `top-${index}`,
        name: String(firstDefined(item, 'rule_name', 'name', 'event_type') || `event-${index}`),
        count: toNumber(firstDefined(item, 'count', 'total')),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)

    events.value = normalizeItems(eventsData, ['items', 'events', 'list']).map((event, idx) => {
      const level = normalizeSeverity(firstDefined(event, 'severity', 'level'))
      const status = normalizeStatus(firstDefined(event, 'status', 'state'))
      const eventId = firstDefined(event, 'id', 'event_id', 'uuid', 'alert_id')

      const rawTime = firstDefined(event, 'created_at', 'timestamp', 'time')
      return {
        id: eventId || `xdr-${idx}`,
        eventDetailId: eventId || null,
        rawTime,
        timeText: formatTime(rawTime),
        type: String(firstDefined(event, 'event_type', 'type', 'attack_type') || '-'),
        srcIp: String(firstDefined(event, 'src_ip', 'source_ip', 'srcIp') || '-'),
        dstIp: String(firstDefined(event, 'dst_ip', 'destination_ip', 'dstIp') || '-'),
        domain: String(firstDefined(event, 'domain', 'host', 'hostname') || ''),
        dstDisplay: String(firstDefined(event, 'dst_ip', 'destination_ip', 'dstIp', 'domain', 'host') || '-'),
        level,
        levelText: severityText(level),
        status,
        statusText: statusText(status),
        message: String(firstDefined(event, 'message', 'detail', 'description') || ''),
        ruleName: String(firstDefined(event, 'rule_name', 'signature', 'ruleName') || ''),
      }
    })

    await renderCharts()
    didSucceed = true
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '加载XDR数据失败'
      updateXdrPolling(xdrFreshness.markFailure())
    }
  } finally {
    if (didSucceed) updateXdrPolling(xdrFreshness.markSuccess())
    loading.value = false
  }
}

const handleResize = () => {
  echarts.getInstanceByDom(graphRef.value)?.resize()
  echarts.getInstanceByDom(radarRef.value)?.resize()
}

onMounted(async () => {
  updateXdrPolling(xdrFreshness.refresh())
  xdrScheduler.start({
    id: 'xdr-polling',
    intervalMs: 30000,
    run: ({ signal }) => loadXDRData({ signal }),
  })
  xdrStaleTimer = setInterval(() => {
    updateXdrPolling(xdrFreshness.refresh())
  }, 1000)
  await loadXDRData()
  window.addEventListener('resize', handleResize)
  window.addEventListener(PLATFORM_TIME_UPDATED_EVENT, refreshFormattedTimes)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  window.removeEventListener(PLATFORM_TIME_UPDATED_EVENT, refreshFormattedTimes)
  xdrScheduler.stopAll()
  if (xdrStaleTimer) clearInterval(xdrStaleTimer)
  echarts.getInstanceByDom(graphRef.value)?.dispose()
  echarts.getInstanceByDom(radarRef.value)?.dispose()
})
</script>

<style scoped>
.xdr-page { min-height: 100%; }
.page-state { margin-bottom: 16px; padding: 12px 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-secondary); }
.page-state.error { color: var(--risk-critical); }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.page-header h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }
.polling-meta { margin-top: 6px; display: flex; align-items: center; gap: 10px; color: var(--text-secondary); font-size: 12px; }
.polling-badge { border: 1px solid var(--border-color); border-radius: 999px; padding: 2px 8px; }
.polling-meta.stale .polling-badge { color: var(--risk-critical); border-color: var(--risk-critical-border); }
.header-actions { display: flex; gap: 12px; }
.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
.stat-card { display: flex; align-items: center; gap: 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
.stat-icon { width: 48px; height: 48px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }
.stat-icon svg { width: 24px; height: 24px; }
.stat-info { display: flex; flex-direction: column; }
.stat-value { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.stat-label { font-size: 12px; color: var(--text-secondary); }
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
.chart-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
.chart-header h3 { font-size: 14px; color: var(--text-primary); margin-bottom: 12px; }
.events-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
.section-header h3 { font-size: 16px; color: var(--text-primary); margin-bottom: 12px; }
.events-table { width: 100%; }
.table-header { display: grid; grid-template-columns: 140px 1fr 130px 130px 90px 100px 100px; padding: 10px 12px; background: rgba(255,255,255,0.02); border-radius: 6px; margin-bottom: 8px; }
.th { font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; }
.table-body { max-height: 420px; overflow-y: auto; }
.table-row { display: grid; grid-template-columns: 140px 1fr 130px 130px 90px 100px 100px; padding: 10px 12px; border-bottom: 1px solid var(--border-color); transition: background .2s; }
.table-row:hover { background: rgba(255,255,255,0.02); }
.td { font-size: 13px; color: var(--text-secondary); display: flex; align-items: center; }
.td.type { color: var(--text-primary); font-weight: 500; }
.td.time { font-size: 12px; }
.risk-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.risk-badge.critical { background: rgba(255,77,79,0.2); color: #ff4d4f; }
.risk-badge.high { background: rgba(255,122,69,0.2); color: #ff7a45; }
.risk-badge.medium { background: rgba(250,173,20,0.2); color: #faad14; }
.risk-badge.low { background: rgba(82,196,26,0.2); color: #52c41a; }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status-dot.new { background: #ff4d4f; }
.status-dot.processed { background: #faad14; }
.status-dot.resolved { background: #52c41a; }
.table-state { padding: 24px; text-align: center; color: var(--text-muted); }
@media (max-width: 1200px) {
  .stats-grid { grid-template-columns: repeat(3, 1fr); }
  .charts-row { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .page-header { flex-direction: column; align-items: flex-start; gap: 12px; }
  .header-actions { width: 100%; }
  .header-actions .el-input { width: 100% !important; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .table-header, .table-row { grid-template-columns: 1fr; gap: 6px; }
  .th { display: none; }
}
</style>
