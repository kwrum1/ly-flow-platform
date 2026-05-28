<template>
  <div class="dpi-page">
    <div class="page-header">
      <h2>流量感知 (DPI)</h2>
      <div class="header-actions">
        <button
          :class="{ active: viewMode === 'realtime' }"
          @click="viewMode = 'realtime'"
        >
          实时
        </button>
        <button
          :class="{ active: viewMode === 'history' }"
          @click="viewMode = 'history'"
        >
          历史
        </button>
      </div>
    </div>

    <!-- 统计卡片 -->
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
        <span
          class="stat-value"
          :style="{ color: stat.color }"
        >{{ stat.value }}</span>
        <span class="stat-label">{{ stat.label }}</span>
      </div>
    </div>

    <!-- 图表区域 -->
    <div class="charts-row">
      <div class="chart-card">
        <div class="chart-header">
          <h3>恶意流量趋势</h3>
        </div>
        <div class="chart-body">
          <div
            ref="trendChartRef"
            style="height: 200px"
          />
        </div>
      </div>

      <div class="chart-card">
        <div class="chart-header">
          <h3>攻击来源分布</h3>
        </div>
        <div class="chart-body">
          <div
            ref="mapChartRef"
            style="height: 200px"
          />
        </div>
      </div>
    </div>

    <!-- 事件列表 -->
    <div class="events-section">
      <div class="section-header">
        <h3>检测事件</h3>
        <div class="filter-row">
          <button
            v-for="filter in filters"
            :key="filter.key"
            :class="{ active: activeFilter === filter.key }"
            @click="activeFilter = filter.key"
          >
            {{ filter.label }}
          </button>
        </div>
      </div>

      <div class="events-table">
        <div class="table-header">
          <div class="th">
            时间
          </div>
          <div class="th">
            类型
          </div>
          <div class="th">
            源IP
          </div>
          <div class="th">
            目标
          </div>
          <div class="th">
            详情
          </div>
          <div class="th">
            状态
          </div>
        </div>
        <div class="table-body">
          <div
            v-if="!loading && !error && events.length === 0"
            class="table-state"
          >
            暂无检测事件
          </div>
          <div
            v-for="event in events"
            :key="event.id"
            class="table-row"
            :class="event.level"
          >
            <div class="td time">
              {{ event.time }}
            </div>
            <div class="td type">
              {{ event.type }}
            </div>
            <div class="td">
              {{ event.srcIp }}
            </div>
            <div class="td">
              {{ event.dstIp }}
            </div>
            <div class="td detail">
              {{ event.detail }}
            </div>
            <div class="td">
              <span
                class="status-tag"
                :class="event.status"
              >{{ event.statusText }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import * as echarts from 'echarts'

const API_BASE = '/api/v1'

const viewMode = ref('realtime')
const activeFilter = ref('all')
const trendChartRef = ref(null)
const mapChartRef = ref(null)
const loading = ref(false)
const error = ref('')

const stats = ref([])
const filters = [
  { key: 'all', label: '全部' },
  { key: 'critical', label: '严重' },
  { key: 'high', label: '高危' }
]
const events = ref([])

const normalizeSeverity = (severity) => {
  const level = String(severity || '').toLowerCase()
  if (level === 'critical' || level === 'high' || level === 'medium') return level
  return 'low'
}

const loadDpiData = async () => {
  loading.value = true
  error.value = ''
  try {
    const [statsRes, eventsRes] = await Promise.all([
      fetch(`${API_BASE}/unified/stats`),
      fetch(`${API_BASE}/unified/events?module=dpi&limit=50&offset=0`)
    ])
    const statsData = await statsRes.json()
    const eventsData = await eventsRes.json()
    if (statsData.code !== 0 || eventsData.code !== 0) throw new Error('加载流量感知数据失败')

    const severity = statsData.data?.by_severity || {}
    stats.value = [
      { key: 'total', label: '总事件', value: statsData.data?.by_module?.dpi || 0, color: '#1890ff' },
      { key: 'critical', label: '严重', value: severity.critical || 0, color: '#ff4d4f' },
      { key: 'high', label: '高危', value: severity.high || 0, color: '#ff7a45' },
      { key: 'medium', label: '中危', value: severity.medium || 0, color: '#ffc53d' },
      { key: 'low', label: '低危', value: severity.low || 0, color: '#52c41a' }
    ]

    const items = eventsData.data?.items || eventsData.data?.events || []
    events.value = items.map((event, index) => {
      const level = normalizeSeverity(event.severity)
      return {
        id: event.id || index,
        time: event.timestamp || event.created_at || '-',
        type: event.event_type || event.type || event.module || 'dpi',
        srcIp: event.src_ip || event.srcIp || '-',
        dstIp: event.dst_ip || event.dstIp || '-',
        detail: event.message || event.detail || '-',
        level,
        status: event.status || 'new',
        statusText: event.status_text || event.status || '新告警'
      }
    })
  } catch (err) {
    error.value = err.message || '加载流量感知数据失败'
  } finally {
    loading.value = false
  }
}

const initCharts = () => {
  const sourceCounts = events.value.reduce((acc, event) => {
    const key = event.srcIp || '-'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const sourceStats = Object.entries(sourceCounts).slice(0, 5)

  if (trendChartRef.value) {
    const chart = echarts.init(trendChartRef.value)
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', backgroundColor: 'rgba(22,27,34,0.95)', borderColor: '#30363d', textStyle: { color: '#f0f6fc' } },
      grid: { left: 50, right: 20, top: 10, bottom: 30 },
      xAxis: { type: 'category', data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'], axisLine: { lineStyle: { color: '#30363d' } }, axisLabel: { color: '#8b949e' } },
      yAxis: { type: 'value', axisLine: { show: false }, splitLine: { lineStyle: { color: '#21262d' } }, axisLabel: { color: '#8b949e' } },
      series: [{
        type: 'line', smooth: true,
        data: [0, 0, 0, 0, 0, 0, events.value.length],
        lineStyle: { color: '#ff4d4f', width: 2 },
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(255,77,79,0.3)' }, { offset: 1, color: 'rgba(255,77,79,0)' }]) },
        symbol: 'circle', symbolSize: 6
      }]
    })
  }

  if (mapChartRef.value) {
    const chart = echarts.init(mapChartRef.value)
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', backgroundColor: 'rgba(22,27,34,0.95)', borderColor: '#30363d', textStyle: { color: '#f0f6fc' } },
      grid: { left: 60, right: 20, top: 10, bottom: 30 },
      xAxis: { type: 'value', axisLine: { lineStyle: { color: '#30363d' } }, axisLabel: { color: '#8b949e' } },
      yAxis: { type: 'category', data: sourceStats.map(([ip]) => ip), axisLine: { lineStyle: { color: '#30363d' } }, axisLabel: { color: '#8b949e' } },
      series: [{
        type: 'bar',
        data: sourceStats.map(([, count]) => count),
        itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [{ offset: 0, color: '#1890ff' }, { offset: 1, color: '#40a9ff' }]), borderRadius: [0, 4, 4, 0] },
        barWidth: 16
      }]
    })
  }
}

onMounted(async () => {
  await loadDpiData()
  initCharts()
  window.addEventListener('resize', () => {
    echarts.getInstanceByDom(trendChartRef.value)?.resize()
    echarts.getInstanceByDom(mapChartRef.value)?.resize()
  })
})
</script>

<style scoped>
.dpi-page { min-height: 100%; }
.page-state { margin-bottom: 16px; padding: 12px 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-secondary); }
.page-state.error, .table-state.error { color: var(--risk-critical); }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.page-header h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }
.header-actions { display: flex; gap: 4px; padding: 4px; background: var(--bg-secondary); border-radius: 8px; }
.header-actions button { padding: 6px 16px; background: transparent; border: none; border-radius: 6px; color: var(--text-secondary); font-size: 13px; cursor: pointer; transition: all 0.15s; }
.header-actions button.active { background: var(--primary-color); color: white; }

.stats-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .stat-value { display: block; font-size: 24px; font-weight: 700; }
.stat-card .stat-label { font-size: 12px; color: var(--text-secondary); }

.charts-row { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 20px; }
.chart-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
.chart-header { padding: 14px 16px; border-bottom: 1px solid var(--border-color); }
.chart-header h3 { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.chart-body { padding: 16px; }

.events-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
.section-header { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; border-bottom: 1px solid var(--border-color); }
.section-header h3 { font-size: 14px; font-weight: 600; color: var(--text-primary); }
.filter-row { display: flex; gap: 8px; }
.filter-row button { padding: 6px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.15s; }
.filter-row button.active { background: var(--primary-color); border-color: var(--primary-color); color: white; }

.events-table { }
.table-header { display: flex; background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); }
.th { flex: 1; padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--text-secondary); text-align: left; }
.table-body { max-height: 400px; overflow-y: auto; }
.table-state { padding: 24px; text-align: center; color: var(--text-secondary); }
.table-row { display: flex; border-bottom: 1px solid var(--border-color); transition: background 0.15s; }
.table-row:hover { background: var(--bg-hover); }
.table-row:last-child { border-bottom: none; }
.table-row.critical .td:first-child { border-left: 3px solid var(--risk-critical); }
.table-row.high .td:first-child { border-left: 3px solid var(--risk-high); }
.table-row.medium .td:first-child { border-left: 3px solid var(--risk-medium); }
.td { flex: 1; padding: 14px 16px; font-size: 13px; color: var(--text-primary); display: flex; align-items: center; }
.td.time { font-family: 'Roboto Mono', monospace; color: var(--text-muted); }
.td.type { font-weight: 500; }
.td.detail { font-size: 12px; color: var(--text-secondary); }

.status-tag { padding: 3px 10px; border-radius: 4px; font-size: 12px; }
.status-tag.processing { background: var(--risk-medium-bg); color: var(--risk-medium); }
.status-tag.blocked { background: var(--risk-low-bg); color: var(--risk-low); }
.status-tag.alert { background: var(--risk-critical-bg); color: var(--risk-critical); }
</style>